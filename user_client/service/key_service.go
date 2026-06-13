package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	abeengine "bc_abe/abe"
	"bc_abe/utils/apperr"
	"bc_abe/utils/config"
	"bc_abe/utils/db"
	"bc_abe/utils/msp"

	"gorm.io/gorm"
)

// KeyService ABE 密钥申请服务。
type KeyService struct {
	cfg    config.Config
	engine *abeengine.Engine
}

func NewKeyService(cfg config.Config, engine *abeengine.Engine) *KeyService {
	return &KeyService{cfg: cfg, engine: engine}
}

func (s *KeyService) RequestKey(userID uint, attribute string) (AutoKeyResult, error) {
	authSvc := NewAuthService()
	user, err := authSvc.GetUser(userID)
	if err != nil {
		return AutoKeyResult{}, err
	}
	spec, err := parseAttrSpec(attribute, user.OrgName)
	if err != nil {
		return AutoKeyResult{}, apperr.Wrap(apperr.ErrInvalidInput, "attribute", err)
	}
	if err := authorizeKeyIssue(user, spec, spec.DisplayLabel); err != nil {
		return AutoKeyResult{}, apperr.Wrap(apperr.ErrUnauthorized, "key issue", err)
	}
	n, err := s.issueAndStore(user, spec)
	if err != nil {
		return AutoKeyResult{}, err
	}
	return AutoKeyResult{Attribute: spec.DisplayLabel, Version: nVersion(user.ID, spec.DisplayLabel), Keys: n}, nil
}

type AutoKeyResult struct {
	Attribute string `json:"attribute"`
	Version   int    `json:"version,omitempty"`
	Keys      int    `json:"keys"`
}

type UserKeyRecord struct {
	Attribute string `json:"attribute"`
	Version   int    `json:"version"`
	Keys      int    `json:"keys"`
	CreatedAt string `json:"createdAt"`
}

func (s *KeyService) ListUserKeys(userID uint) ([]UserKeyRecord, error) {
	var keys []db.UserABEKey
	if err := db.Get().Where("user_id = ?", userID).Order("attribute asc, version desc").Find(&keys).Error; err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := make([]UserKeyRecord, 0, len(keys))
	for _, k := range keys {
		if seen[k.Attribute] {
			continue
		}
		seen[k.Attribute] = true
		ua := abeengine.ParseUserAttrs(k.UserKeyJSON)
		out = append(out, UserKeyRecord{
			Attribute: k.Attribute,
			Version:   k.Version,
			Keys:      len(ua.Userkey),
			CreatedAt: k.CreatedAt.Format(time.RFC3339),
		})
	}
	return out, nil
}

func (s *KeyService) RequestAutoKeys(userID uint, location, atTime string, hour *int, hourOp string) ([]AutoKeyResult, error) {
	authSvc := NewAuthService()
	user, err := authSvc.GetUser(userID)
	if err != nil {
		return nil, err
	}
	h := parseKeyTime(atTime).Hour()
	if hour != nil {
		h = *hour
	}
	specs := s.autoAttributeSpecs(user, location, h, hourOp)
	results := make([]AutoKeyResult, 0, len(specs))
	for _, spec := range specs {
		count, err := s.issueAndStore(user, spec)
		if err != nil {
			return nil, err
		}
		results = append(results, AutoKeyResult{
			Attribute: spec.DisplayLabel,
			Version:   nVersion(user.ID, spec.DisplayLabel),
			Keys:      count,
		})
	}
	return results, nil
}

// EnsureKeysForPolicy 按策略补全缺失 userkey（解密前调用）。
func (s *KeyService) EnsureKeysForPolicy(user *db.UserAccount, policy string) ([]AutoKeyResult, error) {
	policy = abeengine.NormalizePolicySyntax(policy)
	specs, err := abeengine.KeyIssueSpecsFromPolicy(policy)
	if err != nil {
		return nil, err
	}
	userAuth := config.AuthNameForOrg(user.OrgName)
	for _, spec := range specs {
		if spec.AuthName != "" && spec.AuthName != userAuth {
			return nil, fmt.Errorf("策略含其他组织属性 @%s；当前为 %s（仅可申请 @%s）", spec.AuthName, user.OrgName, userAuth)
		}
	}
	merged := s.MergeUserKeysForPolicy(user.ID, user.Username, policy, user)
	missing := missingAttrsSet(policy, merged)
	if len(missing) == 0 {
		return nil, nil
	}
	var issued []AutoKeyResult
	for _, spec := range specs {
		if !specNeedsIssue(user, spec, missing) {
			continue
		}
		as, err := resolveAttrSpecForUser(user, spec.DisplayLabel, spec.IssueAttr)
		if err != nil {
			return issued, err
		}
		if err := authorizeKeyIssue(user, as, spec.DisplayLabel); err != nil {
			return issued, err
		}
		n, err := s.issueAndStore(user, as)
		if err != nil {
			return issued, fmt.Errorf("申请 %s: %w", spec.DisplayLabel, err)
		}
		issued = append(issued, AutoKeyResult{
			Attribute: as.DisplayLabel,
			Version:   nVersion(user.ID, as.DisplayLabel),
			Keys:      n,
		})
		merged = s.MergeUserKeysForPolicy(user.ID, user.Username, policy, user)
		missing = missingAttrsSet(policy, merged)
		if len(missing) == 0 {
			break
		}
	}
	if len(missing) > 0 {
		list := mapKeys(missing)
		return issued, fmt.Errorf("仍缺少策略属性密钥: %s", strings.Join(list[:min(3, len(list))], ", "))
	}
	return issued, nil
}

func specNeedsIssue(user *db.UserAccount, spec abeengine.KeyIssueSpec, missing map[string]struct{}) bool {
	if len(missing) == 0 {
		return false
	}
	as, err := resolveAttrSpecForUser(user, spec.DisplayLabel, spec.IssueAttr)
	if err == nil {
		for _, attr := range abeengine.IssueAttributeExpansion(as.IssueAttr) {
			if _, ok := missing[attr]; ok {
				return true
			}
		}
	}
	for _, attr := range abeengine.IssueAttributeExpansion(spec.IssueAttr) {
		if _, ok := missing[attr]; ok {
			return true
		}
	}
	if _, ok := missing[spec.IssueAttr]; ok {
		return true
	}
	if _, ok := missing[spec.DisplayLabel]; ok {
		return true
	}
	return false
}

func missingAttrsSet(policy string, merged *abeengine.UserAttrs) map[string]struct{} {
	out := map[string]struct{}{}
	for _, attr := range abeengine.PolicyMissingUserKeys(policy, merged) {
		out[attr] = struct{}{}
	}
	return out
}

func (s *KeyService) issueAndStore(user *db.UserAccount, spec attrSpec) (int, error) {
	attribute := spec.IssueAttr
	if err := validateIssueAttrOrg(user.OrgName, attribute); err != nil {
		return 0, apperr.Wrap(apperr.ErrUnauthorized, "key issue", err)
	}
	body := canonicalIssueBody(user.Username, attribute)
	bodyHash := sha256.Sum256(body)
	sig, err := msp.SignASN1(user.KeyPEM, bodyHash[:])
	if err != nil {
		return 0, err
	}

	adminPort := s.cfg.AuthAdminOrg1Port
	if user.OrgName == "org2" {
		adminPort = s.cfg.AuthAdminOrg2Port
	}
	issueReq := map[string]string{
		"user": user.Username, "attribute": attribute,
		"certPem":   user.CertPEM,
		"signature": base64.StdEncoding.EncodeToString(sig),
		"bodyHash":  base64.StdEncoding.EncodeToString(bodyHash[:]),
	}
	reqBody, _ := json.Marshal(issueReq)
	resp, err := http.Post(fmt.Sprintf("http://127.0.0.1:%d/api/v1/key/issue", adminPort), "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return 0, apperr.Wrap(apperr.ErrFabricNetwork, "call auth admin", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("auth admin: %s", string(respBody))
	}

	var parsed map[string]string
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return 0, apperr.Wrap(apperr.ErrInvalidInput, "decode auth admin response", err)
	}
	userAttrsJSON := parsed["userAttrsJson"]
	if strings.TrimSpace(userAttrsJSON) == "" {
		return 0, fmt.Errorf("auth admin returned empty user key")
	}
	userattrs := abeengine.ParseUserAttrs(userAttrsJSON)

	var keyCount int
	err = db.Transaction(func(tx *gorm.DB) error {
		var latest db.UserABEKey
		version := 1
		q := tx.Where("user_id = ?", user.ID).
			Where("attribute IN ?", []string{spec.DisplayLabel, spec.IssueAttr})
		if err := q.Order("version desc").First(&latest).Error; err == nil {
			version = latest.Version + 1
		}
		record := db.UserABEKey{UserID: user.ID, Attribute: spec.DisplayLabel, Version: version, UserKeyJSON: userAttrsJSON}
		if err := tx.Create(&record).Error; err != nil {
			return err
		}
		keyCount = len(userattrs.Userkey)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return keyCount, nil
}

func validateIssueAttrOrg(orgName, issueAttr string) error {
	userAuth := config.AuthNameForOrg(orgName)
	attrAuth := authFromAttr(issueAttr)
	if attrAuth == "" {
		return nil
	}
	if attrAuth != userAuth {
		return fmt.Errorf("不能跨组织申请密钥：@%s 仅限 %s（@%s）", attrAuth, orgName, userAuth)
	}
	return nil
}

func authFromAttr(s string) string {
	i := strings.LastIndex(s, "@")
	if i < 0 {
		return ""
	}
	tail := strings.TrimSpace(s[i+1:])
	if j := strings.IndexAny(tail, " \t"); j >= 0 {
		tail = tail[:j]
	}
	return tail
}

func nVersion(userID uint, attribute string) int {
	var latest db.UserABEKey
	if err := db.Get().Where("user_id = ? AND attribute = ?", userID, attribute).
		Order("version desc").First(&latest).Error; err != nil {
		return 1
	}
	return latest.Version
}

func (s *KeyService) autoAttributeSpecs(user *db.UserAccount, location string, hour int, hourOp string) []attrSpec {
	seen := map[string]bool{}
	var specs []attrSpec
	add := func(spec attrSpec) {
		if spec.IssueAttr == "" || seen[spec.IssueAttr] {
			return
		}
		seen[spec.IssueAttr] = true
		specs = append(specs, spec)
	}
	for _, attr := range UserAttributes(user) {
		if sp, err := parseAttrSpec(attr, user.OrgName); err == nil {
			add(sp)
		}
	}
	add(hourAttrSpec(user.OrgName, hour, hourOp))
	add(locAttrSpec(user.OrgName, location))
	return specs
}

func (s *KeyService) MergeUserKeys(userID uint, username, _ string) *abeengine.UserAttrs {
	return s.MergeUserKeysForPolicy(userID, username, "", nil)
}

func (s *KeyService) MergeUserKeysForPolicy(userID uint, username, policy string, user *db.UserAccount) *abeengine.UserAttrs {
	var keys []db.UserABEKey
	db.Get().Where("user_id = ?", userID).Order("attribute asc, version desc").Find(&keys)

	want := map[string]bool{}
	if strings.TrimSpace(policy) != "" {
		policy = abeengine.NormalizePolicySyntax(policy)
		if specs, err := abeengine.KeyIssueSpecsFromPolicy(policy); err == nil {
			if user == nil {
				var u db.UserAccount
				if db.Get().First(&u, userID).Error == nil {
					user = &u
				}
			}
			for _, sp := range specs {
				if user != nil {
					for _, label := range keyLabelsForPolicySpec(user, sp) {
						want[label] = true
					}
				} else {
					want[sp.DisplayLabel] = true
					want[sp.IssueAttr] = true
				}
			}
		}
	}

	orgName := ""
	if user != nil {
		orgName = user.OrgName
	}
	seen := map[string]bool{}
	numericMerged := map[string]bool{}
	var merged *abeengine.UserAttrs
	for _, k := range keys {
		if seen[k.Attribute] {
			continue
		}
		if len(want) > 0 && !want[k.Attribute] {
			continue
		}
		if orgName != "" {
			if base := numericKeyBase(k.Attribute, orgName); base != "" {
				if numericMerged[base] {
					continue
				}
				numericMerged[base] = true
			}
		}
		seen[k.Attribute] = true
		ua := abeengine.ParseUserAttrs(k.UserKeyJSON)
		merged = s.engine.MergeUserKeys(merged, ua)
	}
	if merged == nil {
		return abeengine.NewEmptyUserAttrs(username)
	}
	merged.User = username
	for attr := range merged.Userkey {
		if _, ok := merged.Coeff[attr]; !ok {
			merged.Coeff[attr] = []int{}
		}
	}
	return merged
}

func parseKeyTime(atTime string) time.Time {
	atTime = strings.TrimSpace(atTime)
	if atTime == "" {
		return time.Now()
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
	}
	for _, layout := range layouts {
		if t, err := time.ParseInLocation(layout, atTime, time.Local); err == nil {
			return t
		}
	}
	return time.Now()
}

func canonicalIssueBody(user, attribute string) []byte {
	body, _ := json.Marshal(map[string]string{"attribute": attribute, "user": user})
	return body
}

func userOwnsIssueAttr(user *db.UserAccount, issueAttr string) bool {
	issueAttr = strings.TrimSpace(issueAttr)
	if issueAttr == "" {
		return false
	}
	for _, owned := range UserAttributes(user) {
		if strings.EqualFold(strings.TrimSpace(owned), issueAttr) {
			return true
		}
		sp, err := parseAttrSpec(owned, user.OrgName)
		if err == nil && strings.EqualFold(sp.IssueAttr, issueAttr) {
			return true
		}
	}
	return false
}

// authorizeKeyIssue 校验用户是否有权申请该属性密钥。
// hour / loc* 仍允许按策略自动补发；数值比较走注册值校验；其余固定属性须在注册属性中。
func authorizeKeyIssue(user *db.UserAccount, spec attrSpec, policyLeaf string) error {
	if err := validateIssueAttrOrg(user.OrgName, spec.IssueAttr); err != nil {
		return err
	}
	if isPolicyStyleKeyAttr(spec.IssueAttr) {
		return nil
	}
	if _, ok := abeengine.ParseNumericClause(strings.TrimSpace(policyLeaf)); ok {
		_, err := resolveAttrSpecForUser(user, policyLeaf, spec.IssueAttr)
		return err
	}
	if userOwnsIssueAttr(user, spec.IssueAttr) {
		return nil
	}
	return fmt.Errorf("用户未注册属性 %s，无法申请密钥", spec.DisplayLabel)
}

func userHasAttribute(user *db.UserAccount, attribute string) bool {
	return userOwnsIssueAttr(user, attribute)
}

func mapKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
