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
	if !isPolicyStyleKeyAttr(spec.IssueAttr) && !userHasAttribute(user, spec.IssueAttr) {
		return AutoKeyResult{}, apperr.ErrUnauthorized
	}
	n, err := s.issueAndStore(user, spec)
	if err != nil {
		return AutoKeyResult{}, err
	}
	return AutoKeyResult{Attribute: spec.DisplayLabel, Keys: n}, nil
}

type AutoKeyResult struct {
	Attribute string `json:"attribute"`
	Keys      int    `json:"keys"`
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
		results = append(results, AutoKeyResult{Attribute: spec.DisplayLabel, Keys: count})
	}
	return results, nil
}

func (s *KeyService) issueAndStore(user *db.UserAccount, spec attrSpec) (int, error) {
	attribute := spec.IssueAttr
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

	var latest db.UserABEKey
	version := 1
	q := db.Get().Where("user_id = ?", user.ID).
		Where("attribute IN ?", []string{spec.DisplayLabel, spec.IssueAttr})
	if err := q.Order("version desc").First(&latest).Error; err == nil {
		version = latest.Version + 1
	}
	record := db.UserABEKey{UserID: user.ID, Attribute: spec.DisplayLabel, Version: version, UserKeyJSON: userAttrsJSON}
	if err := db.Get().Create(&record).Error; err != nil {
		return 0, err
	}
	return len(userattrs.Userkey), nil
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
	var keys []db.UserABEKey
	db.Get().Where("user_id = ?", userID).Find(&keys)
	var merged *abeengine.UserAttrs
	for _, k := range keys {
		ua := abeengine.ParseUserAttrs(k.UserKeyJSON)
		merged = s.engine.MergeUserKeys(merged, ua)
	}
	if merged == nil {
		return abeengine.NewEmptyUserAttrs(username)
	}
	merged.User = username
	// 解密时由 engine.Decrypt 按策略重算系数；此处仅合并密钥，不做时间/地点等运行时校验。
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

func userHasAttribute(user *db.UserAccount, attribute string) bool {
	for _, owned := range UserAttributes(user) {
		if owned == attribute {
			return true
		}
	}
	return false
}
