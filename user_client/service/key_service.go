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

func (s *KeyService) RequestKey(userID uint, attribute string) (int, error) {
	authSvc := NewAuthService()
	user, err := authSvc.GetUser(userID)
	if err != nil {
		return 0, err
	}
	attribute = normalizeAttribute(attribute, user.OrgName)
	if !userHasAttribute(user, attribute) {
		return 0, apperr.ErrUnauthorized
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

	var latest db.UserABEKey
	version := 1
	if err := db.Get().Where("user_id = ? AND attribute = ?", user.ID, attribute).Order("version desc").First(&latest).Error; err == nil {
		version = latest.Version + 1
	}
	record := db.UserABEKey{UserID: user.ID, Attribute: attribute, Version: version, UserKeyJSON: userAttrsJSON}
	if err := db.Get().Create(&record).Error; err != nil {
		return 0, err
	}
	return len(userattrs.Userkey), nil
}

func (s *KeyService) MergeUserKeys(userID uint, username, policy string) *abeengine.UserAttrs {
	var keys []db.UserABEKey
	db.Get().Where("user_id = ?", userID).Find(&keys)
	engine := abeengine.NewEngine("")
	var merged *abeengine.UserAttrs
	for _, k := range keys {
		ua := abeengine.ParseUserAttrs(k.UserKeyJSON)
		merged = engine.MergeUserKeys(merged, ua)
	}
	if merged == nil {
		return &abeengine.UserAttrs{User: username, Coeff: map[string][]int{}, Userkey: map[string]*abeengine.Userkey{}}
	}
	merged.User = username
	return abeengine.SelectUserAttrs(merged, username, policy)
}

func canonicalIssueBody(user, attribute string) []byte {
	body, _ := json.Marshal(map[string]string{"attribute": attribute, "user": user})
	return body
}

func normalizeAttribute(attribute, orgName string) string {
	attribute = strings.TrimSpace(attribute)
	if strings.Contains(attribute, "@") {
		return attribute
	}
	return attribute + "@" + config.AuthNameForOrg(orgName)
}

func userHasAttribute(user *db.UserAccount, attribute string) bool {
	for _, owned := range UserAttributes(user) {
		if owned == attribute {
			return true
		}
	}
	return false
}
