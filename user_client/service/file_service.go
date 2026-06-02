package service

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	abeengine "bc_abe/abe"
	"bc_abe/utils/apperr"
	"bc_abe/utils/config"
	"bc_abe/utils/db"
	"bc_abe/utils/gateway"
)

// FileService 文件加解密与上链服务。
type FileService struct {
	cfg    config.Config
	engine *abeengine.Engine
}

func NewFileService(cfg config.Config, engine *abeengine.Engine) *FileService {
	return &FileService{cfg: cfg, engine: engine}
}

type EncryptResult struct {
	AssetID string `json:"assetId"`
	Policy  string `json:"policy"`
}

func (s *FileService) Encrypt(userID uint, filename, content, policy string) (*EncryptResult, error) {
	authSvc := NewAuthService()
	user, err := authSvc.GetUser(userID)
	if err != nil {
		return nil, err
	}
	var org db.Organization
	if err := db.Get().Where("name = ?", user.OrgName).First(&org).Error; err != nil {
		return nil, apperr.Wrap(apperr.ErrNotFound, "organization", err)
	}
	if strings.TrimSpace(org.OrgJSON) == "" {
		return nil, fmt.Errorf("organization %s is not initialized", user.OrgName)
	}
	_ = s.engine.LoadOrgFromJSON(org.OrgJSON)

	secret, err := s.engine.NewSecret()
	if err != nil {
		return nil, err
	}
	symKey := sha256.Sum256([]byte(secret.ToJsonObj().GetP()))
	encContent, err := aesEncrypt(symKey, []byte(content))
	if err != nil {
		return nil, err
	}

	gw := gateway.Get()
	if gw == nil {
		return nil, apperr.ErrGatewayConnect
	}
	pubKeys, err := s.fetchOrgPubKeys(gw)
	if err != nil {
		return nil, err
	}
	authpubs := s.engine.AuthPubsOfPolicy(policy)
	for name := range authpubs.AuthPub {
		authPubJSON, ok := pubKeys[name]
		if !ok || authPubJSON == "" {
			return nil, fmt.Errorf("authority public key not found on chain: %s", name)
		}
		authPub := abeengine.ParseAuthPub(authPubJSON)
		if abeengine.SerializeOrg(authPub.Org) != org.OrgJSON {
			return nil, fmt.Errorf("authority public key %s does not match user org %s; reinitialize organizations", name, user.OrgName)
		}
		authpubs.AuthPub[name] = authPub
	}

	ct, err := s.engine.Encrypt(secret, policy, authpubs)
	if err != nil {
		return nil, err
	}

	assetID := fmt.Sprintf("%d-%s", time.Now().UnixNano(), filename)
	asset := map[string]string{
		"id": assetID, "policy": policy,
		"ciphertext": abeengine.SerializeCiphertext(ct),
		"owner":      fmt.Sprintf("%d", userID),
		"createdAt":  time.Now().Format(time.RFC3339),
		"updatedAt":  time.Now().Format(time.RFC3339),
	}
	payload, _ := json.Marshal(asset)

	if _, err := gw.Contract().SubmitTransaction("PutCiphertext", string(payload)); err != nil {
		return nil, apperr.Wrap(apperr.ErrFabricNetwork, "put ciphertext", err)
	}

	fileDir := filepath.Join(s.cfg.DataDir, "files")
	_ = os.MkdirAll(fileDir, 0o755)
	if err := os.WriteFile(filepath.Join(fileDir, assetID+".bin"), encContent, 0o644); err != nil {
		return nil, err
	}
	return &EncryptResult{AssetID: assetID, Policy: policy}, nil
}

func (s *FileService) fetchOrgPubKeys(gw *gateway.Gateway) (map[string]string, error) {
	raw, err := gw.Contract().EvaluateTransaction("GetGlobalParams")
	if err != nil {
		return nil, apperr.Wrap(apperr.ErrFabricNetwork, "get global params", err)
	}
	var params struct {
		OrgPubKeys map[string]string `json:"orgPubKeys"`
	}
	if err := json.Unmarshal(raw, &params); err != nil {
		return nil, apperr.Wrap(apperr.ErrInvalidInput, "decode global params", err)
	}
	if len(params.OrgPubKeys) == 0 {
		return nil, fmt.Errorf("global params contains no authority public keys")
	}
	return params.OrgPubKeys, nil
}

type DecryptResult struct {
	Content string `json:"content"`
	Policy  string `json:"policy"`
}

func (s *FileService) Decrypt(userID uint, assetID string) (*DecryptResult, error) {
	authSvc := NewAuthService()
	user, err := authSvc.GetUser(userID)
	if err != nil {
		return nil, err
	}

	var ctJSON string
	var policy string
	gw := gateway.Get()
	if gw == nil {
		return nil, apperr.ErrGatewayConnect
	}
	raw, err := gw.Contract().EvaluateTransaction("GetCiphertext", assetID)
	if err != nil {
		return nil, apperr.Wrap(apperr.ErrFabricNetwork, "get ciphertext", err)
	}
	var asset map[string]any
	if err := json.Unmarshal(raw, &asset); err != nil {
		return nil, apperr.Wrap(apperr.ErrInvalidInput, "decode ciphertext asset", err)
	}
	ctJSON, _ = asset["ciphertext"].(string)
	policy, _ = asset["policy"].(string)
	if strings.TrimSpace(ctJSON) == "" {
		return nil, fmt.Errorf("ciphertext asset %s has empty ciphertext", assetID)
	}

	ct := abeengine.ParseCiphertext(ctJSON)
	if policy == "" {
		policy = ct.Policy
	}
	var org db.Organization
	if err := db.Get().Where("name = ?", user.OrgName).First(&org).Error; err != nil {
		return nil, apperr.Wrap(apperr.ErrNotFound, "organization", err)
	}
	if abeengine.SerializeOrg(ct.Org) != org.OrgJSON {
		return nil, fmt.Errorf("ciphertext org does not match user org %s; reinitialize organizations and encrypt again", user.OrgName)
	}
	userattrs := NewKeyService(s.cfg, s.engine).MergeUserKeys(user.ID, user.Username, policy)
	secret, err := s.engine.Decrypt(ct, userattrs)
	if err != nil {
		return nil, apperr.Wrap(apperr.ErrUnauthorized, "abe decrypt", err)
	}

	filePath := filepath.Join(s.cfg.DataDir, "files", assetID+".bin")
	encContent, err := os.ReadFile(filePath)
	if err != nil {
		return nil, apperr.ErrNotFound
	}
	symKey := sha256.Sum256([]byte(secret.ToJsonObj().GetP()))
	plain, err := aesDecrypt(symKey, encContent)
	if err != nil {
		return nil, apperr.Wrap(apperr.ErrUnauthorized, "decrypt content", err)
	}
	return &DecryptResult{Content: string(plain), Policy: policy}, nil
}

func aesEncrypt(key [32]byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func aesDecrypt(key [32]byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, apperr.ErrInvalidInput
	}
	nonce, body := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, body, nil)
}
