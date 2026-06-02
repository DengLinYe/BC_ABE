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
	assetID := fmt.Sprintf("%d-%s", time.Now().UnixNano(), safeFilename(filename))
	return s.putEncrypted(userID, assetID, content, policy, "")
}

func (s *FileService) Update(userID uint, assetID, content, policy string) (*EncryptResult, error) {
	if strings.TrimSpace(assetID) == "" {
		return nil, apperr.ErrInvalidInput
	}
	return s.putEncrypted(userID, assetID, content, policy, assetID)
}

func (s *FileService) putEncrypted(userID uint, assetID, content, policy, existingAssetID string) (*EncryptResult, error) {
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
	policy = abeengine.NormalizePolicySyntax(policy)
	authpubs := s.engine.AuthPubsOfPolicy(policy)
	if len(authpubs.AuthPub) == 0 {
		return nil, fmt.Errorf("invalid policy syntax (check location/time format)")
	}
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

	createdAt := time.Now().Format(time.RFC3339)
	if existingAssetID != "" {
		if existing, err := s.getAsset(existingAssetID); err == nil {
			if v, _ := existing["createdAt"].(string); v != "" {
				createdAt = v
			}
		}
	}
	asset := map[string]string{
		"id": assetID, "policy": policy,
		"ciphertext": abeengine.SerializeCiphertext(ct),
		"owner":      fmt.Sprintf("%d", userID),
		"createdAt":  createdAt,
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

type AssetSummary struct {
	AssetID   string `json:"assetId"`
	Owner     string `json:"owner"`
	Policy    string `json:"policy"`
	Version   int    `json:"version"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

func (s *FileService) List(userID uint, ownedOnly bool) ([]AssetSummary, error) {
	gw := gateway.Get()
	if gw == nil {
		return nil, apperr.ErrGatewayConnect
	}
	raw, err := gw.Contract().EvaluateTransaction("ListCiphertextIDs")
	if err != nil {
		return nil, apperr.Wrap(apperr.ErrFabricNetwork, "list ciphertext ids", err)
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil, apperr.Wrap(apperr.ErrInvalidInput, "decode ciphertext ids", err)
	}
	owner := fmt.Sprintf("%d", userID)
	out := make([]AssetSummary, 0, len(ids))
	for _, id := range ids {
		asset, err := s.getAsset(id)
		if err != nil {
			continue
		}
		if ownedOnly && fmt.Sprint(asset["owner"]) != owner {
			continue
		}
		out = append(out, AssetSummary{
			AssetID:   id,
			Owner:     fmt.Sprint(asset["owner"]),
			Policy:    fmt.Sprint(asset["policy"]),
			Version:   intFromAny(asset["version"]),
			CreatedAt: fmt.Sprint(asset["createdAt"]),
			UpdatedAt: fmt.Sprint(asset["updatedAt"]),
		})
	}
	return out, nil
}

func (s *FileService) Delete(userID uint, assetID string) error {
	asset, err := s.getAsset(assetID)
	if err != nil {
		return err
	}
	if fmt.Sprint(asset["owner"]) != fmt.Sprintf("%d", userID) {
		return apperr.ErrUnauthorized
	}
	gw := gateway.Get()
	if gw == nil {
		return apperr.ErrGatewayConnect
	}
	if _, err := gw.Contract().SubmitTransaction("DeleteCiphertext", assetID); err != nil {
		return apperr.Wrap(apperr.ErrFabricNetwork, "delete ciphertext", err)
	}
	_ = os.Remove(filepath.Join(s.cfg.DataDir, "files", assetID+".bin"))
	return nil
}

func (s *FileService) getAsset(assetID string) (map[string]any, error) {
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
	return asset, nil
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
		return nil, apperr.ErrUnauthorized
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

func safeFilename(filename string) string {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return "demo.txt"
	}
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "\\", "_")
	return filename
}

func intFromAny(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	default:
		return 0
	}
}
