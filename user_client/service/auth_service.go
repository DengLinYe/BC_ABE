package service

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"bc_abe/utils/apperr"
	"bc_abe/utils/config"
	"bc_abe/utils/db"
	"bc_abe/utils/fabricca"

	"golang.org/x/crypto/bcrypt"
)

// AuthService 用户认证与注册服务。
type AuthService struct{}

func NewAuthService() *AuthService {
	return &AuthService{}
}

func (s *AuthService) Register(username, password, orgName, attributes string) (*db.UserAccount, error) {
	var dup db.UserAccount
	if err := db.Get().Where("username = ?", username).First(&dup).Error; err == nil {
		return nil, apperr.Wrap(apperr.ErrInvalidInput, "create user", fmt.Errorf("username already exists"))
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	enrollSecret := randomSecret()
	caClient := fabricca.NewClient(orgName)
	result, err := caClient.RegisterAndEnroll(username, enrollSecret)
	if err != nil {
		return nil, apperr.Wrap(apperr.ErrFabricNetwork, "fabric-ca enroll", err)
	}

	user := db.UserAccount{
		Username:     username,
		PasswordHash: string(hash),
		OrgName:      orgName,
		Attributes:   attributes,
		CertPEM:      result.CertPEM,
		KeyPEM:       result.KeyPEM,
		MSPID:        config.MSPIDForOrg(orgName),
	}
	if err := db.Get().Create(&user).Error; err != nil {
		return nil, apperr.Wrap(apperr.ErrInvalidInput, "create user", err)
	}
	return &user, nil
}

func (s *AuthService) Login(username, password string) (*db.UserAccount, error) {
	var user db.UserAccount
	if err := db.Get().Where("username = ?", username).First(&user).Error; err != nil {
		return nil, apperr.ErrUnauthorized
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, apperr.ErrUnauthorized
	}
	return &user, nil
}

func (s *AuthService) GetUser(userID uint) (*db.UserAccount, error) {
	var user db.UserAccount
	if err := db.Get().First(&user, userID).Error; err != nil {
		return nil, apperr.ErrNotFound
	}
	return &user, nil
}

func UserAttributes(user *db.UserAccount) []string {
	if user.Attributes == "" {
		return nil
	}
	authName := config.AuthNameForOrg(user.OrgName)
	out := []string{}
	for _, p := range strings.Split(user.Attributes, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "@") {
			out = append(out, p)
		} else {
			out = append(out, fmt.Sprintf("%s@%s", p, authName))
		}
	}
	return out
}

func randomSecret() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
