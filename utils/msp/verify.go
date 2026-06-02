package msp

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bc_abe/utils/apperr"
)

// VerifyCertByCA 验证用户证书由指定 CA 签发且未过期。
func VerifyCertByCA(userCertPEM, caCertPEM string) error {
	userBlock, _ := pem.Decode([]byte(userCertPEM))
	if userBlock == nil {
		return apperr.ErrUnauthorized
	}
	userCert, err := x509.ParseCertificate(userBlock.Bytes)
	if err != nil {
		return apperr.Wrap(apperr.ErrUnauthorized, "parse user cert", err)
	}
	now := time.Now()
	if now.Before(userCert.NotBefore) || now.After(userCert.NotAfter) {
		return apperr.ErrUnauthorized
	}

	caBlock, _ := pem.Decode([]byte(caCertPEM))
	if caBlock == nil {
		return apperr.Wrap(apperr.ErrUnauthorized, "parse ca cert", fmt.Errorf("invalid ca pem"))
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return apperr.Wrap(apperr.ErrUnauthorized, "parse ca cert", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	_, err = userCert.Verify(x509.VerifyOptions{Roots: roots})
	if err != nil {
		return apperr.Wrap(apperr.ErrUnauthorized, "cert not issued by org ca", err)
	}
	return nil
}

// LoadCACertFromMSP 从 test-network MSP 目录加载 CA 证书。
func LoadCACertFromMSP(cacertsDir string) (string, error) {
	entries, err := os.ReadDir(cacertsDir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(cacertsDir, e.Name()))
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	return "", fmt.Errorf("no ca cert in %s", cacertsDir)
}

// IsAdminIdentity 判断证书 CN 是否为 Admin 身份。
func IsAdminIdentity(cert *x509.Certificate) bool {
	cn := cert.Subject.CommonName
	if strings.Contains(strings.ToLower(cn), "admin") {
		return true
	}
	for _, ou := range cert.Subject.OrganizationalUnit {
		if strings.EqualFold(ou, "admin") {
			return true
		}
	}
	return false
}
