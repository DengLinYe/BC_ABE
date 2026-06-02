package msp

import (
	"fmt"
	"os"
	"path/filepath"
)

// LoadOrgCACertPEM 加载组织 Fabric CA 根证书（与用户 fabric-ca enroll 签发一致）。
func LoadOrgCACertPEM(fabricNetworkDir, orgName string) (string, error) {
	domain := "org1.example.com"
	if orgName == "org2" {
		domain = "org2.example.com"
	}
	candidates := []string{
		filepath.Join(fabricNetworkDir, "organizations/fabric-ca", orgName, "ca-cert.pem"),
		filepath.Join(fabricNetworkDir, "organizations/peerOrganizations", domain, "ca", "ca."+domain+"-cert.pem"),
	}
	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if err == nil && len(b) > 0 {
			return string(b), nil
		}
	}
	adminCACerts := filepath.Join(fabricNetworkDir, "organizations/peerOrganizations", domain, "users/Admin@"+domain+"/msp/cacerts")
	if cert, err := LoadCACertFromMSP(adminCACerts); err == nil {
		return cert, nil
	}
	return "", fmt.Errorf("no org ca cert found for %s", orgName)
}
