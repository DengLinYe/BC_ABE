package fabricdocker

import (
	"fmt"
	"os"
	"path/filepath"

	"bc_abe/utils/apperr"
	"bc_abe/utils/logger"
)

var artifactLog = logger.New("fabricdocker/artifacts")

// cryptoCheckpoints 判断 Fabric 证书是否完整生成。
var cryptoCheckpoints = []string{
	"organizations/fabric-ca/org1/ca-cert.pem",
	"organizations/fabric-ca/org2/ca-cert.pem",
	"organizations/fabric-ca/ordererOrg/ca-cert.pem",
	"organizations/peerOrganizations/org1.example.com/msp/cacerts",
	"organizations/peerOrganizations/org2.example.com/msp/cacerts",
	"organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp/signcerts",
	"organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/msp/signcerts",
	"organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/signcerts",
}

// CryptoMaterialReady 检查 test-network 证书目录是否完整。
func CryptoMaterialReady(networkDir string) bool {
	for _, rel := range cryptoCheckpoints {
		p := filepath.Join(networkDir, rel)
		if !dirHasFiles(p) {
			artifactLog.Debug("crypto checkpoint missing: %s", rel)
			return false
		}
	}
	return true
}

// WipeNetworkArtifacts 删除 test-network 生成的证书与通道产物（等同 network.sh down 的文件清理）。
func WipeNetworkArtifacts(networkDir string) error {
	targets := []string{
		"organizations/peerOrganizations",
		"organizations/ordererOrganizations",
		"channel-artifacts",
		"system-genesis-block",
	}
	for _, rel := range targets {
		p := filepath.Join(networkDir, rel)
		if err := os.RemoveAll(p); err != nil {
			return apperr.Wrap(apperr.ErrFabricNetwork, "remove "+rel, err)
		}
	}
	for _, org := range []string{"org1", "org2", "ordererOrg"} {
		if err := wipeFabricCAOrg(filepath.Join(networkDir, "organizations/fabric-ca", org)); err != nil {
			return err
		}
	}
	artifactLog.Info("network artifacts wiped under %s", networkDir)
	return nil
}

func wipeFabricCAOrg(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if name == "fabric-ca-server-config.yaml" {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// EnsureCryptoMaterial 若证书不完整则清理残留目录，迫使 network.sh 重新 createOrgs。
func EnsureCryptoMaterial(networkDir string) error {
	if CryptoMaterialReady(networkDir) {
		artifactLog.Info("fabric crypto material looks complete")
		return nil
	}
	artifactLog.Warn("incomplete fabric crypto material detected, wiping for regeneration")
	if err := WipeNetworkArtifacts(networkDir); err != nil {
		return err
	}
	return nil
}

func dirHasFiles(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if !info.IsDir() {
		return info.Size() > 0
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			return true
		}
	}
	return false
}

// ValidateCryptoMaterial 返回可读错误，供部署前检查。
func ValidateCryptoMaterial(networkDir string) error {
	if CryptoMaterialReady(networkDir) {
		return nil
	}
	return fmt.Errorf("fabric MSP incomplete under %s (likely from a previous failed deploy; artifacts will be wiped and regenerated)", networkDir)
}
