package msp

import (
	"fmt"
	"os"
	"path/filepath"
)

// LoadIdentityFromMSP 从 Fabric MSP 目录加载 signcert 与私钥。
func LoadIdentityFromMSP(mspDir string) (certPEM, keyPEM string, err error) {
	certPEM, err = readFirstFile(filepath.Join(mspDir, "signcerts"))
	if err != nil {
		return "", "", fmt.Errorf("load signcert from %s: %w", mspDir, err)
	}
	keyPEM, err = readFirstFile(filepath.Join(mspDir, "keystore"))
	if err != nil {
		return "", "", fmt.Errorf("load keystore from %s: %w", mspDir, err)
	}
	return certPEM, keyPEM, nil
}

func readFirstFile(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	return "", fmt.Errorf("no file in %s", dir)
}
