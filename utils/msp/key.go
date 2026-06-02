package msp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseECPrivateKeyPEM 解析 Fabric MSP / fabric-ca 导出的 ECDSA 私钥（SEC1 或 PKCS#8）。
func ParseECPrivateKeyPEM(keyPEM string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid key pem")
	}

	var parsed any
	var err error
	switch block.Type {
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		if k, e := x509.ParseECPrivateKey(block.Bytes); e == nil {
			parsed = k
		} else if k, e := x509.ParsePKCS8PrivateKey(block.Bytes); e == nil {
			parsed = k
		} else {
			return nil, fmt.Errorf("unsupported key type %q", block.Type)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not ECDSA")
	}
	return key, nil
}

// SignASN1 使用用户私钥对哈希做 ECDSA 签名。
func SignASN1(keyPEM string, hash []byte) ([]byte, error) {
	key, err := ParseECPrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	return ecdsa.SignASN1(rand.Reader, key, hash)
}
