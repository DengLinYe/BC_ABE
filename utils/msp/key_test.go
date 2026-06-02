package msp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestParseECPrivateKeyPEM_PKCS8(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	parsed, err := ParseECPrivateKeyPEM(string(pemBytes))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.D.Cmp(key.D) != 0 {
		t.Fatal("parsed key mismatch")
	}
}

func TestParseECPrivateKeyPEM_SEC1(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	parsed, err := ParseECPrivateKeyPEM(string(pemBytes))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.D.Cmp(key.D) != 0 {
		t.Fatal("parsed key mismatch")
	}
}

func TestSignASN1_PKCS8(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	hash := []byte("test-body-hash------------------")
	sig, err := SignASN1(string(pemBytes), hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, hash, sig) {
		t.Fatal("signature verify failed")
	}
}
