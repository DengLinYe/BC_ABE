package abe

import (
	"bytes"
	"testing"
)

// TestABERoundtrip_MultiAuthority 双 authority 策略加解密往返。
func TestABERoundtrip_MultiAuthority(t *testing.T) {
	e0 := NewEngine("bc-abe-demo-seed")
	if err := e0.InitOrg(); err != nil {
		t.Fatal(err)
	}
	if err := e0.InitAuthority(); err != nil {
		t.Fatal(err)
	}
	orgJSON := e0.OrgJSON()

	e1 := NewEngine("bc-abe-demo-seed")
	if err := e1.LoadOrgFromJSON(orgJSON); err != nil {
		t.Fatal(err)
	}
	if err := e1.InitAuthority(); err != nil {
		t.Fatal(err)
	}

	policy := NormalizePolicySyntax("(Vitality@auth0 /\\ locschool@auth1)")
	authpubs := e0.AuthPubsOfPolicy(policy)
	authpubs.AuthPub["auth0"] = e0.AuthKeys().AuthPub
	authpubs.AuthPub["auth1"] = e1.AuthKeys().AuthPub

	secret, err := e0.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	wantKey, _ := SymKeyFromSecret(secret)

	ct, err := e0.Encrypt(secret, policy, authpubs)
	if err != nil {
		t.Fatal(err)
	}

	ua0, err := e0.IssueUserKey("alice", "Vitality@auth0")
	if err != nil {
		t.Fatal(err)
	}
	ua1, err := e1.IssueUserKey("alice", "locschool@auth1")
	if err != nil {
		t.Fatal(err)
	}
	merged := e0.MergeUserKeys(ua0, ua1)
	for a := range merged.Userkey {
		merged.Coeff[a] = []int{}
	}

	gotSecret, err := e0.Decrypt(ct, merged)
	if err != nil {
		t.Fatal(err)
	}
	gotKey, _ := SymKeyFromSecret(gotSecret)
	if !bytes.Equal(wantKey[:], gotKey[:]) {
		t.Fatal("multi-authority roundtrip failed")
	}
}
