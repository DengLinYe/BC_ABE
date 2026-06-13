package abe

import (
	"bytes"
	"strings"
	"testing"

	mosaic "bc_abe/pkg/mosaic/abe"
)

func TestABERoundtrip_UserORPolicy(t *testing.T) {
	e := NewEngine("bc-abe-demo-seed")
	if err := e.InitOrg(); err != nil {
		t.Fatal(err)
	}
	if err := e.InitAuthority(); err != nil {
		t.Fatal(err)
	}
	policy := NormalizePolicySyntax("((hour@auth1 == 16) \\/ (Vitality@auth1 /\\ locschool@auth1))")
	authpubs := e.AuthPubsOfPolicy(policy)
	e.FillAuthPub(authpubs, "auth1")
	var merged *UserAttrs
	for _, attr := range []string{"hour=16@auth1", "Vitality@auth1", "locschool@auth1"} {
		ua, err := e.IssueUserKey("alice", attr)
		if err != nil {
			t.Fatal(err)
		}
		merged = e.MergeUserKeys(merged, ua)
	}
	for a := range merged.Userkey {
		merged.Coeff[a] = []int{}
	}
	secret, err := e.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	wantKey, _ := SymKeyFromSecret(secret)
	ct, err := e.Encrypt(secret, policy, authpubs)
	if err != nil {
		t.Fatal(err)
	}
	gotSecret, err := e.Decrypt(ct, merged)
	if err != nil {
		t.Fatal(err)
	}
	gotKey, _ := SymKeyFromSecret(gotSecret)
	if !bytes.Equal(wantKey[:], gotKey[:]) {
		t.Fatal("user OR policy roundtrip failed")
	}
}

func TestABERoundtrip_FlatAndWithHour(t *testing.T) {
	e := NewEngine("bc-abe-demo-seed")
	if err := e.InitOrg(); err != nil {
		t.Fatal(err)
	}
	if err := e.InitAuthority(); err != nil {
		t.Fatal(err)
	}
	policy := NormalizePolicySyntax("(hour@auth1 == 16) /\\ (Vitality@auth1 /\\ locschool@auth1)")
	authpubs := e.AuthPubsOfPolicy(policy)
	e.FillAuthPub(authpubs, "auth1")
	var merged *UserAttrs
	for _, attr := range []string{"hour=16@auth1", "Vitality@auth1", "locschool@auth1"} {
		ua, err := e.IssueUserKey("alice", attr)
		if err != nil {
			t.Fatal(err)
		}
		merged = e.MergeUserKeys(merged, ua)
	}
	for a := range merged.Userkey {
		merged.Coeff[a] = []int{}
	}
	secret, err := e.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	wantKey, _ := SymKeyFromSecret(secret)
	ct, err := e.Encrypt(secret, policy, authpubs)
	if err != nil {
		t.Fatal(err)
	}
	gotSecret, err := e.Decrypt(ct, merged)
	if err != nil {
		t.Fatal(err)
	}
	gotKey, _ := SymKeyFromSecret(gotSecret)
	if !bytes.Equal(wantKey[:], gotKey[:]) {
		t.Fatal("flat AND with hour roundtrip failed")
	}
}

func TestValidateNumericCompare(t *testing.T) {
	if err := ValidateNumericCompare("score", ">", 34); err != nil {
		t.Fatalf("score > 34: %v", err)
	}
	if err := ValidateNumericCompare("score", ">=", 0); err == nil {
		t.Fatal("expected >= 0 to fail")
	}
	if err := ValidateNumericCompare("score", "<", 0); err == nil {
		t.Fatal("expected < 0 to fail")
	}
	if err := ValidateNumericCompare("hour", "==", 24); err == nil {
		t.Fatal("expected hour 24 to fail")
	}
	if err := ValidateNumericCompare("score", ">", 65536); err == nil {
		t.Fatal("expected overflow to fail")
	}
}

func TestNormalizeNumericPrecedence(t *testing.T) {
	in := "hour@auth1 == 17 /\\ (Vitality@auth1 /\\ locschool@auth1)"
	out := NormalizePolicySyntax(in)
	if out != "(hour@auth1 == 17) /\\ Vitality@auth1 /\\ locschool@auth1" {
		t.Fatalf("unexpected normalize: %q", out)
	}
}

func TestValidateUIPolicy(t *testing.T) {
	ok := []string{
		"score@auth0 > 34",
		"(Vitality@auth1 /\\ locschool@auth1)",
		"hour@auth1 == 17",
		"hour@auth1 == 17 /\\ (Vitality@auth1 /\\ locschool@auth1)",
		"(hour@auth1 == 17 /\\ (Vitality@auth1 /\\ locschool@auth1))",
		"(hour@auth1 == 17 /\\ locschool@auth1)",
		"((hour@auth1 == 16) \\/ (Vitality@auth1 /\\ locschool@auth1))",
	}
	for _, p := range ok {
		if err := ValidateUIPolicy(p); err != nil {
			t.Fatalf("expected ok %q: %v", p, err)
		}
	}
	bad := []string{
		"(score@auth0 > 34 /\\ hour@auth0 == 20)",
		"score@auth0 >= 0",
	}
	for _, p := range bad {
		if err := ValidateUIPolicy(p); err == nil {
			t.Fatalf("expected fail %q", p)
		}
	}
}

func TestFlattenNestedAndGroups(t *testing.T) {
	in := "(hour@auth1 == 16) /\\ (Vitality@auth1 /\\ locschool@auth1)"
	out := NormalizePolicySyntax(in)
	want := "(hour@auth1 == 16) /\\ Vitality@auth1 /\\ locschool@auth1"
	if out != want {
		t.Fatalf("flatten: got %q want %q", out, want)
	}
}

func TestABERoundtrip_NumericGreaterThan(t *testing.T) {
	e := NewEngine("bc-abe-demo-seed")
	if err := e.InitOrg(); err != nil {
		t.Fatal(err)
	}
	if err := e.InitAuthority(); err != nil {
		t.Fatal(err)
	}
	policy := NormalizePolicySyntax("(cry@auth0 > 18)")
	authpubs := e.AuthPubsOfPolicy(policy)
	e.FillAuthPub(authpubs, "auth0")
	ua, err := e.IssueUserKey("alice", "cry=20@auth0")
	if err != nil {
		t.Fatal(err)
	}
	for a := range ua.Userkey {
		ua.Coeff[a] = []int{}
	}
	secret, err := e.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	wantKey, _ := SymKeyFromSecret(secret)
	ct, err := e.Encrypt(secret, policy, authpubs)
	if err != nil {
		t.Fatal(err)
	}
	gotSecret, err := e.Decrypt(ct, ua)
	if err != nil {
		t.Fatal(err)
	}
	gotKey, _ := SymKeyFromSecret(gotSecret)
	if !bytes.Equal(wantKey[:], gotKey[:]) {
		t.Fatal("numeric greater-than roundtrip failed")
	}
}

func TestDecrypt_LegacyCiphertextAttrCase(t *testing.T) {
	e := NewEngine("bc-abe-demo-seed")
	if err := e.InitOrg(); err != nil {
		t.Fatal(err)
	}
	if err := e.InitAuthority(); err != nil {
		t.Fatal(err)
	}
	policy := NormalizePolicySyntax("cry@auth0 > 18")
	authpubs := e.AuthPubsOfPolicy(policy)
	e.FillAuthPub(authpubs, "auth0")
	secret, err := e.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	wantKey, _ := SymKeyFromSecret(secret)
	ct, err := e.Encrypt(secret, policy, authpubs)
	if err != nil {
		t.Fatal(err)
	}
	legacyC := make(map[string][][]mosaic.Point, len(ct.C))
	for k, v := range ct.C {
		if strings.HasPrefix(k, "cry-") {
			legacyC["Cry-"+k[4:]] = v
		} else {
			legacyC[k] = v
		}
	}
	ct.C = legacyC
	ct.Policy = "Cry@auth0 > 18"

	ua, err := e.IssueUserKey("alice", "cry=21@auth0")
	if err != nil {
		t.Fatal(err)
	}
	for a := range ua.Userkey {
		ua.Coeff[a] = []int{}
	}
	gotSecret, err := e.Decrypt(ct, ua)
	if err != nil {
		t.Fatal(err)
	}
	gotKey, _ := SymKeyFromSecret(gotSecret)
	if !bytes.Equal(wantKey[:], gotKey[:]) {
		t.Fatal("legacy ciphertext case roundtrip failed")
	}
}

func TestParseNumericClause(t *testing.T) {
	nc, ok := ParseNumericClause("Cry@auth0 > 18")
	if !ok || nc.Op != ">" || nc.Value != 18 || nc.Attr != "Cry" {
		t.Fatalf("parse: %+v ok=%v", nc, ok)
	}
	if !NumericCompareSatisfied(20, ">", 18) {
		t.Fatal("20 > 18")
	}
	if NumericCompareSatisfied(10, ">", 18) {
		t.Fatal("10 > 18 should be false")
	}
}

func TestKeyIssueSpecsFromPolicy(t *testing.T) {
	policy := "(hour@auth1 == 16) /\\ (Vitality@auth1 /\\ locschool@auth1)"
	specs, err := KeyIssueSpecsFromPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 3 {
		t.Fatalf("expected 3 specs, got %d", len(specs))
	}
	if specs[0].IssueAttr != "hour=16@auth1" {
		t.Fatalf("hour issue: %q", specs[0].IssueAttr)
	}
	vars := PolicyVars(policy)
	if len(vars) != 34 {
		t.Fatalf("expected 34 policy vars, got %d", len(vars))
	}
	exp := IssueAttributeExpansion("hour=16@auth1")
	if len(exp) != 32 {
		t.Fatalf("expected 32 bit attrs, got %d", len(exp))
	}
}
