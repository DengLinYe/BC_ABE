package service

import (
	"testing"

	abeengine "bc_abe/abe"
	"bc_abe/utils/db"
)

func TestParseAttrSpec_hourPolicy(t *testing.T) {
	for _, in := range []string{"hour@auth0 = 20", "hour@auth0 == 20"} {
		spec, err := parseAttrSpec(in, "org1")
		if err != nil {
			t.Fatal(err)
		}
		if spec.IssueAttr != "hour=20@auth0" {
			t.Fatalf("issue: got %q", spec.IssueAttr)
		}
		if spec.DisplayLabel != "hour@auth0 == 20" {
			t.Fatalf("display: got %q", spec.DisplayLabel)
		}
	}
}

func TestParseAttrSpec_hourLegacy(t *testing.T) {
	spec, err := parseAttrSpec("hour=20", "org1")
	if err != nil {
		t.Fatal(err)
	}
	if spec.IssueAttr != "hour=20@auth0" {
		t.Fatalf("issue: got %q", spec.IssueAttr)
	}
	if spec.DisplayLabel != "hour@auth0 == 20" {
		t.Fatalf("display: got %q", spec.DisplayLabel)
	}
}

func TestParseAttrSpec_rejectCrossOrg(t *testing.T) {
	_, err := parseAttrSpec("Vitality@auth0", "org2")
	if err == nil {
		t.Fatal("expected cross-org reject")
	}
	_, err = parseAttrSpec("hour@auth0 == 16", "org2")
	if err == nil {
		t.Fatal("expected cross-org hour reject")
	}
}

func TestParseAttrSpec_numericLegacy(t *testing.T) {
	spec, err := parseAttrSpec("Cry=20", "org1")
	if err != nil {
		t.Fatal(err)
	}
	if spec.IssueAttr != "cry=20@auth0" {
		t.Fatalf("issue: got %q", spec.IssueAttr)
	}
	if spec.DisplayLabel != "Cry@auth0 == 20" {
		t.Fatalf("display: got %q", spec.DisplayLabel)
	}
	spec, err = parseAttrSpec("Cry=20@auth0", "org1")
	if err != nil {
		t.Fatal(err)
	}
	if spec.DisplayLabel != "Cry@auth0 == 20" {
		t.Fatalf("display with auth: got %q", spec.DisplayLabel)
	}
}

func TestResolveAttrSpecForUser_numericCompare(t *testing.T) {
	user := &db.UserAccount{OrgName: "org1", Attributes: "Cry=20"}
	sp, err := resolveAttrSpecForUser(user, "Cry@auth0 > 18", "cry=18@auth0")
	if err != nil {
		t.Fatal(err)
	}
	if sp.IssueAttr != "cry=20@auth0" {
		t.Fatalf("issue: got %q", sp.IssueAttr)
	}
	_, err = resolveAttrSpecForUser(user, "Cry@auth0 > 30", "cry=30@auth0")
	if err == nil {
		t.Fatal("expected unsatisfied compare to fail")
	}
}

func TestKeyLabelsForPolicySpec_numeric(t *testing.T) {
	user := &db.UserAccount{OrgName: "org1", Attributes: "Cry=20,locschool"}
	spec := abeengine.KeyIssueSpec{IssueAttr: "cry=18@auth0", DisplayLabel: "Cry@auth0 > 18", AuthName: "auth0"}
	labels := keyLabelsForPolicySpec(user, spec)
	has := map[string]bool{}
	for _, l := range labels {
		has[l] = true
	}
	for _, want := range []string{"Cry=20@auth0", "Cry@auth0 == 20", "cry=20@auth0"} {
		if !has[want] {
			t.Fatalf("missing label %q in %v", want, labels)
		}
	}
	if has["Cry@auth0 > 18"] || has["cry=18@auth0"] {
		t.Fatalf("compare policy labels should not be key labels: %v", labels)
	}
}

func TestLocAttrSpec(t *testing.T) {
	spec := locAttrSpec("org1", "home")
	if spec.IssueAttr != "lochome@auth0" {
		t.Fatalf("issue: got %q", spec.IssueAttr)
	}
}

func TestNormalizeLocation(t *testing.T) {
	if normalizeLocation("school") != "school" {
		t.Fatal("school")
	}
	if normalizeLocation("学校") != "school" {
		t.Fatal("legacy chinese")
	}
	if normalizeLocation("") != "others" {
		t.Fatal("default others")
	}
}
