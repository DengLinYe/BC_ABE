package service

import (
	"strings"
	"testing"

	"bc_abe/utils/db"
)

func TestAuthorizeKeyIssue_fixedAttrDenied(t *testing.T) {
	user := &db.UserAccount{OrgName: "org1", Attributes: "Cry=21"}
	spec := attrSpec{IssueAttr: "a@auth0", DisplayLabel: "a@auth0"}
	err := authorizeKeyIssue(user, spec, "a@auth0")
	if err == nil || !strings.Contains(err.Error(), "未注册") {
		t.Fatalf("expected unregistered error, got %v", err)
	}
}

func TestAuthorizeKeyIssue_fixedAttrAllowed(t *testing.T) {
	user := &db.UserAccount{OrgName: "org1", Attributes: "a,Cry=21"}
	spec := attrSpec{IssueAttr: "a@auth0", DisplayLabel: "a@auth0"}
	if err := authorizeKeyIssue(user, spec, "a@auth0"); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizeKeyIssue_locAutoAllowed(t *testing.T) {
	user := &db.UserAccount{OrgName: "org1", Attributes: "Cry=21"}
	spec := locAttrSpec("org1", "school")
	if err := authorizeKeyIssue(user, spec, spec.DisplayLabel); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizeKeyIssue_numericFromRegistration(t *testing.T) {
	user := &db.UserAccount{OrgName: "org1", Attributes: "Cry=21"}
	spec := attrSpec{IssueAttr: "cry=21@auth0", DisplayLabel: "Cry@auth0 == 21"}
	if err := authorizeKeyIssue(user, spec, "cry@auth0 > 18"); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizeKeyIssue_numericCompareDenied(t *testing.T) {
	user := &db.UserAccount{OrgName: "org1", Attributes: "Cry=10"}
	spec := attrSpec{IssueAttr: "cry=10@auth0", DisplayLabel: "cry@auth0 > 18"}
	err := authorizeKeyIssue(user, spec, "cry@auth0 > 18")
	if err == nil {
		t.Fatal("expected compare failure")
	}
}
