package service

import "testing"

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
