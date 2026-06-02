package service

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"bc_abe/utils/config"
)

type attrSpec struct {
	IssueAttr    string
	DisplayLabel string
}

var (
	reHourPolicy = regexp.MustCompile(`(?i)^hour@([a-zA-Z0-9_]+)\s*(==|=|>=|<=|>|<)\s*(\d+)\s*$`)
	reHourLegacy = regexp.MustCompile(`(?i)^hour=(\d+)(@([a-zA-Z0-9_]+))?\s*$`)
)

func parseAttrSpec(input, orgName string) (attrSpec, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return attrSpec{}, fmt.Errorf("empty attribute")
	}
	auth := config.AuthNameForOrg(orgName)

	if m := reHourPolicy.FindStringSubmatch(input); len(m) == 4 {
		hour, err := strconv.Atoi(m[3])
		if err != nil || hour < 0 || hour > 23 {
			return attrSpec{}, fmt.Errorf("hour must be 0-23")
		}
		op := normalizeHourOp(strings.TrimSpace(m[2]))
		an := strings.TrimSpace(m[1])
		return attrSpec{
			IssueAttr:    fmt.Sprintf("hour=%d@%s", hour, an),
			DisplayLabel: fmt.Sprintf("hour@%s %s %d", an, op, hour),
		}, nil
	}

	if m := reHourLegacy.FindStringSubmatch(input); len(m) >= 2 {
		hour, err := strconv.Atoi(m[1])
		if err != nil || hour < 0 || hour > 23 {
			return attrSpec{}, fmt.Errorf("hour must be 0-23")
		}
		an := auth
		if len(m) >= 4 && m[3] != "" {
			an = m[3]
		}
		return attrSpec{
			IssueAttr:    fmt.Sprintf("hour=%d@%s", hour, an),
			DisplayLabel: fmt.Sprintf("hour@%s == %d", an, hour),
		}, nil
	}

	issue := appendAuthSuffix(input, orgName)
	display := issue
	if strings.Contains(input, " ") {
		display = input
	}
	return attrSpec{IssueAttr: issue, DisplayLabel: display}, nil
}

func appendAuthSuffix(attribute, orgName string) string {
	attribute = strings.TrimSpace(attribute)
	if attribute == "" {
		return ""
	}
	if strings.Contains(attribute, "@") {
		return attribute
	}
	return attribute + "@" + config.AuthNameForOrg(orgName)
}

func hourAttrSpec(orgName string, hour int, op string) attrSpec {
	op = normalizeHourOp(op)
	auth := config.AuthNameForOrg(orgName)
	return attrSpec{
		IssueAttr:    fmt.Sprintf("hour=%d@%s", hour, auth),
		DisplayLabel: fmt.Sprintf("hour@%s %s %d", auth, op, hour),
	}
}

func locAttrSpec(orgName, location string) attrSpec {
	location = normalizeLocation(location)
	auth := config.AuthNameForOrg(orgName)
	name := "loc" + location
	return attrSpec{
		IssueAttr:    name + "@" + auth,
		DisplayLabel: name + "@" + auth,
	}
}

func normalizeHourOp(op string) string {
	switch strings.TrimSpace(op) {
	case "==", "=":
		return "=="
	case ">=", "<=", ">", "<":
		return strings.TrimSpace(op)
	default:
		return "=="
	}
}

func normalizeLocation(location string) string {
	location = strings.TrimSpace(location)
	switch location {
	case "", "其他", "others":
		return "others"
	case "学校", "school":
		return "school"
	case "家", "home":
		return "home"
	default:
		return location
	}
}

func isPolicyStyleKeyAttr(issueAttr string) bool {
	issueAttr = strings.ToLower(issueAttr)
	return strings.HasPrefix(issueAttr, "hour=") || strings.HasPrefix(issueAttr, "loc")
}
