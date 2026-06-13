package service

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	abeengine "bc_abe/abe"
	"bc_abe/utils/config"
	"bc_abe/utils/db"
)

type attrSpec struct {
	IssueAttr    string
	DisplayLabel string
}

var (
	reHourPolicy    = regexp.MustCompile(`(?i)^hour@([a-zA-Z0-9_]+)\s*(==|=|>=|<=|>|<)\s*(\d+)\s*$`)
	reHourLegacy    = regexp.MustCompile(`(?i)^hour=(\d+)(@([a-zA-Z0-9_]+))?\s*$`)
	reNumericLegacy = regexp.MustCompile(`(?i)^([a-zA-Z][a-zA-Z0-9_]*)=(\d+)(@([a-zA-Z0-9_]+))?\s*$`)
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
		if an != auth {
			return attrSpec{}, fmt.Errorf("只能申请本组织 @%s 的时间属性（当前 %s）", auth, orgName)
		}
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
		if an != auth {
			return attrSpec{}, fmt.Errorf("只能申请本组织 @%s 的时间属性（当前 %s）", auth, orgName)
		}
		return attrSpec{
			IssueAttr:    fmt.Sprintf("hour=%d@%s", hour, an),
			DisplayLabel: fmt.Sprintf("hour@%s == %d", an, hour),
		}, nil
	}

	if m := reNumericLegacy.FindStringSubmatch(input); len(m) >= 3 {
		name := m[1]
		if strings.EqualFold(name, "hour") {
			return attrSpec{}, fmt.Errorf("hour must be 0-23")
		}
		value, err := strconv.Atoi(m[2])
		if err != nil {
			return attrSpec{}, fmt.Errorf("invalid numeric attribute value")
		}
		an := auth
		if len(m) >= 5 && m[4] != "" {
			an = m[4]
		}
		if an != auth {
			return attrSpec{}, fmt.Errorf("不能跨组织申请密钥：@%s 仅限 %s（@%s）", an, orgName, auth)
		}
		return numericAttrSpec(name, value, an), nil
	}

	issue := appendAuthSuffix(input, orgName)
	display := issue
	if strings.Contains(input, " ") {
		display = input
	}
	if err := validateAttrOrgAuth(orgName, issue); err != nil {
		return attrSpec{}, err
	}
	return attrSpec{IssueAttr: issue, DisplayLabel: display}, nil
}

func validateAttrOrgAuth(orgName, attr string) error {
	userAuth := config.AuthNameForOrg(orgName)
	attrAuth := authFromAttrString(attr)
	if attrAuth != "" && attrAuth != userAuth {
		return fmt.Errorf("不能跨组织申请密钥：@%s 仅限 %s（@%s）", attrAuth, orgName, userAuth)
	}
	return nil
}

func authFromAttrString(s string) string {
	i := strings.LastIndex(s, "@")
	if i < 0 {
		return ""
	}
	tail := strings.TrimSpace(s[i+1:])
	if j := strings.IndexAny(tail, " \t"); j >= 0 {
		tail = tail[:j]
	}
	return tail
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

func numericAttrSpec(name string, value int, auth string) attrSpec {
	lower := strings.ToLower(name)
	return attrSpec{
		IssueAttr:    fmt.Sprintf("%s=%d@%s", lower, value, auth),
		DisplayLabel: fmt.Sprintf("%s@%s == %d", name, auth, value),
	}
}

func findUserNumericAttr(user *db.UserAccount, attrBase, auth string) (value int, spec attrSpec, ok bool) {
	attrBase = strings.ToLower(strings.TrimSpace(attrBase))
	auth = strings.TrimSpace(auth)
	for _, raw := range UserAttributes(user) {
		sp, err := parseAttrSpec(raw, user.OrgName)
		if err != nil {
			continue
		}
		m := reNumericLegacy.FindStringSubmatch(sp.IssueAttr)
		if m == nil {
			m = reNumericLegacy.FindStringSubmatch(raw)
		}
		if m == nil {
			continue
		}
		if strings.ToLower(m[1]) != attrBase {
			continue
		}
		an := config.AuthNameForOrg(user.OrgName)
		if len(m) >= 5 && m[4] != "" {
			an = m[4]
		}
		if an != auth {
			continue
		}
		v, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		return v, sp, true
	}
	return 0, attrSpec{}, false
}

func resolveAttrSpecForUser(user *db.UserAccount, displayLabel, fallbackIssue string) (attrSpec, error) {
	nc, ok := abeengine.ParseNumericClause(displayLabel)
	if !ok {
		if sp, err := parseAttrSpec(displayLabel, user.OrgName); err == nil {
			return sp, nil
		}
		return attrSpec{IssueAttr: fallbackIssue, DisplayLabel: displayLabel}, nil
	}
	if nc.Op == "==" {
		if sp, err := parseAttrSpec(displayLabel, user.OrgName); err == nil {
			return sp, nil
		}
		return attrSpec{IssueAttr: fallbackIssue, DisplayLabel: displayLabel}, nil
	}
	userVal, sp, found := findUserNumericAttr(user, nc.Attr, nc.Auth)
	if !found {
		return attrSpec{}, fmt.Errorf("用户未注册数值属性 %s@%s", nc.Attr, nc.Auth)
	}
	if !abeengine.NumericCompareSatisfied(userVal, nc.Op, nc.Value) {
		return attrSpec{}, fmt.Errorf("用户 %s=%d 不满足策略 %s", nc.Attr, userVal, displayLabel)
	}
	return sp, nil
}

func keyLabelsForPolicySpec(user *db.UserAccount, spec abeengine.KeyIssueSpec) []string {
	nc, ok := abeengine.ParseNumericClause(spec.DisplayLabel)
	if ok && nc.Op != "==" {
		sp, err := resolveAttrSpecForUser(user, spec.DisplayLabel, spec.IssueAttr)
		if err != nil {
			return nil
		}
		labels := []string{sp.DisplayLabel, sp.IssueAttr}
		for _, raw := range UserAttributes(user) {
			sp2, err := parseAttrSpec(raw, user.OrgName)
			if err != nil {
				continue
			}
			if sp2.IssueAttr != sp.IssueAttr {
				continue
			}
			labels = append(labels, raw, sp2.DisplayLabel)
		}
		return dedupeLabels(labels)
	}
	labels := []string{spec.DisplayLabel, spec.IssueAttr}
	if sp, err := parseAttrSpec(spec.DisplayLabel, user.OrgName); err == nil {
		labels = append(labels, sp.DisplayLabel, sp.IssueAttr)
	} else if sp, err := resolveAttrSpecForUser(user, spec.DisplayLabel, spec.IssueAttr); err == nil {
		labels = append(labels, sp.DisplayLabel, sp.IssueAttr)
	}
	if ok {
		for _, raw := range UserAttributes(user) {
			sp, err := parseAttrSpec(raw, user.OrgName)
			if err != nil {
				labels = append(labels, raw)
				continue
			}
			m := reNumericLegacy.FindStringSubmatch(sp.IssueAttr)
			if m != nil && strings.EqualFold(m[1], nc.Attr) {
				labels = append(labels, raw, sp.DisplayLabel, sp.IssueAttr)
			}
		}
	}
	return dedupeLabels(labels)
}

func dedupeLabels(labels []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(labels))
	for _, l := range labels {
		l = strings.TrimSpace(l)
		if l == "" || seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out
}

func numericKeyBase(label, orgName string) string {
	sp, err := parseAttrSpec(label, orgName)
	if err != nil {
		return ""
	}
	m := reNumericLegacy.FindStringSubmatch(sp.IssueAttr)
	if m == nil {
		return ""
	}
	auth := config.AuthNameForOrg(orgName)
	if len(m) >= 5 && m[4] != "" {
		auth = m[4]
	}
	return strings.ToLower(m[1]) + "@" + auth
}

func isPolicyStyleKeyAttr(issueAttr string) bool {
	issueAttr = strings.ToLower(issueAttr)
	return strings.HasPrefix(issueAttr, "hour=") || strings.HasPrefix(issueAttr, "loc")
}
