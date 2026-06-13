package abe

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	mosaic "bc_abe/pkg/mosaic/abe"
)

const (
	PolicyIntMin  = 0
	PolicyIntMax  = 65535
	PolicyHourMax = 23
)

var (
	reHourSingleEq        = regexp.MustCompile(`(?i)(hour@[a-zA-Z0-9_]+)\s*=\s*(\d+)`)
	rePolicyAnd           = regexp.MustCompile(`(?i)\s+and\s+`)
	rePolicyOr            = regexp.MustCompile(`(?i)\s+or\s+`)
	reLocUnderscore       = regexp.MustCompile(`(?i)loc_(school|home|others)@`)
	rePolicyNumericClause = regexp.MustCompile(`(?i)([a-zA-Z][a-zA-Z0-9_]*)@([a-zA-Z0-9_]+)\s*(==|>=|<=|>|<)\s*(\d+)\s*$`)
	rePolicyAttrName      = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)
)

// NumericClause 策略中的数值比较子句。
type NumericClause struct {
	Attr  string
	Auth  string
	Op    string
	Value int
	Raw   string
}

// ParseNumericClause 解析单条数值比较策略叶子。
func ParseNumericClause(part string) (NumericClause, bool) {
	part = strings.TrimSpace(part)
	m := rePolicyNumericClause.FindStringSubmatch(part)
	if m == nil {
		return NumericClause{}, false
	}
	value, _ := strconv.Atoi(m[4])
	return NumericClause{
		Attr:  m[1],
		Auth:  m[2],
		Op:    m[3],
		Value: value,
		Raw:   part,
	}, true
}

// NumericCompareSatisfied 判断用户数值是否满足比较子句。
func NumericCompareSatisfied(userValue int, op string, threshold int) bool {
	switch op {
	case "==":
		return userValue == threshold
	case ">":
		return userValue > threshold
	case ">=":
		return userValue >= threshold
	case "<":
		return userValue < threshold
	case "<=":
		return userValue <= threshold
	default:
		return false
	}
}

// KeyIssueSpec 向 authority 申请 userkey 的属性规格。
type KeyIssueSpec struct {
	IssueAttr    string
	DisplayLabel string
	AuthName     string
}

type policyClause struct {
	raw   string
	attr  string
	op    string
	value int
}

// NormalizePolicySyntax 修正 UI/旧数据里不符合 ABE 语法的片段。
func NormalizePolicySyntax(policy string) string {
	p := strings.TrimSpace(policy)
	p = reHourSingleEq.ReplaceAllString(p, "${1} == ${2}")
	p = rePolicyAnd.ReplaceAllString(p, " /\\ ")
	p = rePolicyOr.ReplaceAllString(p, " \\/ ")
	p = reLocUnderscore.ReplaceAllString(p, "loc$1@")
	p = normalizePolicyAttrCase(p)
	p = flattenNestedAndGroups(p)
	p = normalizeNumericPrecedence(p)
	return strings.TrimSpace(p)
}

// ValidateNumericCompare 校验 Mosaic 数值比较子句中的整数与运算符。
func ValidateNumericCompare(attr, op string, value int) error {
	attr = strings.TrimSpace(attr)
	op = strings.TrimSpace(op)
	if !rePolicyAttrName.MatchString(attr) {
		return fmt.Errorf("属性名仅允许英文字母、数字、下划线，且以字母开头")
	}
	isHour := strings.EqualFold(attr, "hour")
	max := PolicyIntMax
	if isHour {
		max = PolicyHourMax
	}
	if value < PolicyIntMin || value > max {
		return fmt.Errorf("数值须在 %d–%d", PolicyIntMin, max)
	}
	switch op {
	case ">=":
		if value < 1 {
			return fmt.Errorf(">= 的比较值须为 ≥1 的自然数")
		}
	case "<":
		if value < 1 {
			return fmt.Errorf("< 的比较值须为 ≥1 的自然数")
		}
	case "==", "<=", ">":
	default:
		return fmt.Errorf("不支持的比较运算符 %s", op)
	}
	return nil
}

// CheckPolicyEncryptable 校验策略能否实际加密（矩阵行索引与属性一致）。
func CheckPolicyEncryptable(policy string) error {
	err := mosaic.CheckPolicyEncryptable(NormalizePolicySyntax(policy))
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "matrix mismatch") {
		return fmt.Errorf("策略结构无效（数值比较须用括号与其他条件分隔）: %w", err)
	}
	return fmt.Errorf("策略无法完成加密: %w", err)
}

// ValidateUIPolicy 校验 UI 可构造的策略（数值范围、组合规则 + Mosaic 语法）。
func ValidateUIPolicy(policy string) error {
	policy = NormalizePolicySyntax(policy)
	if strings.TrimSpace(policy) == "" {
		return fmt.Errorf("策略不能为空")
	}
	clauses := parsePolicyClauses(policy)
	for _, c := range clauses {
		if c.op == "" {
			continue
		}
		if err := ValidateNumericCompare(c.attr, c.op, c.value); err != nil {
			return err
		}
	}
	if err := validatePolicyComposition(clauses); err != nil {
		return err
	}
	if err := mosaic.CheckPolicyEncryptable(policy); err != nil {
		return err
	}
	if err := mosaic.ValidateAccessPolicy(policy); err != nil {
		return err
	}
	return nil
}

// KeyIssueSpecsFromPolicy 从策略提取需申请的属性（每条数值比较、每个布尔属性各一条）。
func KeyIssueSpecsFromPolicy(policy string) ([]KeyIssueSpec, error) {
	policy = NormalizePolicySyntax(policy)
	parts := policyLeafClauses(policy)
	if len(parts) == 0 {
		return nil, fmt.Errorf("策略无有效属性")
	}
	seen := map[string]bool{}
	var specs []KeyIssueSpec
	for _, part := range parts {
		part = strings.TrimSpace(part)
		m := rePolicyNumericClause.FindStringSubmatch(part)
		if m != nil {
			auth := authNameFromClause(part)
			if auth == "" {
				return nil, fmt.Errorf("无法解析属性 authority: %s", part)
			}
			value, _ := strconv.Atoi(m[4])
			issue := fmt.Sprintf("%s=%d@%s", strings.ToLower(m[1]), value, auth)
			if seen[issue] {
				continue
			}
			seen[issue] = true
			specs = append(specs, KeyIssueSpec{
				IssueAttr:    issue,
				DisplayLabel: part,
				AuthName:     auth,
			})
			continue
		}
		if part == "" || seen[part] {
			continue
		}
		seen[part] = true
		specs = append(specs, KeyIssueSpec{
			IssueAttr:    part,
			DisplayLabel: part,
			AuthName:     authNameFromClause(part),
		})
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("策略无有效属性")
	}
	return specs, nil
}

// PolicyVars 返回策略 LSSS 展开后的全部属性名。
func PolicyVars(policy string) []string {
	return mosaic.PolicyVars(NormalizePolicySyntax(policy))
}

// IssueAttributeExpansion 返回 issueAttr 签发时展开的属性名。
func IssueAttributeExpansion(issueAttr string) []string {
	return mosaic.IssueAttributeExpansion(issueAttr)
}

// Mosaic Policy.g4 中 AND/OR 优先级高于 ==，未加括号时
// hour@auth1 == 17 /\ locschool@auth1 会被解析成 hour@auth1 == (17 /\ locschool@auth1)。
func normalizeNumericPrecedence(policy string) string {
	policy = strings.TrimSpace(policy)
	if policy == "" {
		return policy
	}
	if isWrappedClause(policy) {
		inner := strings.TrimSpace(policy[1 : len(policy)-1])
		normalized := normalizeNumericPrecedence(inner)
		if normalized == inner {
			return policy
		}
		return "(" + normalized + ")"
	}
	parts, joins := splitAtTopLevelJoins(policy)
	if len(parts) <= 1 {
		return policy
	}
	changed := false
	for i, part := range parts {
		part = strings.TrimSpace(part)
		next := normalizeNumericPrecedence(part)
		if rePolicyNumericClause.MatchString(next) && !isWrappedClause(next) {
			next = "(" + next + ")"
			changed = true
		}
		if next != part {
			changed = true
		}
		parts[i] = next
	}
	if !changed {
		return policy
	}
	var b strings.Builder
	for i, part := range parts {
		if i > 0 {
			b.WriteString(" ")
			b.WriteString(joins[i-1])
			b.WriteString(" ")
		}
		b.WriteString(part)
	}
	return b.String()
}

func parsePolicyClauses(policy string) []policyClause {
	policy = strings.TrimSpace(policy)
	if policy == "" {
		return nil
	}
	var parts []string
	if err := splitPolicyParts(policy, &parts); err != nil {
		parts = []string{policy}
	}
	out := make([]policyClause, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		m := rePolicyNumericClause.FindStringSubmatch(part)
		if m == nil {
			out = append(out, policyClause{raw: part})
			continue
		}
		value, _ := strconv.Atoi(m[4])
		out = append(out, policyClause{
			raw: part, attr: m[1], op: m[3], value: value,
		})
	}
	return out
}

func policyLeafClauses(policy string) []string {
	var out []string
	var walk func(string)
	walk = func(p string) {
		p = strings.TrimSpace(p)
		for isWrappedClause(p) {
			p = strings.TrimSpace(p[1 : len(p)-1])
		}
		parts, _ := splitAtTopLevelJoins(p)
		if len(parts) > 1 {
			for _, part := range parts {
				walk(part)
			}
			return
		}
		if p != "" {
			out = append(out, p)
		}
	}
	walk(policy)
	return out
}

func flattenNestedAndGroups(policy string) string {
	policy = strings.TrimSpace(policy)
	if policy == "" {
		return policy
	}
	if isWrappedClause(policy) {
		inner := flattenNestedAndGroups(strings.TrimSpace(policy[1 : len(policy)-1]))
		if inner == strings.TrimSpace(policy[1:len(policy)-1]) {
			return policy
		}
		return "(" + inner + ")"
	}
	parts, joins := splitAtTopLevelJoins(policy)
	if len(parts) <= 1 {
		return policy
	}
	allAnd := len(joins) > 0
	for _, j := range joins {
		if j != "/\\" {
			allAnd = false
			break
		}
	}
	if allAnd {
		var flat []string
		var walk func(string)
		walk = func(part string) {
			part = strings.TrimSpace(part)
			for isWrappedClause(part) {
				inner := strings.TrimSpace(part[1 : len(part)-1])
				sub, subJoins := splitAtTopLevelJoins(inner)
				if len(sub) > 1 {
					subAllAnd := true
					for _, j := range subJoins {
						if j != "/\\" {
							subAllAnd = false
							break
						}
					}
					if subAllAnd {
						for _, sp := range sub {
							walk(sp)
						}
						return
					}
				}
				part = inner
			}
			if part != "" {
				flat = append(flat, part)
			}
		}
		for _, part := range parts {
			walk(part)
		}
		return joinPolicyParts(flat, "/\\")
	}
	changed := false
	for i, part := range parts {
		next := flattenNestedAndGroups(part)
		if next != part {
			changed = true
		}
		parts[i] = next
	}
	if !changed {
		return policy
	}
	return joinPolicyParts(parts, joins)
}

func joinPolicyParts(parts []string, joinOrJoins interface{}) string {
	var joins []string
	switch j := joinOrJoins.(type) {
	case string:
		joins = make([]string, len(parts)-1)
		for i := range joins {
			joins[i] = j
		}
	case []string:
		joins = j
	}
	var b strings.Builder
	for i, part := range parts {
		if i > 0 {
			b.WriteString(" ")
			b.WriteString(joins[i-1])
			b.WriteString(" ")
		}
		b.WriteString(part)
	}
	return b.String()
}

func validatePolicyComposition(clauses []policyClause) error {
	var numeric []policyClause
	for _, c := range clauses {
		if c.op != "" {
			numeric = append(numeric, c)
		}
	}
	if len(numeric) > 1 {
		return fmt.Errorf("策略只能包含一条数值比较（不可同时约束 hour 与自定义数值属性）")
	}
	return nil
}

func splitPolicyParts(policy string, out *[]string) error {
	policy = strings.TrimSpace(policy)
	if policy == "" {
		return nil
	}
	if !strings.HasPrefix(policy, "(") {
		*out = append(*out, policy)
		return nil
	}
	depth := 0
	start := 0
	for i, ch := range policy {
		switch ch {
		case '(':
			if depth == 0 {
				start = i + 1
			}
			depth++
		case ')':
			depth--
			if depth == 0 {
				inner := strings.TrimSpace(policy[start:i])
				return splitTopLevel(inner, out)
			}
		}
	}
	return fmt.Errorf("策略括号不匹配")
}

func splitTopLevel(policy string, out *[]string) error {
	depth := 0
	last := 0
	for i := 0; i < len(policy); i++ {
		switch policy[i] {
		case '(':
			depth++
		case ')':
			depth--
		default:
			if depth == 0 && i+2 <= len(policy) {
				if policy[i:i+2] == "/\\" || policy[i:i+2] == "\\/" {
					part := strings.TrimSpace(policy[last:i])
					if part != "" {
						if err := splitPolicyParts(part, out); err != nil {
							return err
						}
					}
					last = i + 2
					i++
				}
			}
		}
	}
	tail := strings.TrimSpace(policy[last:])
	if tail == "" {
		return nil
	}
	return splitPolicyParts(tail, out)
}

func isWrappedClause(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' {
		return false
	}
	depth := 0
	for i, ch := range s {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 && i != len(s)-1 {
				return false
			}
		}
	}
	return depth == 0
}

func splitAtTopLevelJoins(policy string) (parts []string, joins []string) {
	depth := 0
	last := 0
	for i := 0; i < len(policy); i++ {
		switch policy[i] {
		case '(':
			depth++
		case ')':
			depth--
		default:
			if depth == 0 && i+2 <= len(policy) {
				op := policy[i : i+2]
				if op == "/\\" || op == "\\/" {
					parts = append(parts, strings.TrimSpace(policy[last:i]))
					joins = append(joins, op)
					last = i + 2
					i++
				}
			}
		}
	}
	parts = append(parts, strings.TrimSpace(policy[last:]))
	return parts, joins
}

// PolicyMissingUserKeys 返回 userkey 中缺失的策略属性名。
func PolicyMissingUserKeys(policy string, userattrs *mosaic.UserAttrs) []string {
	policy = NormalizePolicySyntax(policy)
	if userattrs == nil || userattrs.Userkey == nil {
		return PolicyVars(policy)
	}
	var missing []string
	for _, attr := range PolicyVars(policy) {
		if shouldSkipNumericCompareVar(policy, attr, userattrs) {
			continue
		}
		if _, ok := userattrs.Userkey[attr]; !ok {
			missing = append(missing, attr)
		}
	}
	return missing
}

func shouldSkipNumericCompareVar(policy, attr string, userattrs *mosaic.UserAttrs) bool {
	i := strings.LastIndex(attr, "@")
	if i <= 0 {
		return false
	}
	auth := attr[i+1:]
	base := attr[:i]
	dash := strings.Index(base, "-")
	if dash <= 0 {
		return false
	}
	attrName := base[:dash]
	for _, part := range policyLeafClauses(policy) {
		nc, ok := ParseNumericClause(part)
		if !ok || nc.Op == "==" {
			continue
		}
		if strings.EqualFold(nc.Attr, attrName) && nc.Auth == auth {
			return userHasNumericBitKeys(userattrs, attrName, auth)
		}
	}
	return false
}

func userHasNumericBitKeys(userattrs *mosaic.UserAttrs, attrBase, auth string) bool {
	prefix := strings.ToLower(attrBase) + "-"
	suffix := "@" + auth
	n := 0
	for a := range userattrs.Userkey {
		low := strings.ToLower(a)
		if strings.HasPrefix(low, prefix) && strings.HasSuffix(low, suffix) {
			n++
		}
	}
	return n >= 32
}

var reBitAttrName = regexp.MustCompile(`(?i)^[a-zA-Z][a-zA-Z0-9_]*-\d+-\d+$`)

// NormalizeAttrName 统一 bit 属性名大小写（如 cry-31-1@auth0），布尔属性保持原样。
func NormalizeAttrName(attr string) string {
	i := strings.LastIndex(attr, "@")
	if i <= 0 {
		return attr
	}
	if !reBitAttrName.MatchString(attr[:i]) {
		return attr
	}
	return strings.ToLower(attr[:i]) + attr[i:]
}

// NormalizeCiphertext 对齐密文策略与 C 中属性名（兼容旧数据 Cry-* vs cry-*）。
func NormalizeCiphertext(ct *mosaic.Ciphertext) {
	if ct == nil {
		return
	}
	ct.Policy = NormalizePolicySyntax(ct.Policy)
	if len(ct.C) == 0 {
		return
	}
	newC := make(map[string][][]mosaic.Point, len(ct.C))
	for k, v := range ct.C {
		newC[NormalizeAttrName(k)] = v
	}
	ct.C = newC
}

// NormalizeUserAttrs 对齐 userkey / coeff 中的属性名。
func NormalizeUserAttrs(userattrs *mosaic.UserAttrs) {
	if userattrs == nil {
		return
	}
	if len(userattrs.Userkey) > 0 {
		uk := make(map[string]*mosaic.Userkey, len(userattrs.Userkey))
		for k, v := range userattrs.Userkey {
			uk[NormalizeAttrName(k)] = v
		}
		userattrs.Userkey = uk
	}
	if len(userattrs.Coeff) > 0 {
		cf := make(map[string][]int, len(userattrs.Coeff))
		for k, v := range userattrs.Coeff {
			cf[NormalizeAttrName(k)] = v
		}
		userattrs.Coeff = cf
	}
}

func normalizePolicyAttrCase(policy string) string {
	policy = strings.TrimSpace(policy)
	if policy == "" {
		return policy
	}
	if isWrappedClause(policy) {
		inner := normalizePolicyAttrCase(strings.TrimSpace(policy[1 : len(policy)-1]))
		if inner == strings.TrimSpace(policy[1:len(policy)-1]) {
			return policy
		}
		return "(" + inner + ")"
	}
	parts, joins := splitAtTopLevelJoins(policy)
	if len(parts) > 1 {
		for i, part := range parts {
			parts[i] = normalizePolicyAttrCase(part)
		}
		return joinPolicyParts(parts, joins)
	}
	if m := rePolicyNumericClause.FindStringSubmatch(policy); m != nil {
		return strings.ToLower(m[1]) + "@" + m[2] + " " + m[3] + " " + m[4]
	}
	return policy
}

func authNameFromClause(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "@"); i >= 0 {
		tail := strings.TrimSpace(raw[i+1:])
		if j := strings.IndexAny(tail, " \t"); j >= 0 {
			tail = tail[:j]
		}
		return tail
	}
	return ""
}
