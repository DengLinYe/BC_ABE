package abe

import "testing"

func TestPolicyVarsMatchMatrixRows(t *testing.T) {
	policy := "(hour@auth1 == 16) /\\ (Vitality@auth1 /\\ locschool@auth1)"
	ln := parsePolicy(policy, 0)
	ap := buildAccessPolicy(policy)
	if len(ln.vars) != len(ap.M) {
		t.Fatalf("vars=%d matrix rows=%d", len(ln.vars), len(ap.M))
	}
	for i, v := range ln.vars {
		rows := ap.Row[v]
		found := false
		for _, r := range rows {
			if r == i {
				found = true
			}
		}
		if !found {
			t.Fatalf("var[%d]=%s not mapped to row %d, rows=%v", i, v, i, ap.Row[v])
		}
	}
}

func TestLeafOrderMatchesVars(t *testing.T) {
	policy := "(hour@auth1 == 16) /\\ (Vitality@auth1 /\\ locschool@auth1)"
	ln := parsePolicy(policy, 0)
	leaves := leafLabels(ln.s[0])
	if len(leaves) != len(ln.vars) {
		t.Fatalf("leaves=%d vars=%d", len(leaves), len(ln.vars))
	}
	for i := range leaves {
		if leaves[i] != ln.vars[i] {
			t.Fatalf("at %d leaf=%q var=%q", i, leaves[i], ln.vars[i])
		}
	}
}

func leafLabels(t *btree) []string {
	if t == nil {
		return nil
	}
	if t.child[0] == nil || t.child[1] == nil {
		return []string{t.label}
	}
	out := leafLabels(t.child[0])
	return append(out, leafLabels(t.child[1])...)
}
