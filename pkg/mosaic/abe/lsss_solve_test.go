package abe

import "testing"

func TestComputeCoefficients_AllRowsUserPolicy(t *testing.T) {
	policy := "((hour@auth1 == 16) \\/ (Vitality@auth1 /\\ locschool@auth1))"
	ap := buildAccessPolicy(policy)
	c := computeCoefficients(ap.M)
	t.Logf("coeffs len=%d nonzero=%d match=%v", len(c), countNonzero(c), linCombMatches(c, ap.M))
	if !linCombMatches(c, ap.M) {
		c2, ok := computeCoefficientsSolve(ap.M)
		t.Logf("solve ok=%v nonzero=%d match=%v", ok, countNonzero(c2), ok && linCombMatches(c2, ap.M))
	}
}

func countNonzero(c []int) int {
	n := 0
	for _, v := range c {
		if v != 0 {
			n++
		}
	}
	return n
}
