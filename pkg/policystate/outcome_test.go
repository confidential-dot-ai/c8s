package policystate

import "testing"

func TestEvaluate(t *testing.T) {
	source, target := digestOf('b'), digestOf('d')
	pinned := func(accepted ...string) func(string) bool {
		return func(digest string) bool {
			for _, a := range accepted {
				if a == digest {
					return true
				}
			}
			return false
		}
	}
	tests := []struct {
		name     string
		bound    []string
		accepted func(string) bool
		want     Outcome
	}{
		{"the active policy is pinned", []string{source}, pinned(source), OutcomeProceed},
		{"both policies of an update are pinned", []string{source, target}, pinned(source, target), OutcomeProceed},
		{"only the source is pinned", []string{source, target}, pinned(source), OutcomeRefused},
		{"only the target is pinned", []string{source, target}, pinned(target), OutcomeRefused},
		{"an unreviewed policy", []string{target}, pinned(source), OutcomeRefused},
		{"following the deployment", []string{source, target}, func(string) bool { return true }, OutcomeProceed},
		{"an empty bound", nil, func(string) bool { return true }, OutcomeRefused},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Evaluate(tc.bound, tc.accepted); got != tc.want {
				t.Errorf("Evaluate(%v, accepted) = %s, want %s", tc.bound, got, tc.want)
			}
		})
	}
}
