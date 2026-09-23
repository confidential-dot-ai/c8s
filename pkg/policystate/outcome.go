package policystate

// Outcome is a verifier's decision about a deployment's advertised bound,
// relative to the policies that verifier has accepted.
type Outcome string

// Verifier outcomes.
const (
	// OutcomeProceed means every policy in the bound is accepted.
	OutcomeProceed Outcome = "PROCEED"
	// OutcomeRefused means at least one is not: a client that pinned only the
	// source refuses the source-or-target bound an update advertises, and
	// waits for the drain that narrows it.
	OutcomeRefused Outcome = "REFUSED"
)

// Evaluate decides whether a bound is covered by what the verifier accepted.
// accepted answers for one policy digest. An empty bound is refused: a state
// always names at least one policy, so an empty one is a bug, not a vacuous
// approval.
func Evaluate(bound []string, accepted func(digest string) bool) Outcome {
	if len(bound) == 0 {
		return OutcomeRefused
	}
	for _, digest := range bound {
		if !accepted(digest) {
			return OutcomeRefused
		}
	}
	return OutcomeProceed
}
