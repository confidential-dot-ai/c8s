package verify

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/policystate"
)

// statePolicy is one run's accepted-policy configuration for the dynamic
// allowlist: which policies the operator has reviewed, which authority may
// sign for the deployment, and how hard to insist the statement is current.
//
// Reviewed pins and observed history are deliberately separate: advancing the
// checkpoint records that a change happened, never that it was approved.
type statePolicy struct {
	// pins are the accepted policy digests. Empty with follow false means no
	// policy was selected: the state is reported, not judged.
	pins map[string]bool
	// follow delegates the decision to the authenticated deployment.
	follow bool
	// authority is --authority, "" when the fingerprint is to be taken from
	// the checkpoint or learned over the attested channel.
	authority string
	// fresh runs the CDS challenge against the bound statement.
	fresh bool
	// checkpoint is the --state-checkpoint path, "" when unset.
	checkpoint string
}

// selected reports whether the operator asked for anything only the state
// binding can deliver. It is what separates "this target binds no state" from
// "the check you asked for could not run": the first leaves an unasked verdict
// standing with a note, the second fails.
func (p *statePolicy) selected() bool {
	return p.follow || len(p.pins) > 0 || p.checkpoint != "" || p.authority != ""
}

// buildStatePolicy parses the state flags. It runs inside buildPolicy, so a
// contradictory selection is a usage error before anything is dialed.
func buildStatePolicy(cfg config) (*statePolicy, error) {
	pins, err := loadAllowlistPins(cfg.allowlistPins)
	if err != nil {
		return nil, err
	}
	// Following the deployment and pinning reviewed policies are opposite
	// policies, and merging them would silently follow: an unpinned digest
	// would still pass.
	if cfg.follow && len(pins) > 0 {
		return nil, fmt.Errorf("--follow cannot be combined with --allowlist-pin: --follow accepts whatever the deployment publishes, which makes the pins unenforceable")
	}
	authority := strings.TrimSpace(cfg.authority)
	if authority != "" {
		if _, err := policystate.ParseHash(authority); err != nil {
			return nil, fmt.Errorf("--authority: %w", err)
		}
	}
	return &statePolicy{
		pins:       pins,
		follow:     cfg.follow,
		authority:  authority,
		fresh:      cfg.freshState,
		checkpoint: cfg.stateCheckpoint,
	}, nil
}

// loadAllowlistPins reads --allowlist-pin into a set of policy digests.
func loadAllowlistPins(flags []string) (map[string]bool, error) {
	pins := make(map[string]bool)
	for _, digest := range flags {
		if digest = strings.TrimSpace(digest); digest == "" {
			continue
		}
		if _, err := policystate.ParseHash(digest); err != nil {
			return nil, fmt.Errorf("--allowlist-pin: %w", err)
		}
		pins[digest] = true
	}
	return pins, nil
}

// StateSummary is the policy state the responder bound, as the verdict reports
// it. Every field is read off the statement whose CDS signature was verified;
// the notes say what each check concluded.
type StateSummary struct {
	DeploymentID  string `json:"deployment_id"`
	Authority     string `json:"authority"`
	LogHead       string `json:"log_head"`
	LogPosition   uint64 `json:"log_position"`
	ActiveVersion uint64 `json:"active_version"`
	ActiveDigest  string `json:"active_digest"`
	// Envelope is the policy set this session may operate under: the bound of
	// the statement above, which the transcript committed.
	Envelope []string `json:"envelope"`
	// UpdateVersion and UpdateTarget name the outstanding update, if any.
	UpdateVersion uint64 `json:"update_version,omitempty"`
	UpdateTarget  string `json:"update_target,omitempty"`
	UpdateNote    string `json:"update_note,omitempty"`
	// Route is the workload the responder committed as this session's
	// destination, empty when it forwards to none.
	Route string `json:"route,omitempty"`
	// AuthorityTrust says what authenticated the signing authority.
	AuthorityTrust string `json:"authority_trust"`
	// Freshness says whether the statement was proven current.
	Freshness string `json:"freshness"`
	// Outcome is PROCEED or REFUSED, empty when no policy was selected.
	Outcome string `json:"outcome,omitempty"`
	// OutcomeNote explains the outcome in operator terms.
	OutcomeNote string `json:"outcome_note,omitempty"`
	// Continuity reports the --state-checkpoint history walk.
	Continuity string `json:"continuity,omitempty"`
}

// applyStatePolicy settles what the verdict may claim about the policy state
// the attestation committed: the CDS signature on the statement, which
// authority is trusted to have made it, its freshness against a challenge the
// verifier nonces, the accepted-policy table, and continuity with the stored
// checkpoint.
//
// Like every other post-verification policy it can only demote. How hard it
// demotes depends on what was asked for: a target that binds no state leaves
// an unasked verdict standing with a note, while a check the operator selected
// and that could not run is a failure.
func applyStatePolicy(ctx context.Context, oc *Outcome, cfg config, plan *verifyPlan, ev *evidence) {
	// A verdict that already failed is not improved by dialing CDS: the
	// hardware evidence or a pinned policy check has decided it, and a second
	// reason would only bury the first.
	if oc.Error != "" {
		return
	}
	policy := plan.state
	if policy == nil {
		policy = &statePolicy{}
	}
	if ev.state == nil {
		// Only say something when the binding was asked for. A certificate or
		// discovery target binds no state, and a line about it on every such
		// verdict would be noise, not information.
		if ev.stateNote == "" && !policy.selected() {
			return
		}
		oc.StateBindingNote = orDefault(ev.stateNote, "policy state: not bound by this evidence source")
		if policy.selected() {
			failVerdict(oc, "policy state unavailable: %s", oc.StateBindingNote)
		}
		return
	}
	oc.StateBinding = ev.bindingVersion

	// A demotion that is not a failure still has to be visible: the evidence
	// presented a policy state this run could not stand behind.
	fail := func(format string, args ...any) {
		reason := fmt.Sprintf(format, args...)
		switch {
		case policy.selected():
			failVerdict(oc, "%s", reason)
		case oc.Partial:
			// Already demoted by another policy: demoteToPartial would drop
			// this reason, and a verdict must name every unproven property.
			oc.NotProven = append(oc.NotProven, reason)
		default:
			demoteToPartial(oc, reason)
		}
	}

	statement := ev.state.signed.Statement
	channel, channelErr := newStateChannel(cfg, ev)
	trust, err := authorityTrust(ctx, policy, statement, channel, channelErr)
	if err != nil {
		fail("the deployment's signing authority: %v", err)
		return
	}

	summary := &StateSummary{
		DeploymentID:   statement.DeploymentID,
		Authority:      statement.Authority,
		LogHead:        statement.LogHead,
		LogPosition:    statement.LogPosition,
		ActiveVersion:  statement.ActiveVersion,
		ActiveDigest:   statement.ActiveDigest,
		Envelope:       ev.state.envelope,
		Route:          ev.route,
		AuthorityTrust: trust,
		Freshness:      "not checked (--fresh-state=false)",
	}
	if u := statement.Update; u != nil {
		summary.UpdateVersion, summary.UpdateTarget = u.Version, u.TargetDigest
		summary.UpdateNote = updateNote(*u)
	}
	oc.State = summary

	if policy.fresh {
		note, err := checkStateFreshness(ctx, statement, channel, channelErr)
		summary.Freshness = note
		if err != nil {
			fail("the bound policy state is not proven current: %v", err)
			return
		}
	}
	applyPolicyOutcome(oc, policy, summary, ev.state.envelope)
	applyCheckpoint(ctx, oc, policy, summary, statement, channel, channelErr)
}

// updateNote says what an outstanding update means for the advertised bound.
func updateNote(u policystate.Update) string {
	if u.RequiresDrain {
		if u.Switched {
			return "the target is in force; the source's removed permissions are still draining, so the bound covers both"
		}
		return "published, not yet switched; the bound covers both policies until the drain completes"
	}
	return "the target adds permissions and removes none, so the bound is the target alone"
}

// failVerdict fails the verdict, keeping the first reason: a later check
// reporting on state the first one already rejected would bury it.
func failVerdict(oc *Outcome, format string, args ...any) {
	oc.Verified = false
	oc.Partial = false
	if oc.Error == "" {
		oc.Error = fmt.Sprintf(format, args...)
	}
}

// authorityTrust decides whether the authority that signed the statement may
// speak for this deployment, and says what made that decision.
//
// The statement authenticates itself under the key it carries, so the only
// question here is whose key that may be: the operator's pin, the authority a
// previous run recorded in its checkpoint, or — failing both — the fingerprint
// CDS serves over the connection bound to the attested certificate, trusted
// for this run only.
func authorityTrust(ctx context.Context, policy *statePolicy, statement policystate.State, channel *stateChannel, channelErr error) (string, error) {
	if policy.authority != "" {
		if statement.Authority != policy.authority {
			return "", fmt.Errorf("the statement is signed by %s, and --authority pins %s", statement.Authority, policy.authority)
		}
		return "pinned by --authority", nil
	}
	if pinned, err := checkpointAuthority(policy.checkpoint); err != nil {
		return "", err
	} else if pinned != "" {
		if statement.Authority != pinned {
			return "", fmt.Errorf("authority changed: the checkpoint records %s and the statement is signed by %s; re-anchor", pinned, statement.Authority)
		}
		return "pinned by the state checkpoint", nil
	}
	if channelErr != nil {
		return "", fmt.Errorf("no channel to learn the authority over: %w — pass --authority to pin it instead", channelErr)
	}
	if !channel.bound {
		return "", fmt.Errorf("the authority can only be learned over a connection bound to the attested certificate, and this evidence source attests none — pass --authority to pin it instead")
	}
	served, err := channel.client.State(ctx)
	if err != nil {
		return "", fmt.Errorf("fetch the deployment's state: %w", err)
	}
	if err := policystate.VerifySignedState(served); err != nil {
		return "", fmt.Errorf("the deployment's own state statement does not verify: %w", err)
	}
	if served.Statement.Authority != statement.Authority {
		return "", fmt.Errorf("the responder bound a statement signed by %s, and the deployment signs with %s", statement.Authority, served.Statement.Authority)
	}
	return "learned over the connection bound to the attested certificate (trust on first use for this run; pin it with --authority or a checkpoint)", nil
}

// checkStateFreshness makes CDS sign this verifier's nonce and requires the
// answer to name the same authority and a log position no older than the one
// the responder bound. Binding H(S) proves which statement the responder used,
// never that it is current; only this exchange does.
//
// The answer may be ahead: an enrollment or an acknowledgement moves the head
// without changing what the session may reach, and the session's envelope is
// what governs that. One retry absorbs a challenge that raced a CDS write; a
// position that went backwards, or an authority that changed under the run,
// fails as state_race.
func checkStateFreshness(ctx context.Context, bound policystate.State, channel *stateChannel, channelErr error) (string, error) {
	if channelErr != nil {
		return "not proven", fmt.Errorf("no channel to challenge CDS over: %w", channelErr)
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		nonce := make([]byte, stateNonceBytes)
		if _, err := rand.Read(nonce); err != nil {
			return "not proven", fmt.Errorf("generate challenge nonce: %w", err)
		}
		challenged, err := channel.client.Challenge(ctx, nonce)
		if err != nil {
			lastErr = err
			continue
		}
		if err := policystate.VerifyChallengedState(challenged, nonce); err != nil {
			// A wrong nonce or a broken signature is not a race: retrying
			// would only ask the same liar twice.
			return "not proven", err
		}
		current := challenged.Statement
		if current.Authority == bound.Authority && current.LogPosition >= bound.LogPosition {
			return fmt.Sprintf("proven current by a nonce-bound CDS challenge (log position %d)", current.LogPosition), nil
		}
		lastErr = fmt.Errorf("state_race: CDS answers for authority %s at log position %d, the responder bound authority %s at position %d; re-run",
			current.Authority, current.LogPosition, bound.Authority, bound.LogPosition)
	}
	return "not proven", lastErr
}

// applyPolicyOutcome evaluates the session's envelope against the accepted
// policies. REFUSED is a failure: the session may operate under a policy this
// run has not approved, which is exactly what the pins exist to prevent.
func applyPolicyOutcome(oc *Outcome, policy *statePolicy, summary *StateSummary, envelope []string) {
	if !policy.follow && len(policy.pins) == 0 {
		summary.OutcomeNote = "no policy selected: the state is reported, not judged (pass --allowlist-pin or --follow)"
		return
	}
	if policy.follow {
		summary.Outcome = string(policystate.OutcomeProceed)
		summary.OutcomeNote = "--follow: the authenticated deployment's own policy is accepted, so this verdict claims no reviewed bound"
		return
	}
	outcome := policystate.Evaluate(envelope, func(digest string) bool { return policy.pins[digest] })
	summary.Outcome = string(outcome)
	if outcome == policystate.OutcomeProceed {
		summary.OutcomeNote = "every policy this session may operate under is pinned"
		return
	}
	var unapproved []string
	for _, digest := range envelope {
		if !policy.pins[digest] {
			unapproved = append(unapproved, digest)
		}
	}
	summary.OutcomeNote = fmt.Sprintf("this session may operate under %s, which %s not pinned",
		strings.Join(unapproved, ", "), plural(len(unapproved), "is", "are"))
	failVerdict(oc, "REFUSED: %s — review and pin it, wait for the deployment to drain back to a policy you pinned, or use --follow to delegate the decision", summary.OutcomeNote)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// renderState prints the policy-state section of a text verdict: what the
// responder bound, what authenticated it, and what this run concluded about
// it. Nothing prints when no state was bound and nothing was asked for.
func renderState(oc Outcome, out io.Writer) {
	if oc.State == nil {
		if oc.StateBindingNote != "" {
			fmt.Fprintf(out, "  policy state: %s\n", oc.StateBindingNote)
		}
		return
	}
	s := oc.State
	fmt.Fprintf(out, "  policy state: %s  deployment %s\n", oc.StateBinding, s.DeploymentID)
	fmt.Fprintf(out, "                authority %s (%s)\n", s.Authority, s.AuthorityTrust)
	fmt.Fprintf(out, "                log head %s at position %d\n", s.LogHead, s.LogPosition)
	fmt.Fprintf(out, "                active version %d, policy %s\n", s.ActiveVersion, s.ActiveDigest)
	if s.UpdateVersion != 0 {
		fmt.Fprintf(out, "                update %d to %s: %s\n", s.UpdateVersion, s.UpdateTarget, s.UpdateNote)
	}
	fmt.Fprintf(out, "                session envelope: %s\n", strings.Join(slices.Clone(s.Envelope), ", "))
	if s.Route != "" {
		fmt.Fprintf(out, "                route: %s\n", s.Route)
	}
	fmt.Fprintf(out, "                freshness: %s\n", s.Freshness)
	if s.Outcome != "" {
		fmt.Fprintf(out, "                outcome: %s — %s\n", s.Outcome, s.OutcomeNote)
	} else if s.OutcomeNote != "" {
		fmt.Fprintf(out, "                outcome: %s\n", s.OutcomeNote)
	}
	if s.Continuity != "" {
		fmt.Fprintf(out, "                continuity: %s\n", s.Continuity)
	}
}
