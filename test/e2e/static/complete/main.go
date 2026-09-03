// Command complete finishes the sealed allowlist the static e2e lane renders.
// `c8s allowlist render --sealed` leaves every review empty and pins each
// system-floor image to the argv its image config bakes with no env and no
// mounts, because only a reviewer who observed the node can say more. The
// lane's reviewer is the checked-in test/e2e/static/reviews.json: this
// command applies it, drops the floor images the node never runs, and
// prints the canonical document once it passes the same LintSealed a node
// runs at boot. A floor entry the reviews file leaves without env and
// mounts fails that lint: a sealed document has no open policy, privileged
// or not, so the floor must be completed from a dynamic node's observation
// (the sealed plugin's deny log prints one per refused container).
//
//	go run ./test/e2e/static/complete -reviews reviews.json rendered.json > static-allowlist.json
//
// Every name in the reviews file must exist in the document and every floor
// entry in the document must be reviewed or dropped, so an RKE2 or chart
// bump fails here, on the runner, rather than as a node that never converges.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// floorPrefix is what pkg/allowlist SystemFloor.Workloads names its entries.
const floorPrefix = "system-"

// Reviews is the reviewer's completion of a rendered document.
type Reviews struct {
	// Entries carries review strings for chart and workload entries, keyed
	// by entry name.
	Entries map[string]EntryReview `json:"entries"`
	// Floor completes system-floor entries as node TCB, keyed by entry name.
	Floor map[string]FloorReview `json:"floor"`
	// Drop lists floor entries that get no rule: the sealed node denies them.
	Drop []string `json:"drop"`
}

// EntryReview fills the review slots of one entry. Privileges goes to every
// container that carries a privileges block; Mounts goes to every container
// whose rule at that destination is a pvc, serviceAccountToken or nodeState
// bind.
type EntryReview struct {
	Privileges string            `json:"privileges,omitempty"`
	Mounts     map[string]string `json:"mounts,omitempty"`
}

// FloorReview completes a floor entry from the reviewer's observation of a
// dynamic node: the reviewed privileges block, the env values and mount
// rules the skeleton left empty, and, when the static pod manifest overrides
// the image config, the argv. Command and Args unset keep the image-config
// pin; Env and Mounts unset leave the entry open, which the lint refuses.
type FloorReview struct {
	Privileges allowlist.Privileges           `json:"privileges"`
	Command    []string                       `json:"command,omitempty"`
	Args       []string                       `json:"args,omitempty"`
	Env        map[string]allowlist.EnvValue  `json:"env,omitempty"`
	Mounts     map[string]allowlist.MountRule `json:"mounts,omitempty"`
}

func main() {
	reviewsPath := flag.String("reviews", "", "reviews file (required)")
	flag.Parse()
	if *reviewsPath == "" || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: complete -reviews FILE <rendered.json|->")
		os.Exit(2)
	}
	if err := run(*reviewsPath, flag.Arg(0), os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "complete:", err)
		os.Exit(1)
	}
}

func run(reviewsPath, docPath string, out io.Writer) error {
	reviews, err := loadReviews(reviewsPath)
	if err != nil {
		return err
	}
	var doc []byte
	if docPath == "-" {
		doc, err = io.ReadAll(os.Stdin)
	} else {
		doc, err = os.ReadFile(docPath)
	}
	if err != nil {
		return err
	}
	completed, err := complete(doc, reviews)
	if err != nil {
		return err
	}
	_, err = out.Write(completed)
	return err
}

func loadReviews(path string) (Reviews, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Reviews{}, err
	}
	var r Reviews
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Reviews{}, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

// complete applies reviews to doc and returns the canonical bytes of a
// document LintSealed accepts. Names the reviews file mentions must exist,
// and every floor entry must be reviewed or dropped.
func complete(doc []byte, r Reviews) ([]byte, error) {
	al, err := allowlist.ParseJSON(doc)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, name := range r.Drop {
		if _, ok := al.Workloads[name]; !ok {
			errs = append(errs, fmt.Errorf("drop: entry %q is not in the document", name))
			continue
		}
		delete(al.Workloads, name)
	}
	for name, fr := range r.Floor {
		w, ok := al.Workloads[name]
		if !ok {
			errs = append(errs, fmt.Errorf("floor: entry %q is not in the document", name))
			continue
		}
		if len(fr.Command) == 0 && len(fr.Args) != 0 {
			errs = append(errs, fmt.Errorf("floor: entry %q: args without command; an observed argv is given as command plus args", name))
			continue
		}
		for _, list := range [][]allowlist.Container{w.InitContainers, w.Containers} {
			for i := range list {
				priv := fr.Privileges
				list[i].Privileges = &priv
				if len(fr.Command) != 0 {
					list[i].Command, list[i].Args = allowlist.ArgvRule(fr.Command), allowlist.ArgvRule(fr.Args)
				}
				list[i].Env = allowlist.EnvRules(fr.Env)
				list[i].Mounts = allowlist.MountRules(fr.Mounts)
			}
		}
	}
	for name, er := range r.Entries {
		w, ok := al.Workloads[name]
		if !ok {
			errs = append(errs, fmt.Errorf("entries: entry %q is not in the document", name))
			continue
		}
		errs = append(errs, applyEntryReview(name, w, er)...)
	}
	for name := range al.Workloads {
		if !strings.HasPrefix(name, floorPrefix) {
			continue
		}
		if _, ok := r.Floor[name]; ok || slices.Contains(r.Drop, name) {
			continue
		}
		errs = append(errs, fmt.Errorf("floor entry %q is neither reviewed under \"floor\" nor listed under \"drop\"; the RKE2 pin moved, refresh the reviews file", name))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return canonicalize(al)
}

// canonicalize round-trips the edited document through ParseJSON so the
// reviewed lists come out normalized (sorted, deduplicated) the way any
// reader of the bytes would write them; LintSealed then holds the bytes to
// that form.
func canonicalize(al *allowlist.Allowlist) ([]byte, error) {
	edited, err := al.Canonical()
	if err != nil {
		return nil, err
	}
	normalized, err := allowlist.ParseJSON(edited)
	if err != nil {
		return nil, err
	}
	canonical, err := normalized.Canonical()
	if err != nil {
		return nil, err
	}
	if err := allowlist.LintSealed(canonical); err != nil {
		return nil, err
	}
	return canonical, nil
}

// applyEntryReview writes the entry's review strings and reports a review
// with no slot to land in, which means the chart no longer needs it.
func applyEntryReview(name string, w allowlist.Workload, er EntryReview) []error {
	var errs []error
	containers := slices.Concat(w.InitContainers, w.Containers)
	if er.Privileges != "" {
		hit := false
		for _, c := range containers {
			if c.Privileges != nil {
				c.Privileges.Review = er.Privileges
				hit = true
			}
		}
		if !hit {
			errs = append(errs, fmt.Errorf("entries: %q carries a privileges review but no container has a privileges block", name))
		}
	}
	for dest, review := range er.Mounts {
		hit := false
		for _, c := range containers {
			rule, ok := c.Mounts.Rules[dest]
			if !ok || !reviewedMount(rule.Source) {
				continue
			}
			rule.Review = review
			c.Mounts.Rules[dest] = rule
			hit = true
		}
		if !hit {
			errs = append(errs, fmt.Errorf("entries: %q reviews mount %q but no container binds a pvc, serviceAccountToken or nodeState source there", name, dest))
		}
	}
	return errs
}

// reviewedMount reports the source classes whose rule carries a review.
func reviewedMount(source string) bool {
	switch source {
	case allowlist.SourcePVC, allowlist.SourceServiceAccountToken, allowlist.SourceNodeState:
		return true
	}
	return false
}
