//go:build !c8s_node

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/distribution/reference"
	"github.com/spf13/cobra"
	corev1 "k8s.io/api/core/v1"

	"github.com/confidential-dot-ai/c8s/internal/cmds/getkubeconfig"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/measurements"
	"github.com/confidential-dot-ai/c8s/pkg/policybundle"
	"github.com/confidential-dot-ai/c8s/pkg/runtimemeasure"
)

var (
	installStaticAllowlist string
	installImageManifest   string
)

// staticInstall is what --static-allowlist resolves to, loaded once per run:
// the bundle the nodes booted with, its sealed document, and the image tuple
// the static entry pins beside the bundle's register.
type staticInstall struct {
	bundle    policybundle.Bundle
	allowlist *pkgallowlist.Allowlist
	pins      runtimemeasure.ImagePins
	// measurementsFile holds the rendered static entry; helm and the values
	// tree take it through --set-file, so it lives on disk until the run
	// ends.
	measurementsFile string
}

// staticState is the run's loaded --static-allowlist, nil when the flag is
// unset. Shared the way the install flags are: the value builder and the
// preflights all read it.
var staticState *staticInstall

// staticNodeVerifier attests one node and requires the static tuple. A var so
// tests replace the network round trip.
var staticNodeVerifier = getkubeconfig.VerifyStaticNode

// staticNodeTimeout bounds each node's attest round trip.
const staticNodeTimeout = 30 * time.Second

// staticInstallPreflight validates the --static-allowlist flag set and loads
// the bundle and manifest before anything touches a cluster or a registry.
// Every pin and digest of a static install comes from the bundle, so the
// flags that supply them by other means are refused rather than merged.
func staticInstallPreflight(cmd *cobra.Command) error {
	if installStaticAllowlist == "" {
		return nil
	}
	if installImageManifest == "" {
		return fmt.Errorf("--static-allowlist requires --image-manifest: the static entry pins the image tuple (MRTD, RTMR[1], RTMR[2]) beside the bundle's RTMR[3], and the bundle alone names no image")
	}
	if installCvmMode != "node" || installHardwarePlatform != "tdx" {
		return fmt.Errorf("--static-allowlist requires --%s=node and --%s=tdx (got %q and %q): the policy bundle is measured into RTMR[3] by the node image, which only a TDX node-as-CVM has", flagCvmMode, flagHardwarePlatform, installCvmMode, installHardwarePlatform)
	}
	var refused []string
	if installOperatorKeys != "" {
		refused = append(refused, "--operator-keys")
	}
	if cmd.Flags().Changed("resolve-digests") && installResolveDigests {
		refused = append(refused, "--resolve-digests=true")
	}
	if len(installMeasurements) > 0 {
		refused = append(refused, "--measurements")
	}
	if installMeasurementsConfig != "" {
		refused = append(refused, "--measurements-config")
	}
	if len(installRTMRs) > 0 {
		refused = append(refused, "--rtmrs")
	}
	if len(refused) > 0 {
		return fmt.Errorf("--static-allowlist cannot be combined with %s: the bundle supplies every component digest and the measurements entry, and a static node takes no operator writes", strings.Join(refused, ", "))
	}
	// Digests come from the bundle, never a registry: what the node admits is
	// what the bundle names, and a freshly resolved tag would be denied.
	installResolveDigests = false

	s, err := loadStaticInstall(installStaticAllowlist, installImageManifest)
	if err != nil {
		return err
	}
	staticState = s
	return nil
}

// loadStaticInstall reads the manifest and the bundle, lints the member as a
// node would, and renders the static entry the chart carries as
// cds.measurementsConfig.
func loadStaticInstall(bundlePath, manifestPath string) (*staticInstall, error) {
	pins, err := runtimemeasure.LoadImageManifest(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("--image-manifest: %w", err)
	}
	bundle, err := policybundle.Load(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("--static-allowlist: %w", err)
	}
	member := bundle.Members[policybundle.MemberStaticAllowlist]
	if err := pkgallowlist.LintSealed(member); err != nil {
		return nil, fmt.Errorf("--static-allowlist %s: %w", policybundle.MemberStaticAllowlist, err)
	}
	al, err := pkgallowlist.ParseJSON(member)
	if err != nil {
		return nil, fmt.Errorf("--static-allowlist %s: %w", policybundle.MemberStaticAllowlist, err)
	}
	doc, err := measurements.Format(measurements.StaticReferenceValues(pins, bundle.RTMR3()))
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp("", "c8s-static-measurements-*.json")
	if err != nil {
		return nil, fmt.Errorf("write static measurements config: %w", err)
	}
	if _, err := f.Write(doc); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, fmt.Errorf("write static measurements config: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return nil, fmt.Errorf("write static measurements config: %w", err)
	}
	return &staticInstall{bundle: bundle, allowlist: al, pins: pins, measurementsFile: f.Name()}, nil
}

// cleanupStaticInstall removes the run's rendered measurements file.
func cleanupStaticInstall() {
	if staticState == nil {
		return
	}
	os.Remove(staticState.measurementsFile)
	staticState = nil
}

// pinArgs is installPins' static arm: the whole-image consumers (CDS itself,
// ratls-mesh, tls-lb) get the file with all four registers; the flat lists
// carry the image tuple only. RTMR[3] cannot go into them: flat pins land in
// container argv, that argv is in the bundle, and the register is derived
// from the bundle, so pinning it there would make the bundle depend on its
// own digest. The injected sidecars take no flat pins at all under a static
// allowlist: the operator gets --static-allowlist and each sidecar pins CDS
// to the tuple of its own quote (--cds-pins-from-own-quote), RTMR[3]
// included.
func (s *staticInstall) pinArgs() (digests [][]byte, rtmrs map[int][]byte, helmArgs []string) {
	return [][]byte{slices.Clone(s.pins.MRTD[:])},
		map[int][]byte{1: slices.Clone(s.pins.RTMR1[:]), 2: slices.Clone(s.pins.RTMR2[:])},
		[]string{
			"--set-file", "cds.measurementsConfig=" + s.measurementsFile,
			"--set-file", "ratlsMesh.measurementsConfig=" + s.measurementsFile,
		}
}

// appendStaticDigestArgs is the digestResolver of a static install: the chart
// values that switch static mode on, and each rendered component pinned to
// the digest the bundle names for its repository.
func appendStaticDigestArgs(ctx context.Context, chartPath string, setArgs []string, _ string, components []c8sComponent) ([]string, error) {
	// The mode values go in first: the enabled predicate below must see the
	// chart plugin off, or it would demand the plugin image from the bundle.
	setArgs = staticModeArgs(setArgs)
	enabled, err := componentEnabledPredicate(ctx, chartPath, setArgs)
	if err != nil {
		return nil, err
	}
	return staticDigestArgs(setArgs, components, staticState.allowlist, enabled)
}

// staticModeArgs are the chart values that switch static mode on.
func staticModeArgs(setArgs []string) []string {
	return append(setArgs,
		"--set", "staticAllowlist.enabled=true",
		"--set", "nriImagePolicy.enabled=false",
		"--set", "cds.persistence.enabled=false",
	)
}

// staticDigestArgs pins each rendered component to the digest the bundle
// names for its repository.
func staticDigestArgs(setArgs []string, components []c8sComponent, al *pkgallowlist.Allowlist, enabled func(valuePath string) (bool, error)) ([]string, error) {
	for _, c := range components {
		if c.enabledPath != "" {
			on, err := enabled(c.enabledPath)
			if err != nil {
				return nil, fmt.Errorf("component %s: resolve %s: %w", c.valuePrefix, c.enabledPath, err)
			}
			if !on {
				continue
			}
		}
		digest, err := bundleComponentDigest(al, c.repository)
		if err != nil {
			return nil, fmt.Errorf("component %s: %w", c.valuePrefix, err)
		}
		setArgs = append(setArgs,
			"--set-string", c.valuePrefix+".repository="+c.repository,
			"--set-string", c.valuePrefix+".digest="+digest,
		)
	}
	return setArgs, nil
}

// bundleComponentDigest returns the one digest the bundle names for
// repository. A component the bundle does not name would be denied on its own
// node, and two digests for one repository leave no way to pick.
func bundleComponentDigest(al *pkgallowlist.Allowlist, repository string) (string, error) {
	want, err := reference.ParseDockerRef(repository)
	if err != nil {
		return "", fmt.Errorf("repository %q: %w", repository, err)
	}
	repo := reference.TrimNamed(want).String()
	digests := map[string]bool{}
	for _, w := range al.Workloads {
		for _, c := range slices.Concat(w.InitContainers, w.Containers) {
			if c.Image == "" {
				continue
			}
			named, err := reference.ParseDockerRef(c.Image)
			if err != nil || reference.TrimNamed(named).String() != repo {
				continue
			}
			digests[c.Digest.String()] = true
		}
	}
	switch len(digests) {
	case 0:
		return "", fmt.Errorf("no entry in the bundle names image %s; the node would deny it — render the bundle with `c8s allowlist render --sealed --chart-values <values>` for this release", repo)
	case 1:
		for d := range digests {
			return d, nil
		}
	}
	return "", fmt.Errorf("the bundle names %d digests for image %s (%s); the chart can pin only one", len(digests), repo, strings.Join(slices.Sorted(maps.Keys(digests)), ", "))
}

// preflightStaticNodes attests every node through its attestation-api and
// requires the static tuple: the register a node sealed to this bundle
// reports. A node still in dynamic mode, or sealed to another bundle,
// fails the install before the chart renders. The containers a node runs
// are not visible through the API, so what they are is the sealed plugin's
// verdict on the node; preflightStaticImages checks their digests instead.
func preflightStaticNodes(ctx context.Context, w io.Writer, s *staticInstall) error {
	out, err := exec.CommandContext(ctx, "kubectl", "get", "nodes", "-o", "json").Output()
	if err != nil {
		return fmt.Errorf("kubectl get nodes: %w", err)
	}
	var list corev1.NodeList
	if err := json.Unmarshal(out, &list); err != nil {
		return fmt.Errorf("parse node list: %w", err)
	}
	if len(list.Items) == 0 {
		return fmt.Errorf("--static-allowlist: the cluster reports no nodes to attest")
	}
	rtmr3 := s.bundle.RTMR3()
	for _, node := range list.Items {
		ip := internalIP(node)
		if ip == "" {
			return fmt.Errorf("--static-allowlist: node %s reports no InternalIP address to attest through", node.Name)
		}
		nodeCtx, cancel := context.WithTimeout(ctx, staticNodeTimeout)
		err := staticNodeVerifier(nodeCtx, "http://"+net.JoinHostPort(ip, "8400")+"/attest", s.pins, rtmr3)
		cancel()
		if err != nil {
			return fmt.Errorf("--static-allowlist: node %s (%s) is not sealed to this bundle: %w — every node must have booted the measured image with this bundle attached as its policydata disk", node.Name, ip, err)
		}
		fmt.Fprintf(w, "+ node %s: static mode, RTMR[3] matches the bundle\n", node.Name)
	}
	return nil
}

// internalIP is the address the node's attestation-api listens on.
func internalIP(node corev1.Node) string {
	for _, a := range node.Status.Addresses {
		if a.Type == corev1.NodeInternalIP {
			return a.Address
		}
	}
	return ""
}

// preflightStaticImages fails when a container the cluster runs has a digest
// the bundle does not name: the sealed plugin admits only bundle entries, so
// such a container is one no node will restart. --force installs anyway and
// returns the same list as a warning.
func preflightStaticImages(ctx context.Context, al *pkgallowlist.Allowlist, force bool) (warn string, err error) {
	podsJSON, err := exec.CommandContext(ctx, "kubectl", "get", "pods", "--all-namespaces", "-o", "json").Output()
	if err != nil {
		return "", fmt.Errorf("kubectl get pods --all-namespaces: %w", err)
	}
	var list corev1.PodList
	if err := json.Unmarshal(podsJSON, &list); err != nil {
		return "", fmt.Errorf("parse pod list: %w", err)
	}
	unlisted := unlistedImages(list.Items, bundleDigests(al))
	if len(unlisted) == 0 {
		return "", nil
	}
	summary := fmt.Sprintf("%d running image(s) the bundle does not name", len(unlisted))
	if force {
		return "installing a static allowlist beside " + summary + "; the sealed plugin will not admit those containers again", nil
	}
	return "", fmt.Errorf("--static-allowlist: the cluster runs %s, which the sealed plugin denies:\n  %s\nAdd their entries to the bundle (`c8s allowlist render --sealed`) and reboot the nodes with it, or re-run with --force to install anyway",
		summary, strings.Join(unlisted, "\n  "))
}

// bundleDigests is every container digest the bundle's entries name.
func bundleDigests(al *pkgallowlist.Allowlist) map[string]bool {
	out := map[string]bool{}
	for _, w := range al.Workloads {
		for _, c := range slices.Concat(w.InitContainers, w.Containers) {
			out[c.Digest.String()] = true
		}
	}
	return out
}

// unlistedImages lists, one "namespace/pod  repository@digest" line per
// (namespace, digest), every container whose digest is not in admitted. Pods
// the kubelet has finished with are skipped, as is a container that has not
// pulled yet (no digest to compare).
func unlistedImages(pods []corev1.Pod, admitted map[string]bool) []string {
	seen := map[string]bool{}
	var lines []string
	for _, p := range pods {
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		for _, st := range podContainerStatuses(p) {
			digest := imageDigest(st.ImageID, st.Image)
			if digest == "" || admitted[digest] {
				continue
			}
			if key := p.Namespace + "\x00" + digest; !seen[key] {
				seen[key] = true
				lines = append(lines, fmt.Sprintf("%s/%s  %s@%s", p.Namespace, p.Name, imageRepository(st.Image, st.ImageID), digest))
			}
		}
	}
	slices.Sort(lines)
	return lines
}

// printStaticVerifyHint says how a relying party verifies the cluster it just
// installed: the same bundle and manifest, the entry name from the bundle.
func printStaticVerifyHint(w io.Writer) {
	fmt.Fprintln(w, "+ static allowlist installed; every node is sealed to the bundle and CDS issues only to its entries.")
	fmt.Fprintf(w, "  Clients verify with the same bundle: c8s verify https://<tls-lb> --kind lb --image-manifest %s --static-allowlist %s --workload <entry> --mesh-ca <ca.pem>\n", installImageManifest, installStaticAllowlist)
}
