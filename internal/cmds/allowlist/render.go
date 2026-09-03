//go:build !c8s_node

package allowlist

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/crane"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func init() {
	extraCommands = append(extraCommands, newRenderCmd)
}

// defaultKubernetesServiceHost is the API server's Service IP on the node
// image's service CIDR (node-guest-image/c8s/mkosi.extra/etc/rancher/rke2/
// config.yaml: service-cidr 10.53.0.0/16).
const defaultKubernetesServiceHost = "10.53.0.1"

// chartKubeVersion is the chart's kubeVersion floor, pinned so rendering
// does not depend on the helm client's compiled default.
const chartKubeVersion = "1.30.0"

func newRenderCmd(_ *options) *cobra.Command {
	var (
		sealed                       bool
		systemFloor, chartValues     string
		workloads, chartDir          string
		releaseName, releaseNS       string
		serviceHost, servicePort     string
		reportPath, workloadsDefault string
	)
	cmd := &cobra.Command{
		Use:   "render --sealed [--system-floor FILE] [--chart-values FILE] [--workloads FILE]",
		Short: "Render a complete sealed allowlist from the chart, the node image and workload manifests",
		Long: `Render the static-allowlist bundle member for a sealed cluster: one entry per
pod the chart deploys (helm template on --chart-values), per system image in
the node image's --system-floor file, and per workload in --workloads. Every
container gets a complete rule: argv from the image config and the template
with Kubernetes semantics, env values from the image, the kubelet and the
template (fieldRefs become 'from' rules), every bind mount with its source
class, and the privileges the pod asks for. Workload pods run through the
operator's own injection, so c8s-cert and its siblings get rules too.

The canonical document goes to stdout; a review report listing every
executable, argv, env rule, mount rule and privilege goes to stderr or
--report. Reviews (privileged entries, pvc mounts) start empty: complete them,
then run 'c8s allowlist lint --sealed'.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !sealed {
				return fmt.Errorf("--sealed is required: render produces static-allowlist bundle members only")
			}
			if systemFloor == "" && chartValues == "" && workloads == "" {
				return fmt.Errorf("nothing to render: pass --system-floor, --chart-values or --workloads")
			}
			if workloads != "" && chartValues == "" {
				return fmt.Errorf("--workloads needs --chart-values: the injected sidecar rules come from the operator the chart deploys")
			}
			if chartValues != "" {
				if err := crane.Require(); err != nil {
					return err
				}
			}
			reportOut := cmd.ErrOrStderr()
			if reportPath != "" {
				f, err := os.Create(reportPath)
				if err != nil {
					return err
				}
				defer f.Close()
				reportOut = f
			}
			r := &renderer{
				images:  &imageResolver{ctx: ctx(cmd)},
				cluster: clusterFacts{serviceHost: serviceHost, servicePort: servicePort},
				report:  &report{},
				entries: map[string]pkgallowlist.Workload{},
			}
			if systemFloor != "" {
				if err := r.addSystemFloor(systemFloor); err != nil {
					return err
				}
			}
			if chartValues != "" {
				dir := chartDir
				if dir == "" {
					extracted, err := extractChart()
					if err != nil {
						return err
					}
					defer os.RemoveAll(extracted)
					dir = extracted
				}
				rendered, err := helmTemplate(ctx(cmd), dir, releaseName, releaseNS, chartKubeVersion, chartValues)
				if err != nil {
					return err
				}
				if err := r.addChart(rendered, releaseNS); err != nil {
					return err
				}
			}
			if workloads != "" {
				data, err := readFileOrStdin(cmd, workloads)
				if err != nil {
					return err
				}
				if err := r.addWorkloads(data, workloadsDefault); err != nil {
					return err
				}
			}
			doc, err := r.document()
			if err != nil {
				return err
			}
			r.report.write(reportOut, r.entries)
			_, err = cmd.OutOrStdout().Write(doc)
			return err
		},
	}
	f := cmd.Flags()
	f.BoolVar(&sealed, "sealed", false, "render a static-allowlist bundle member (required)")
	f.StringVar(&systemFloor, "system-floor", "", "system-floor.json emitted by the node image build")
	f.StringVar(&chartValues, "chart-values", "", "helm values file the cluster is installed with")
	f.StringVar(&workloads, "workloads", "", "YAML manifests of the workloads to admit (Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob); '-' reads stdin")
	f.StringVar(&chartDir, "chart", "", "chart directory (default: the chart embedded in this binary)")
	f.StringVar(&releaseName, "release-name", "c8s", "helm release name")
	f.StringVar(&releaseNS, "release-namespace", "c8s-system", "helm release namespace")
	f.StringVar(&workloadsDefault, "workloads-namespace", "default", "namespace for --workloads objects that name none")
	f.StringVar(&serviceHost, "kubernetes-service-host", defaultKubernetesServiceHost, "cluster IP of the kubernetes Service (the KUBERNETES_SERVICE_HOST the kubelet injects)")
	f.StringVar(&servicePort, "kubernetes-service-port", "443", "port of the kubernetes Service")
	f.StringVar(&reportPath, "report", "", "write the review report here instead of stderr")
	return cmd
}

// renderer accumulates entries from every input and the report about them.
type renderer struct {
	images  *imageResolver
	cluster clusterFacts
	report  *report
	entries map[string]pkgallowlist.Workload
	// operator is the webhook configuration recovered from the chart, applied
	// to every workload pod.
	operator *webhook.Config
}

func (r *renderer) add(name string, w pkgallowlist.Workload) error {
	if _, dup := r.entries[name]; dup {
		return fmt.Errorf("two inputs produce the entry name %q", name)
	}
	r.entries[name] = w
	return nil
}

func (r *renderer) addSystemFloor(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	floor, err := pkgallowlist.ParseSystemFloor(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	ws, err := floor.Workloads()
	if err != nil {
		return err
	}
	for name, w := range ws {
		if err := r.add(name, w); err != nil {
			return err
		}
	}
	return nil
}

// addChart renders every pod the chart deploys. helm hooks are skipped and
// reported; a claim on a storage class whose provisioner runs a helper pod
// (local-path) is an error, because that pod has no admissible rule.
func (r *renderer) addChart(rendered []byte, namespace string) error {
	manifests, err := parseManifests(rendered)
	if err != nil {
		return fmt.Errorf("rendered chart: %w", err)
	}
	cfg, err := operatorConfig(manifests, namespace)
	if err != nil {
		return err
	}
	r.operator = &cfg
	if cfg.WorkloadClaimsHostDir != "" {
		r.cluster.platformDir = hostPathAsBound(cfg.WorkloadClaimsHostDir)
		r.report.notef("platform socket directory: %s (the operator's --workload-claims-host-dir); binds from it are platform mounts", r.cluster.platformDir)
	}
	return r.addManifests(manifests, namespace, "chart")
}

func (r *renderer) addWorkloads(data []byte, namespace string) error {
	manifests, err := parseManifests(data)
	if err != nil {
		return fmt.Errorf("workloads: %w", err)
	}
	return r.addManifests(manifests, namespace, "workloads")
}

func (r *renderer) addManifests(manifests []manifest, namespace, source string) error {
	for _, m := range manifests {
		if claim, ok := m.localPathClaim(); ok {
			return fmt.Errorf("%s: %s uses local-path storage, whose provisioner runs a per-claim helper pod that no sealed rule admits; use another storage class or no persistence", source, claim)
		}
	}
	for _, m := range manifests {
		pod, ok := m.pod(namespace)
		if !ok {
			continue
		}
		if m.isHook() {
			r.report.skipf("%s %s/%s is a helm hook; hooks run outside the sealed steady state and get no entry", m.Kind, pod.Namespace, pod.Name)
			continue
		}
		if r.operator != nil {
			if _, err := webhook.Mutate(pod, pod.Namespace, *r.operator); err != nil {
				return fmt.Errorf("%s %s/%s: admission would refuse it: %w", m.Kind, pod.Namespace, pod.Name, err)
			}
		}
		init, main, err := podRules(pod, r.images, r.cluster, r.report)
		if err != nil {
			return err
		}
		if err := r.add(pod.Name, pkgallowlist.Workload{Label: m.Kind + "/" + pod.Namespace + "/" + pod.Name, InitContainers: init, Containers: main}); err != nil {
			return err
		}
	}
	return nil
}

// localPathClass reports a claim the local-path provisioner would serve: the
// class named outright, or the unset default, which is local-path on RKE2.
// An empty class name disables dynamic provisioning (the claim binds a
// pre-provisioned volume), so no helper pod runs for it.
func localPathClass(class *string) bool {
	return class == nil || *class == "local-path"
}

// document assembles the canonical bytes, normalizing through a parse
// round-trip so hand-built structs serialize like parsed ones, and records
// the sealed findings the reviewer still owes.
func (r *renderer) document() ([]byte, error) {
	al := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Digests: map[string]string{}, Workloads: r.entries}
	draft, err := al.Canonical()
	if err != nil {
		return nil, err
	}
	parsed, err := pkgallowlist.ParseJSON(draft)
	if err != nil {
		return nil, fmt.Errorf("rendered document does not parse: %w", err)
	}
	doc, err := parsed.Canonical()
	if err != nil {
		return nil, err
	}
	findings, err := pkgallowlist.SealedFindings(doc)
	if err != nil {
		return nil, err
	}
	for _, f := range findings {
		r.report.warnf("%s", f)
	}
	r.entries = parsed.Workloads
	return doc, nil
}

// report is the reviewer's view of what was rendered: every rule in
// readable form, what was skipped, and what still needs a human.
type report struct {
	notes    []string
	warnings []string
	skipped  []string
}

func (r *report) notef(format string, args ...any) {
	r.notes = append(r.notes, fmt.Sprintf(format, args...))
}

func (r *report) warnf(format string, args ...any) {
	r.warnings = append(r.warnings, fmt.Sprintf(format, args...))
}

func (r *report) skipf(format string, args ...any) {
	r.skipped = append(r.skipped, fmt.Sprintf(format, args...))
}

func (r *report) write(w io.Writer, entries map[string]pkgallowlist.Workload) {
	for _, name := range sortedWorkloadNames(entries) {
		e := entries[name]
		fmt.Fprintf(w, "entry %s", name)
		if e.Label != "" {
			fmt.Fprintf(w, " (%s)", e.Label)
		}
		fmt.Fprintln(w)
		for i, c := range e.InitContainers {
			writeContainerReport(w, fmt.Sprintf("initContainers[%d]", i), c)
		}
		for i, c := range e.Containers {
			writeContainerReport(w, fmt.Sprintf("containers[%d]", i), c)
		}
	}
	for _, s := range r.notes {
		fmt.Fprintf(w, "note: %s\n", s)
	}
	for _, s := range r.skipped {
		fmt.Fprintf(w, "skipped: %s\n", s)
	}
	for _, s := range r.warnings {
		fmt.Fprintf(w, "warning: %s\n", s)
	}
}

func writeContainerReport(w io.Writer, where string, c pkgallowlist.Container) {
	fmt.Fprintf(w, "  %s %s\n", where, c.Image)
	fmt.Fprintf(w, "    argv: %s\n", containerSummary(c))
	if c.Env.Policy == pkgallowlist.PolicyExact {
		for _, n := range c.Env.Names {
			fmt.Fprintf(w, "    env: %s\n", envRuleSummary(n, c.Env.Values[n]))
		}
	} else {
		fmt.Fprintln(w, "    env: any")
	}
	if c.Mounts.Policy == pkgallowlist.PolicyExact {
		for _, d := range c.Mounts.Destinations {
			r := c.Mounts.Rules[d]
			fmt.Fprintf(w, "    mount: %s source=%s", d, r.Source)
			if r.Source == pkgallowlist.SourcePVC {
				fmt.Fprintf(w, " review=%q", r.Review)
			}
			fmt.Fprintln(w)
		}
	} else {
		fmt.Fprintln(w, "    mounts: any")
	}
	if p := c.Privileges; p != nil {
		fmt.Fprintf(w, "    privileges: privileged=%t hostNamespaces=[%s] capabilities=[%s] devices=[%s] hostPaths=[%s] unmaskedProc=%t review=%q\n",
			p.Privileged, strings.Join(p.HostNamespaces, " "), strings.Join(p.Capabilities, " "),
			strings.Join(p.Devices, " "), strings.Join(p.HostPaths, " "), p.UnmaskedProc, p.Review)
	}
}

func envRuleSummary(name string, v pkgallowlist.EnvValue) string {
	if v.From != "" {
		return name + " from " + v.From
	}
	if v.Value != nil {
		return name + "=" + *v.Value
	}
	return name
}
