package nriimagepolicy

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// config represents the plugin configuration.
type config struct {
	// Platform types the RA-TLS identity the sandbox-digests endpoint serves
	// to CDS, as an attestation-api platform string; empty means snp. It must
	// name the node's actual CPU TEE — CDS fails closed when the certificate's
	// TEE type and the evidence envelope's platform disagree.
	Platform       string               `yaml:"platform"`
	Plugin         pluginConfig         `yaml:"plugin"`
	Allowlist      allowlistConfig      `yaml:"allowlist"`
	Containerd     containerdConfig     `yaml:"containerd"`
	Policy         policyConfig         `yaml:"policy"`
	Logging        loggingConfig        `yaml:"logging"`
	WorkloadClaims workloadClaimsConfig `yaml:"workload_claims"`
}

// pluginConfig contains plugin runtime settings.
type pluginConfig struct {
	// HealthAddr is the listen address for the readiness/liveness HTTP
	// server. `host:port` selects TCP; `unix:///path/to.sock` selects a
	// Unix socket.
	HealthAddr string `yaml:"health_addr"`
}

// workloadClaimsConfig configures the node-CVM admission inventory
// (docs/ratls.md).
type workloadClaimsConfig struct {
	// SocketDir is the host directory the inventory creates its socket in (as the
	// compiled workloadclaims.SocketName); the webhook mounts it into c8s-cert
	// sidecars so get-cert can fetch its pod's digests. The filename is fixed
	// so get-cert can bake the dial path — see workloadclaims.InventoryEndpoint.
	SocketDir string `yaml:"socket_dir"`
	// ProcRoot is the /proc mount used to resolve a caller PID to its
	// container cgroup. Defaults to "/proc".
	ProcRoot string `yaml:"proc_root"`
	// AdvertiseHost is the node address CDS dials to reach this inventory's
	// digests endpoint. Empty reads it from NodeIPFile, which the installer
	// writes from its own status.hostIP — the plugin is a host process and has
	// no downward API of its own.
	AdvertiseHost string `yaml:"advertise_host"`
}

// allowlistConfig groups the digest-source mechanisms.
//
// AlwaysAllow is a static baseline, always merged into the cache at
// startup (the chart's floor: self-allows the installer + the CDS digest,
// so a floor-rewrite roll admits the new images without a network round-trip).
// Pull is the runtime-update source: every plugin polls CDS.
type allowlistConfig struct {
	AlwaysAllow map[string]string `yaml:"always_allow"`
	Pull        pullConfig        `yaml:"pull"`
}

// pullConfig configures the CDS polling source.
type pullConfig struct {
	URL               string        `yaml:"url"`                 // empty disables pull
	Interval          time.Duration `yaml:"interval"`            // ticker cadence; > 0 required when URL is set
	Timeout           time.Duration `yaml:"timeout"`             // per-request timeout; > 0 required when URL is set
	AttestationApiURL string        `yaml:"attestation_api_url"` // required for https pull
	CDSMeasurements   []string      `yaml:"cds_measurements"`    // SHA-384 hex launch digests
}

// containerdConfig contains containerd connection settings for tag-to-digest resolution.
type containerdConfig struct {
	Socket    string `yaml:"socket"`
	Namespace string `yaml:"namespace"`
}

// policyConfig contains policy enforcement settings.
type policyConfig struct {
	Mode                  string      `yaml:"mode"`                    // fail-closed, audit
	EnforceExisting       bool        `yaml:"enforce_existing"`        // kill non-allowlisted containers on startup
	DenyMissingAnnotation bool        `yaml:"deny_missing_annotation"` // deny containers without image annotation
	LabelRules            []labelRule `yaml:"label_rules"`

	// ExemptNamespaces admits a namespace's containers by the digests captured
	// running in it at first admission, not by a name the control plane picks.
	// See exempt.go and docs/getcert-workload-binding.md — Corner 8.
	ExemptNamespaces []string `yaml:"exempt_namespaces"`
	// ExemptSnapshotPath persists the captured per-namespace digest set. Required
	// when ExemptNamespaces is set; must sit on a filesystem that survives reboot.
	ExemptSnapshotPath string `yaml:"exempt_snapshot_path"`
}

// labelRule defines a constraint on pod labels. Pods that do not satisfy
// all match expressions are denied.
type labelRule struct {
	Name             string            `yaml:"name"`
	MatchExpressions []labelExpression `yaml:"match_expressions"`
	selector         labels.Selector   `yaml:"-"`
}

// labelExpression is a single label selector requirement (Kubernetes-style).
type labelExpression struct {
	Key      string   `yaml:"key"`
	Operator string   `yaml:"operator"` // In, NotIn, Exists, DoesNotExist
	Values   []string `yaml:"values"`
}

// Label expression operators.
const (
	OpIn           = "In"
	OpNotIn        = "NotIn"
	OpExists       = "Exists"
	OpDoesNotExist = "DoesNotExist"
)

// Policy modes.
const (
	ModeFailClosed = "fail-closed"
	ModeAudit      = "audit"
)

// loggingConfig contains logging settings.
type loggingConfig struct {
	Level string `yaml:"level"`
}

const defaultPullInterval = 30 * time.Second
const defaultPullTimeout = 30 * time.Second

// NodeIPFile is the filename, inside SocketDir, the installer writes this
// node's address to. Read only when advertise_host is unset.
const NodeIPFile = "node-ip"

// loadConfig loads configuration from a YAML file.
func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := &config{
		Allowlist: allowlistConfig{
			Pull: pullConfig{
				Interval: defaultPullInterval,
				Timeout:  defaultPullTimeout,
			},
		},
		Containerd: containerdConfig{
			Socket:    "/run/containerd/containerd.sock",
			Namespace: "k8s.io",
		},
		Policy: policyConfig{
			Mode:                  ModeFailClosed,
			EnforceExisting:       true,
			DenyMissingAnnotation: true,
		},
		Logging: loggingConfig{
			Level: "info",
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// NormalizedPlatform folds the az-/gcp- variants onto the two TEE families the
// RA-TLS extension records, matching what CDS does with its own
// --ratls-platform. Defaulting here rather than in loadConfig keeps every
// construction path on the same value, including callers that build a config
// literal and validate it directly.
func (c *config) NormalizedPlatform() string {
	if strings.TrimSpace(c.Platform) == "" {
		return ratls.NormalizePlatform(string(types.PlatformSnp))
	}
	return ratls.NormalizePlatform(c.Platform)
}

// PullEnabled reports whether the plugin should poll a remote CDS.
func (c *config) PullEnabled() bool { return c.Allowlist.Pull.URL != "" }

// AllowlistEnabled reports whether any digest-based enforcement is active.
func (c *config) AllowlistEnabled() bool {
	return c.PullEnabled() || len(c.Allowlist.AlwaysAllow) > 0
}

// Validate checks the configuration for errors.
func (c *config) Validate() error {
	// Reject at load rather than at the first CDS handshake: a wrong platform
	// produces a peer-attestation failure on the CDS side that names the
	// evidence platform, not this setting, so the cause is several hops from
	// the symptom.
	if err := ratls.ValidatePlatform(c.NormalizedPlatform()); err != nil {
		return fmt.Errorf("platform %q is not a supported CPU TEE (want snp or tdx)", c.Platform)
	}
	if c.PullEnabled() && len(c.Allowlist.AlwaysAllow) == 0 {
		return fmt.Errorf("allowlist.always_allow must be non-empty when pull is configured (cold-boot baseline)")
	}
	for d := range c.Allowlist.AlwaysAllow {
		if _, err := types.ParseDigest(d); err != nil {
			return fmt.Errorf("allowlist.always_allow: invalid digest %q (expected sha256:<64 hex chars>)", d)
		}
	}
	if c.PullEnabled() {
		if c.Allowlist.Pull.Timeout <= 0 {
			return fmt.Errorf("allowlist.pull.timeout must be > 0 when pull.url is set")
		}
		if c.Allowlist.Pull.Interval <= 0 {
			return fmt.Errorf("allowlist.pull.interval must be > 0 when pull.url is set")
		}
		parsed, err := url.Parse(c.Allowlist.Pull.URL)
		if err != nil {
			return fmt.Errorf("allowlist.pull.url: %w", err)
		}
		// CDS serves RA-TLS only, so the pull URL must be https — a plaintext
		// pull would defeat the attestation handshake entirely.
		if parsed.Scheme != "https" {
			return fmt.Errorf("allowlist.pull.url scheme must be https, got %q", parsed.Scheme)
		}
		if c.Allowlist.Pull.AttestationApiURL == "" {
			return fmt.Errorf("allowlist.pull.attestation_api_url must be set")
		}
		if _, err := ratls.ParseHexMeasurementsList(c.Allowlist.Pull.CDSMeasurements); err != nil {
			return fmt.Errorf("allowlist.pull.cds_measurements: %w", err)
		}
	}
	if !c.AllowlistEnabled() && len(c.Policy.LabelRules) == 0 {
		return fmt.Errorf("set allowlist.always_allow (required when pull is enabled) or configure policy.label_rules")
	}
	if c.Policy.Mode != ModeFailClosed && c.Policy.Mode != ModeAudit {
		return fmt.Errorf("policy.mode must be '%s' or '%s'", ModeFailClosed, ModeAudit)
	}
	if c.WorkloadClaims.SocketDir != "" && !c.AllowlistEnabled() {
		return fmt.Errorf("workload_claims.socket_dir requires allowlist.always_allow or allowlist.pull: the inventory reports digests for CDS to match against the allowlist")
	}
	if len(c.Policy.ExemptNamespaces) > 0 && c.Policy.ExemptSnapshotPath == "" {
		return fmt.Errorf("policy.exempt_namespaces requires policy.exempt_snapshot_path: the captured digest set must persist across restarts")
	}
	return validateLabelRules(c.Policy.LabelRules)
}

// validateLabelRules checks label rules for errors.
func validateLabelRules(rules []labelRule) error {
	seen := make(map[string]bool, len(rules))
	for i := range rules {
		r := rules[i]
		if r.Name == "" {
			return fmt.Errorf("label_rules[%d]: name must be set", i)
		}
		if seen[r.Name] {
			return fmt.Errorf("label_rules[%d]: duplicate name %q", i, r.Name)
		}
		seen[r.Name] = true
		if len(r.MatchExpressions) == 0 {
			return fmt.Errorf("label_rules[%d] %q: at least one match_expression required", i, r.Name)
		}
		selector, err := buildLabelSelector(r)
		if err != nil {
			return fmt.Errorf("label_rules[%d] %q: %w", i, r.Name, err)
		}
		rules[i].selector = selector
	}
	return nil
}

func buildLabelSelector(rule labelRule) (labels.Selector, error) {
	selector := labels.NewSelector()
	for j, expr := range rule.MatchExpressions {
		if expr.Key == "" {
			return nil, fmt.Errorf("expression[%d]: key must be set", j)
		}
		op, err := labelOperator(expr.Operator)
		if err != nil {
			return nil, fmt.Errorf("expression[%d]: %w", j, err)
		}
		req, err := labels.NewRequirement(expr.Key, op, expr.Values)
		if err != nil {
			return nil, fmt.Errorf("expression[%d]: %w", j, err)
		}
		selector = selector.Add(*req)
	}
	return selector, nil
}

func labelOperator(op string) (selection.Operator, error) {
	switch op {
	case OpIn:
		return selection.In, nil
	case OpNotIn:
		return selection.NotIn, nil
	case OpExists:
		return selection.Exists, nil
	case OpDoesNotExist:
		return selection.DoesNotExist, nil
	default:
		return "", fmt.Errorf("operator must be %s, %s, %s, or %s", OpIn, OpNotIn, OpExists, OpDoesNotExist)
	}
}
