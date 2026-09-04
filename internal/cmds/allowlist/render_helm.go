//go:build !c8s_node

package allowlist

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/helmchart"
	"github.com/confidential-dot-ai/c8s/internal/webhook"
)

// helmTimeout bounds one `helm template` run; rendering is local, so a
// minute is generous.
const helmTimeout = time.Minute

// helmTemplate renders the chart with the given values file and returns the
// multi-document YAML, exactly as `c8s install` would hand it to the cluster.
func helmTemplate(ctx context.Context, chartDir, release, namespace, kubeVersion, valuesFile string) ([]byte, error) {
	if _, err := exec.LookPath("helm"); err != nil {
		return nil, fmt.Errorf("this command needs the 'helm' CLI on PATH: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, helmTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "helm", "template", release, chartDir,
		"--namespace", namespace, "--kube-version", kubeVersion, "-f", valuesFile)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("helm template: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// extractChart writes the embedded chart to a temp dir; the caller removes it.
func extractChart() (string, error) {
	dir, err := os.MkdirTemp("", "c8s-chart-*")
	if err != nil {
		return "", err
	}
	if err := os.CopyFS(dir, helmchart.ChartFS); err != nil {
		_ = os.RemoveAll(dir)
		return "", err
	}
	return filepath.Join(dir, helmchart.ChartRoot), nil
}

// manifest is one Kubernetes object read from rendered YAML, decoded only as
// far as this command needs: pods (own or templated), ConfigMaps for the
// operator's measurements file, and claims for their storage class.
type manifest struct {
	Kind     string            `json:"kind"`
	Metadata metav1.ObjectMeta `json:"metadata"`
	Spec     manifestSpec      `json:"spec"`
	Data     map[string]string `json:"data"`
}

type manifestSpec struct {
	corev1.PodSpec
	Template    corev1.PodTemplateSpec `json:"template"`
	JobTemplate struct {
		Spec struct {
			Template corev1.PodTemplateSpec `json:"template"`
		} `json:"spec"`
	} `json:"jobTemplate"`
	StorageClassName     *string                        `json:"storageClassName"`
	VolumeClaimTemplates []corev1.PersistentVolumeClaim `json:"volumeClaimTemplates"`
}

// localPathClaim names the first claim in the manifest the local-path
// provisioner would serve: a PersistentVolumeClaim object, a StatefulSet's
// volumeClaimTemplates entry, or a pod's ephemeral volume.
func (m manifest) localPathClaim() (string, bool) {
	if m.Kind == "PersistentVolumeClaim" && localPathClass(m.Spec.StorageClassName) {
		return "PersistentVolumeClaim " + m.Metadata.Name, true
	}
	for _, t := range m.Spec.VolumeClaimTemplates {
		if localPathClass(t.Spec.StorageClassName) {
			return fmt.Sprintf("%s %s volumeClaimTemplates %s", m.Kind, m.Metadata.Name, t.Name), true
		}
	}
	pod, ok := m.pod("")
	if !ok {
		return "", false
	}
	for _, v := range pod.Spec.Volumes {
		if v.Ephemeral != nil && v.Ephemeral.VolumeClaimTemplate != nil && localPathClass(v.Ephemeral.VolumeClaimTemplate.Spec.StorageClassName) {
			return fmt.Sprintf("%s %s ephemeral volume %s", m.Kind, m.Metadata.Name, v.Name), true
		}
	}
	return "", false
}

// isHook reports a helm hook resource; hooks run outside the steady state
// this document describes and are reported as skipped.
func (m manifest) isHook() bool {
	_, ok := m.Metadata.Annotations["helm.sh/hook"]
	return ok
}

// pod returns the pod a manifest would create, or false for a kind that
// creates none.
func (m manifest) pod(defaultNamespace string) (*corev1.Pod, bool) {
	var tmpl corev1.PodTemplateSpec
	switch m.Kind {
	case "Pod":
		tmpl = corev1.PodTemplateSpec{ObjectMeta: m.Metadata, Spec: m.Spec.PodSpec}
	case "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job":
		tmpl = m.Spec.Template
	case "CronJob":
		tmpl = m.Spec.JobTemplate.Spec.Template
	default:
		return nil, false
	}
	pod := &corev1.Pod{ObjectMeta: tmpl.ObjectMeta, Spec: tmpl.Spec}
	pod.Name = m.Metadata.Name
	pod.Namespace = m.Metadata.Namespace
	if pod.Namespace == "" {
		pod.Namespace = defaultNamespace
	}
	return pod, true
}

var documentSeparator = regexp.MustCompile(`(?m)^---[ \t]*$`)

// parseManifests splits multi-document YAML and decodes each object.
func parseManifests(data []byte) ([]manifest, error) {
	var out []manifest
	for i, doc := range documentSeparator.Split(string(data), -1) {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var m manifest
		if err := sigsyaml.Unmarshal([]byte(doc), &m); err != nil {
			return nil, fmt.Errorf("document %d: %w", i+1, err)
		}
		if m.Kind == "" {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

// operatorConfig rebuilds the webhook's Config from the operator's rendered
// args, so the sidecars rendered here are the ones the cluster injects. The
// flag names mirror cmd/c8s/operator.go; a measurements file is read from
// the ConfigMap the chart mounts at that path.
func operatorConfig(manifests []manifest, namespace string) (webhook.Config, error) {
	var operator *corev1.Container
	var pod *corev1.Pod
	for _, m := range manifests {
		p, ok := m.pod(namespace)
		if !ok {
			continue
		}
		for i := range p.Spec.Containers {
			if c := &p.Spec.Containers[i]; len(c.Args) > 0 && c.Args[0] == "operator" {
				operator, pod = c, p
			}
		}
	}
	if operator == nil {
		return webhook.Config{}, fmt.Errorf("the rendered chart deploys no operator container; injected sidecar rules need its --get-cert-image and CDS pins")
	}
	var cfg webhook.Config
	var certFSGroup, runAsUser, runAsGroup int64
	var runAsNonRoot bool
	var measurementsConfig string
	fs := pflag.NewFlagSet("operator", pflag.ContinueOnError)
	fs.ParseErrorsAllowlist.UnknownFlags = true
	fs.StringVar(&cfg.GetCertImage, "get-cert-image", "", "")
	fs.StringVar(&cfg.CDSURL, "cds-url", "", "")
	fs.StringVar(&cfg.AttestationApiURL, "attestation-api-url", "", "")
	fs.StringSliceVar(&cfg.CDSMeasurements, "cds-measurements", nil, "")
	fs.StringSliceVar(&cfg.CDSRTMRs, "cds-rtmrs", nil, "")
	fs.StringVar(&measurementsConfig, "measurements-config", "", "")
	fs.Int64Var(&certFSGroup, "cert-fs-group", 65532, "")
	fs.StringVar(&cfg.CertKeyMode, "cert-key-mode", "", "")
	fs.DurationVar(&cfg.CertRenewInterval, "get-cert-renew-interval", 0, "")
	fs.Int64Var(&runAsUser, "get-cert-run-as-user", 65532, "")
	fs.Int64Var(&runAsGroup, "get-cert-run-as-group", 65532, "")
	fs.BoolVar(&runAsNonRoot, "get-cert-run-as-non-root", true, "")
	fs.BoolVar(&cfg.KataEnforce, "kata-enforce", false, "")
	fs.StringVar(&cfg.HardwarePlatform, "hardware-platform", "", "")
	fs.StringVar(&cfg.WorkloadClaimsHostDir, "workload-claims-host-dir", "", "")
	fs.BoolVar(&cfg.WorkloadClaimsGuest, "workload-claims-guest", false, "")
	fs.BoolVar(&cfg.KataGuestReadyGate, "kata-guest-ready-gate", false, "")
	fs.BoolVar(&cfg.StaticAllowlist, "static-allowlist", false, "")
	fs.StringVar(&cfg.AttestationSocketDir, "attestation-socket-dir", "", "")
	if err := fs.Parse(operator.Args[1:]); err != nil {
		return webhook.Config{}, fmt.Errorf("operator args: %w", err)
	}
	cfg.CertFSGroup, cfg.GetCertRunAsUser, cfg.GetCertRunAsGroup, cfg.GetCertRunAsNonRoot = &certFSGroup, &runAsUser, &runAsGroup, &runAsNonRoot
	if measurementsConfig != "" {
		path, err := mountedConfigMapFile(manifests, pod, operator, measurementsConfig)
		if err != nil {
			return webhook.Config{}, err
		}
		defer os.Remove(path)
		if _, err := cmdsutil.LoadMeasurementsConfig(path, "--measurements-config", "--cds-measurements", "--cds-rtmrs", &cfg.CDSMeasurements, &cfg.CDSRTMRs); err != nil {
			return webhook.Config{}, err
		}
	}
	return cfg, nil
}

// mountedConfigMapFile finds the ConfigMap key a container reads at filePath
// and writes it to a temp file the caller removes.
func mountedConfigMapFile(manifests []manifest, pod *corev1.Pod, c *corev1.Container, filePath string) (string, error) {
	dir, key := filepath.Split(filePath)
	dir = filepath.Clean(dir)
	var volumeName string
	for _, vm := range c.VolumeMounts {
		if filepath.Clean(vm.MountPath) == dir {
			volumeName = vm.Name
		}
	}
	var configMap string
	for _, v := range pod.Spec.Volumes {
		if v.Name == volumeName && v.ConfigMap != nil {
			configMap = v.ConfigMap.Name
		}
	}
	if configMap == "" {
		return "", fmt.Errorf("operator reads %s, but no ConfigMap volume is mounted at %s", filePath, dir)
	}
	for _, m := range manifests {
		if m.Kind != "ConfigMap" || m.Metadata.Name != configMap {
			continue
		}
		content, ok := m.Data[key]
		if !ok {
			return "", fmt.Errorf("ConfigMap %s has no key %q", configMap, key)
		}
		f, err := os.CreateTemp("", "c8s-measurements-*.json")
		if err != nil {
			return "", err
		}
		if _, err := f.WriteString(content); err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			return "", err
		}
		return f.Name(), f.Close()
	}
	return "", fmt.Errorf("ConfigMap %s is not among the rendered manifests", configMap)
}
