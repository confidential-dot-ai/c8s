package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TrustDomainReference is a reference to a cluster-scoped TrustDomain by name.
type TrustDomainReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// WorkloadKind is the Kubernetes Kind of the workload mirrored by a
// ConfidentialWorkload.
// +kubebuilder:validation:Enum=Deployment;StatefulSet;DaemonSet
type WorkloadKind string

const (
	WorkloadKindDeployment  WorkloadKind = "Deployment"
	WorkloadKindStatefulSet WorkloadKind = "StatefulSet"
	WorkloadKindDaemonSet   WorkloadKind = "DaemonSet"
)

// WorkloadRef references a workload in the same namespace as the
// ConfidentialWorkload.
type WorkloadRef struct {
	Kind WorkloadKind `json:"kind"`

	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// MeshSpec is informational. The mutating webhook decides pod injection from
// the workload annotation `confidential.ai/cw`, not this field.
type MeshSpec struct {
	Enabled bool `json:"enabled,omitempty"`
}

// ConfidentialWorkloadSpec is the desired state of a ConfidentialWorkload.
//
// Sidecar injection happens on pod annotation alone — a CW CR is not required
// for any cluster behavior. When present, the operator aggregates per-pod
// attestation state into .status.
type ConfidentialWorkloadSpec struct {
	TrustDomainRef TrustDomainReference `json:"trustDomainRef,omitempty"`

	WorkloadRef WorkloadRef `json:"workloadRef"`

	Mesh MeshSpec `json:"mesh,omitempty"`
}

// AttestationSummary aggregates per-pod attestation state for the workload.
type AttestationSummary struct {
	Total    int32 `json:"total"`
	Attested int32 `json:"attested"`
}

// SecretRef points at the Secret holding the issued keypair.
type SecretRef struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
}

// Condition types surfaced on ConfidentialWorkload.status.
const (
	ConditionAttested   = "Attested"
	ConditionCertIssued = "CertIssued"
)

// ConfidentialWorkloadStatus is the observed state of a ConfidentialWorkload.
// Status-mirror only.
type ConfidentialWorkloadStatus struct {
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	AttestationSummary *AttestationSummary `json:"attestationSummary,omitempty"`

	IssuedCertRef *SecretRef `json:"issuedCertRef,omitempty"`

	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=cwl,scope=Namespaced
// +kubebuilder:printcolumn:name="Workload",type="string",JSONPath=".spec.workloadRef.name"
// +kubebuilder:printcolumn:name="Attested",type="integer",JSONPath=".status.attestationSummary.attested"
// +kubebuilder:printcolumn:name="Total",type="integer",JSONPath=".status.attestationSummary.total"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ConfidentialWorkload is an optional namespaced CR that mirrors per-pod
// attestation state for a workload. Sidecar injection is driven by pod
// annotations and runs whether or not a matching CW CR exists.
type ConfidentialWorkload struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ConfidentialWorkloadSpec   `json:"spec,omitempty"`
	Status ConfidentialWorkloadStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConfidentialWorkloadList is a list of ConfidentialWorkloads.
type ConfidentialWorkloadList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ConfidentialWorkload `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ConfidentialWorkload{}, &ConfidentialWorkloadList{})
}
