package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AttestationServiceRef points at the assam Service that pods talk to for
// challenge / attest / cert issuance. The TrustDomain controller probes
// reachability and surfaces it on .status.
type AttestationServiceRef struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`
}

// LeafDefaultsSpec sets defaults applied by cert-issuer to leaf certificates
// issued under this TrustDomain.
type LeafDefaultsSpec struct {
	// TTL is the issued leaf certificate lifetime. Default 24h.
	TTL *metav1.Duration `json:"ttl,omitempty"`
}

// TrustDomainSpec is the desired state of a TrustDomain.
//
// All fields are optional. Without a TrustDomain CR pods talk to the default
// attestation Service shipped by the helm chart. CA material is intentionally
// not part of this spec: a Kubernetes Secret is readable by the operator and
// any cluster-admin, so a TrustDomain CR cannot make claims about CA
// confidentiality. TEE-sealed CA bootstrap is tracked in docs/GAPS.md.
type TrustDomainSpec struct {
	AttestationServiceRef AttestationServiceRef `json:"attestationServiceRef,omitempty"`

	LeafDefaults LeafDefaultsSpec `json:"leafDefaults,omitempty"`
}

// Condition types surfaced on TrustDomain.status.
const (
	ConditionAttestationSvcReachable = "AttestationServiceReachable"
)

// TrustDomainStatus is the observed state of a TrustDomain. Status-mirror
// only — nothing in the cluster gates on these fields.
type TrustDomainStatus struct {
	// AttestationServiceReachable is the result of the last probe.
	AttestationServiceReachable bool `json:"attestationServiceReachable,omitempty"`

	Conditions []metav1.Condition `json:"conditions,omitempty"`

	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=td,scope=Cluster
// +kubebuilder:printcolumn:name="Attest",type="boolean",JSONPath=".status.attestationServiceReachable"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// TrustDomain is an optional cluster-scoped CR that overrides the default
// attestation-service wiring shipped by the helm chart.
type TrustDomain struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TrustDomainSpec   `json:"spec,omitempty"`
	Status TrustDomainStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TrustDomainList is a list of TrustDomains.
type TrustDomainList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TrustDomain `json:"items"`
}

func init() {
	SchemeBuilder.Register(&TrustDomain{}, &TrustDomainList{})
}
