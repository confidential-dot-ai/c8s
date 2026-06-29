package cds

import (
	"github.com/confidential-dot-ai/c8s/internal/ear"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/attestationclient"
	"github.com/confidential-dot-ai/c8s/pkg/earsigner"
)

// Compile-time assertions that the concrete types CDS wires into the
// internal/issuer interfaces still satisfy them. Those interfaces are defined
// abstractly in internal/issuer to keep it decoupled from these concrete
// packages, so the guards live here at the composition root (where both the
// interface and the implementation are already imported) rather than next to
// the interface definitions.
var (
	_ issuer.KeyProvider    = (*earsigner.Rotator)(nil)
	_ issuer.LocalEARMinter = ear.Issuer{}
	_ issuer.AttestationApi = attestationclient.Client{}
)
