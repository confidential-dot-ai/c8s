package cds

import (
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/earsigner"
)

// Compile-time assertion that the concrete type CDS wires into the
// internal/issuer interface still satisfies it. The interface is defined
// abstractly in internal/issuer to keep it decoupled from this concrete
// package, so the guard lives here at the composition root (where both the
// interface and the implementation are already imported) rather than next to
// the interface definition.
var _ issuer.KeyProvider = (*earsigner.Rotator)(nil)
