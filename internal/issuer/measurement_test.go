package issuer_test

import (
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

func TestNormalizeMeasurement(t *testing.T) {
	if got := issuer.NormalizeMeasurement("  DEADbeef \n"); got != "deadbeef" {
		t.Errorf("NormalizeMeasurement = %q, want deadbeef", got)
	}
}
