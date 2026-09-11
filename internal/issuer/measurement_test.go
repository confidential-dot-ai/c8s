package issuer_test

import (
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"testing"
)

func TestNormalizeMeasurement(t *testing.T) {
	if got := issuer.NormalizeMeasurement("  DEADbeef \n"); got != "deadbeef" {
		t.Errorf("NormalizeMeasurement = %q, want deadbeef", got)
	}
}
