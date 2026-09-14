package allowlistproxy

import "testing"

func TestProxyAcceptsCompleteLeaderPolicy(t *testing.T) {
	cfg := validConfig()
	cfg.measurementsConfig = "../../../pkg/measurements/testdata/node-identities.json"
	if _, err := newHandler(cfg, nil); err != nil {
		t.Fatalf("node operator policy refused at startup: %v", err)
	}
}
