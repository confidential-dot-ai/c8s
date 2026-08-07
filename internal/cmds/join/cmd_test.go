package join

import (
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// execCmd runs cmd with args, output discarded.
func execCmd(t *testing.T, cmd *cobra.Command, args ...string) error {
	t.Helper()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestJoinCmdRequiresServer(t *testing.T) {
	err := execCmd(t, NewJoinCmd())
	if err == nil || !strings.Contains(err.Error(), "server") {
		t.Fatalf("err = %v, want missing --server", err)
	}
}

func TestJoinCmdRejectsBareHost(t *testing.T) {
	err := execCmd(t, NewJoinCmd(),
		"--server", "10.0.0.5",
		"--attestation-api-url", "http://127.0.0.1:1",
		"--timeout", "50ms")
	if err == nil || !strings.Contains(err.Error(), "host:port") {
		t.Fatalf("err = %v, want host:port error", err)
	}
}

func TestReleaseCmdRequiresPlatform(t *testing.T) {
	err := execCmd(t, NewReleaseCmd(), "--platform", "")
	if err == nil {
		t.Fatal("expected error for empty platform")
	}
}
