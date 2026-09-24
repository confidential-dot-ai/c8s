package main

import (
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
)

func TestNodeServicesOnlyExposesBootstrapCommands(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"node-services"})
	if err != nil || cmd == rootCmd {
		t.Fatalf("node-services command: %v", err)
	}
	children := cmd.Commands()
	if len(children) != 3 || children[0].Name() != "node-ip" || children[1].Name() != "prepare" || children[2].Name() != "run" {
		t.Fatalf("unexpected node-service dispatch: %v", children)
	}
	for _, child := range children[:2] {
		if err := child.ValidateArgs([]string{"unmeasured-override"}); err == nil {
			t.Fatalf("%s accepts an extra argument", child.Name())
		}
	}
	if err := children[2].ValidateArgs([]string{"join", "unmeasured-override"}); err == nil {
		t.Fatal("run accepts more than the service name")
	}
}

// The enrollment units exec whatever Arguments builds; a flag the subcommand
// no longer accepts would fail CI here rather than leave the measured image
// in a systemd restart loop.
func TestNodeServiceArgumentsMatchCommands(t *testing.T) {
	for _, name := range []string{"join-release", "join"} {
		t.Run(name, func(t *testing.T) {
			role := launchconfig.Server
			if name == "join" {
				role = launchconfig.Agent
			}
			doc := &launchconfig.Document{Role: role, Image: launchconfig.Image{Platform: "tdx"},
				Server: launchconfig.ServerConfig{Address: "192.0.2.10"}, AgentOperatorPublicKeys: []string{"authorized agent"}}
			args, err := nodeservices.Arguments(name, doc)
			if err != nil {
				t.Fatal(err)
			}
			sub, rest, err := rootCmd.Find(args[:1])
			if err != nil || sub == rootCmd || len(rest) != 0 {
				t.Fatalf("%s is not a c8s subcommand: %v", args[0], err)
			}
			if err := sub.ParseFlags(args[1:]); err != nil {
				t.Fatalf("%s rejects its measured arguments: %v", name, err)
			}
		})
	}
}
