package main

import "testing"

func TestNodeServicesOnlyExposesBootstrapCommands(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"node-services"})
	if err != nil || cmd == rootCmd {
		t.Fatalf("node-services command: %v", err)
	}
	children := cmd.Commands()
	if len(children) != 2 || children[0].Name() != "node-ip" || children[1].Name() != "prepare" {
		t.Fatalf("unexpected node-service dispatch: %v", children)
	}
	for _, child := range children {
		if err := child.ValidateArgs([]string{"unmeasured-override"}); err == nil {
			t.Fatalf("%s accepts an extra argument", child.Name())
		}
	}
}
