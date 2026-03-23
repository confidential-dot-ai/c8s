//go:build !linux

package main

import (
	"fmt"
	"os"
)

func iptablesSetup() {
	fmt.Fprintln(os.Stderr, "iptables-setup requires Linux")
	os.Exit(1)
}

func iptablesCleanup() {
	fmt.Fprintln(os.Stderr, "iptables-cleanup requires Linux")
	os.Exit(1)
}
