package cds

import (
	"fmt"
	"net"
	"regexp"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
)

func compileDNSPatterns(raws []string, path string) ([]*regexp.Regexp, error) {
	patterns, err := compilePatterns("--dns-san-pattern", raws)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return patterns, nil
	}
	name, err := cmdsutil.ReadSANFile("--dns-san-file", path)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(name) != nil {
		return nil, fmt.Errorf("--dns-san-file must contain a DNS hostname, not an IP address")
	}
	if err := cmdsutil.ValidateDNSName(name); err != nil {
		return nil, fmt.Errorf("--dns-san-file: %w", err)
	}
	// The authenticated hostname is a literal identity, never a caller-
	// supplied regular expression. Keep the whole-name match explicit.
	return append(patterns, regexp.MustCompile("^"+regexp.QuoteMeta(name)+"$")), nil
}
