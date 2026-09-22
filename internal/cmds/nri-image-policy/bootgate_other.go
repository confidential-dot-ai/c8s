//go:build !linux

package nriimagepolicy

import "errors"

// powerOff has no meaning off Linux; the caller exits instead. The plugin only
// ever runs on a Linux node — this keeps `go build` for the macOS CLI honest.
func powerOff() error { return errors.New("powering off is only implemented on linux") }
