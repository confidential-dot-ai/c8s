//go:build linux

package ratlsmesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/meshnetns"
)

type localDelivery interface {
	DialContext(context.Context, string) (net.Conn, error)
}

type hostNetworkDelivery struct {
	timeout   time.Duration
	keepAlive time.Duration
}

func (d hostNetworkDelivery) DialContext(ctx context.Context, destination string) (net.Conn, error) {
	return (&net.Dialer{Timeout: durOrDefault(d.timeout, 5*time.Second), KeepAlive: durOrDefault(d.keepAlive, 30*time.Second)}).DialContext(ctx, "tcp", destination)
}

type podNamespaceDelivery struct {
	directory string
	timeout   time.Duration
	keepAlive time.Duration
}

func (d podNamespaceDelivery) DialContext(ctx context.Context, destination string) (net.Conn, error) {
	address, err := netip.ParseAddrPort(destination)
	if err != nil || address.Port() == 0 || !address.Addr().IsGlobalUnicast() {
		return nil, fmt.Errorf("local delivery requires a numeric pod address and nonzero port")
	}
	ctx, cancel := context.WithTimeout(ctx, durOrDefault(d.timeout, 5*time.Second))
	defer cancel()
	namespace, err := d.findNamespace(ctx, address.Addr())
	if err != nil {
		return nil, err
	}
	defer namespace.Close()
	return namespace.DialLocal(ctx, address, durOrDefault(d.keepAlive, 30*time.Second))
}

func (d podNamespaceDelivery) findNamespace(ctx context.Context, address netip.Addr) (match *meshnetns.Namespace, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(d.directory)
	if err != nil {
		return nil, fmt.Errorf("read runtime namespaces: %w", err)
	}
	defer func() {
		if err != nil && match != nil {
			match.Close()
			match = nil
		}
	}()
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			return match, err
		}
		namespace, openErr := meshnetns.Open(filepath.Join(d.directory, entry.Name()))
		if os.IsNotExist(openErr) || errors.Is(openErr, meshnetns.ErrNotNetworkNamespace) {
			continue
		}
		if openErr != nil {
			return match, fmt.Errorf("open runtime namespace %q: %w", entry.Name(), openErr)
		}
		owns, inspectErr := namespace.OwnsAddress(address)
		if inspectErr != nil {
			namespace.Close()
			return match, fmt.Errorf("inspect runtime namespace: %w", inspectErr)
		}
		if !owns {
			namespace.Close()
			continue
		}
		if match != nil {
			namespace.Close()
			return match, fmt.Errorf("multiple runtime namespaces own destination %s", address)
		}
		match = namespace
	}
	if match == nil {
		return nil, fmt.Errorf("no local runtime namespace owns destination %s", address)
	}
	return match, nil
}
