// Package nriimagepolicy is an NRI plugin that validates container images
// against a digest whitelist fetched from a whitelist API.
package nriimagepolicy

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/lunal-dev/c8s/internal/audit"
	"github.com/lunal-dev/c8s/internal/cache"
	"github.com/lunal-dev/c8s/internal/cmds/cmdsutil"
	ctrdresolver "github.com/lunal-dev/c8s/internal/containerd"
	"github.com/lunal-dev/c8s/internal/version"
	"github.com/lunal-dev/c8s/pkg/certutil"
	"github.com/lunal-dev/c8s/pkg/whitelist"
	"github.com/lunal-dev/c8s/pkg/whitelistclient"
)

const (
	// KBS startup retry parameters
	whitelistApiMaxRetries   = 5
	whitelistApiInitialDelay = 2 * time.Second
)

// Run executes the nri-image-policy binary. args is the slice of CLI args
// after the program name.
func Run(args []string) error {
	fs := flag.NewFlagSet("nri-image-policy", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/nri/conf.d/image-policy.yaml", "path to config file")
	healthAddr := fs.String("health-addr", ":8080", "health check listen address")
	readTimeout := fs.Duration("read-timeout", 5*time.Second, "HTTP server read timeout")
	writeTimeout := fs.Duration("write-timeout", 10*time.Second, "HTTP server write timeout")
	if err := cmdsutil.ParseFlags(fs, args); err != nil {
		return err
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config %q: %w", *configPath, err)
	}

	logger := certutil.NewJSONLogger(cfg.Logging.Level)
	slog.SetDefault(logger)

	logger.Info("starting nri-image-policy", "version", version.Version, "config", *configPath)

	logger.Debug("initializing containerd resolver",
		"socket", cfg.Containerd.Socket,
		"namespace", cfg.Containerd.Namespace,
	)
	resolver, err := ctrdresolver.NewResolver(cfg.Containerd.Socket, cfg.Containerd.Namespace)
	if err != nil {
		return fmt.Errorf("create containerd resolver: %w", err)
	}
	defer resolver.Close()

	policyCache := cache.NewPolicyCache()
	auditLogger := audit.NewLogger()

	var wlClient whitelistclient.Client
	if cfg.WhitelistEnabled() {
		wlCfg := cfg.Whitelist
		logger.Info("initializing whitelist client", "url", wlCfg.URL)
		wlClient = whitelistclient.NewClientWithHTTP(wlCfg.URL, &http.Client{
			Timeout: wlCfg.Timeout,
		})
	} else {
		logger.Info("whitelist disabled, running with label rules only")
	}

	if cfg.WhitelistEnabled() {
		logger.Info("creating NRI plugin (not ready, fail-closed until whitelist loaded)")
	} else {
		logger.Info("creating NRI plugin (label rules only)")
	}
	plugin, err := newPlugin(cfg, resolver, policyCache, auditLogger, logger, wlClient)
	if err != nil {
		return fmt.Errorf("create plugin: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				logger.Info("received SIGHUP, reloading config")
				if err := plugin.Reload(*configPath); err != nil {
					logger.Error("failed to reload config", "error", err)
				}
			case syscall.SIGINT, syscall.SIGTERM:
				logger.Info("received shutdown signal", "signal", sig)
				cancel()
				return
			}
		}
	}()

	// plugin.health_addr from the config file wins over the flag default;
	// containerd-launched NRI plugins don't get CLI args.
	addr := *healthAddr
	if cfg.Plugin.HealthAddr != "" {
		addr = cfg.Plugin.HealthAddr
	}
	if err := startHealthServer(ctx, healthServerConfig{
		logger:       logger,
		plugin:       plugin,
		addr:         addr,
		readTimeout:  *readTimeout,
		writeTimeout: *writeTimeout,
	}); err != nil {
		return fmt.Errorf("start health server on %q: %w", addr, err)
	}

	pluginErrCh := make(chan error, 1)
	go func() {
		pluginErrCh <- plugin.Run(ctx)
	}()

	if cfg.WhitelistEnabled() {
		wlCfg := cfg.Whitelist
		var initialWhitelist *whitelist.Whitelist
		delay := whitelistApiInitialDelay
		for attempt := 1; attempt <= whitelistApiMaxRetries; attempt++ {
			select {
			case err := <-pluginErrCh:
				return fmt.Errorf("NRI plugin died during whitelist init: %w", err)
			case <-ctx.Done():
				logger.Info("shutdown requested during whitelist init")
				return nil
			default:
			}

			reqCtx, reqCancel := context.WithTimeout(ctx, wlCfg.Timeout)

			logger.Info("fetching whitelist", "attempt", attempt)
			wl, err := wlClient.FetchWhitelist(reqCtx)
			reqCancel()
			if err != nil {
				logger.Error("whitelist fetch failed", "attempt", attempt, "error", err)
				if attempt < whitelistApiMaxRetries {
					logger.Info("retrying whitelist fetch", "delay", delay)
					select {
					case <-time.After(delay):
					case <-ctx.Done():
						logger.Info("shutdown requested during whitelist init")
						return nil
					}
					delay *= 2
					continue
				}
				return fmt.Errorf("whitelist fetch failed after %d attempts: %w", whitelistApiMaxRetries, err)
			}

			initialWhitelist = wl
			logger.Info("whitelist loaded", "digests", len(initialWhitelist.Digests))
			break
		}

		policyCache.SetWhitelist(initialWhitelist)
	}

	plugin.SetReady()
	logger.Info("plugin ready")

	plugin.RunDeferredSweep(ctx)

	select {
	case err := <-pluginErrCh:
		if err != nil {
			return fmt.Errorf("plugin: %w", err)
		}
	case <-ctx.Done():
		if err := <-pluginErrCh; err != nil {
			logger.Error("plugin error during shutdown", "error", err)
		}
	}
	logger.Info("nri-image-policy stopped")
	return nil
}

type healthServerConfig struct {
	logger       *slog.Logger
	plugin       *plugin
	addr         string
	readTimeout  time.Duration
	writeTimeout time.Duration
}

// startHealthServer starts an HTTP server for readiness/liveness probes.
// addr accepts plain `host:port` for TCP or `unix:///path/to.sock` for a
// Unix socket. It shuts down gracefully when ctx is cancelled.
func startHealthServer(ctx context.Context, cfg healthServerConfig) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if cfg.plugin.Ready() {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "ok")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "not ready")
		}
	})

	listener, err := healthListener(cfg.addr)
	if err != nil {
		return err
	}

	server := &http.Server{Handler: mux, ReadTimeout: cfg.readTimeout, WriteTimeout: cfg.writeTimeout}
	go func() {
		cfg.logger.Info("starting health server", "addr", cfg.addr)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			cfg.logger.Error("health server error", "error", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			cfg.logger.Error("health server shutdown error", "error", err)
		}
	}()
	return nil
}

// healthListener returns a TCP listener for `host:port` or a Unix socket
// listener for `unix:///abs/path`. Stale socket files are removed before
// bind so plugin restarts don't fail with EADDRINUSE; the file is chmod'd
// to 0660 so probers in the install-DaemonSet (which mounts the parent
// directory via hostPath) can connect.
func healthListener(addr string) (net.Listener, error) {
	if path, ok := strings.CutPrefix(addr, "unix://"); ok {
		_ = os.Remove(path)
		l, err := net.Listen("unix", path)
		if err != nil {
			return nil, fmt.Errorf("listen unix %s: %w", path, err)
		}
		if err := os.Chmod(path, 0o660); err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("chmod unix socket %s: %w", path, err)
		}
		return l, nil
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen tcp %s: %w", addr, err)
	}
	return l, nil
}
