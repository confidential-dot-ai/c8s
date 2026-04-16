// nri-image-policy is an NRI plugin that validates container images against
// a digest whitelist fetched from a whitelist API.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lunal-dev/c8s/internal/audit"
	"github.com/lunal-dev/c8s/internal/cache"
	ctrdresolver "github.com/lunal-dev/c8s/internal/containerd"
	"github.com/lunal-dev/c8s/pkg/whitelist"
	"github.com/lunal-dev/c8s/pkg/whitelistclient"
)

var (
	configPath   = flag.String("config", "/etc/nri/conf.d/image-policy.yaml", "path to config file")
	healthAddr   = flag.String("health-addr", ":8080", "health check listen address")
	readTimeout  = flag.Duration("read-timeout", 5*time.Second, "HTTP server read timeout")
	writeTimeout = flag.Duration("write-timeout", 10*time.Second, "HTTP server write timeout")
	version      = "dev"
)

const (
	// KBS startup retry parameters
	whitelistApiMaxRetries   = 5
	whitelistApiInitialDelay = 2 * time.Second
)

func main() {
	flag.Parse()

	// Load configuration
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err, "path", *configPath)
		os.Exit(1)
	}

	// Initialize logger
	logLevel := slog.LevelInfo
	if cfg.Logging.Level == "debug" {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	logger.Info("starting nri-image-policy", "version", version, "config", *configPath)

	// Initialize components
	logger.Debug("initializing containerd resolver",
		"socket", cfg.Containerd.Socket,
		"namespace", cfg.Containerd.Namespace,
	)
	resolver, err := ctrdresolver.NewResolver(cfg.Containerd.Socket, cfg.Containerd.Namespace)
	if err != nil {
		logger.Error("failed to create containerd resolver", "error", err)
		os.Exit(1)
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
	plugin, err := NewPlugin(cfg, resolver, policyCache, auditLogger, logger, wlClient)
	if err != nil {
		logger.Error("failed to create plugin", "error", err)
		os.Exit(1)
	}

	// Handle shutdown signals — must start before plugin.Run so shutdown
	// works during KBS init.
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

	// Start health server (shut down with ctx)
	startHealthServer(ctx, logger, plugin, *healthAddr)

	// Start NRI plugin in background — registers with containerd immediately
	// so all container creation events are intercepted during KBS init.
	pluginErrCh := make(chan error, 1)
	go func() {
		pluginErrCh <- plugin.Run(ctx)
	}()

	if cfg.WhitelistEnabled() {
		// Fetch initial whitelist with retries.
		wlCfg := cfg.Whitelist
		var initialWhitelist *whitelist.Whitelist
		delay := whitelistApiInitialDelay
		for attempt := 1; attempt <= whitelistApiMaxRetries; attempt++ {
			select {
			case err := <-pluginErrCh:
				logger.Error("NRI plugin died during whitelist init", "error", err)
				os.Exit(1)
			case <-ctx.Done():
				logger.Info("shutdown requested during whitelist init")
				os.Exit(0)
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
						os.Exit(0)
					}
					delay *= 2
					continue
				}
				logger.Error("whitelist fetch failed after all retries, exiting")
				os.Exit(1)
			}

			initialWhitelist = wl
			logger.Info("whitelist loaded", "digests", len(initialWhitelist.Digests))
			break
		}

		policyCache.SetWhitelist(initialWhitelist)
	}

	plugin.SetReady()
	logger.Info("plugin ready")

	// Run deferred sweep on containers that were present when Synchronize
	// was called before the plugin was ready.
	plugin.RunDeferredSweep(ctx)

	// Block until NRI plugin exits or context is cancelled
	select {
	case err := <-pluginErrCh:
		if err != nil {
			logger.Error("plugin error", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		// Wait for plugin to finish shutting down
		if err := <-pluginErrCh; err != nil {
			logger.Error("plugin error during shutdown", "error", err)
		}
	}
	logger.Info("nri-image-policy stopped")
}

// startHealthServer starts an HTTP server for readiness/liveness probes.
// It shuts down gracefully when ctx is cancelled.
func startHealthServer(ctx context.Context, logger *slog.Logger, plugin *Plugin, addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if plugin.Ready() {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "ok")
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "not ready")
		}
	})

	server := &http.Server{Addr: addr, Handler: mux, ReadTimeout: *readTimeout, WriteTimeout: *writeTimeout}
	go func() {
		logger.Info("starting health server", "addr", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("health server error", "error", err)
		}
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("health server shutdown error", "error", err)
		}
	}()
}
