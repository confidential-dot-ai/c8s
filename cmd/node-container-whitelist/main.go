// node-container-whitelist fetches the NRI image whitelist from a whitelist API
// and serves it as a JSON HTTP endpoint.
// It periodically refreshes the whitelist in the background.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/lunal-dev/c8s/pkg/whitelist"
	"github.com/lunal-dev/c8s/pkg/whitelistclient"
)

var version = "dev"

var (
	port            = flag.Int("port", 8000, "HTTP listen port")
	whitelistURL    = flag.String("whitelist-url", "", "whitelist API base URL")
	refreshInterval = flag.Duration("refresh-interval", 300*time.Second, "whitelist refresh interval")
	maxRetries      = flag.Int("max-retries", 60, "max fetch retries on startup")
	retryDelay      = flag.Duration("retry-delay", 5*time.Second, "delay between startup retries")
	readTimeout     = flag.Duration("read-timeout", 5*time.Second, "HTTP server read timeout")
	writeTimeout    = flag.Duration("write-timeout", 10*time.Second, "HTTP server write timeout")
	fetchTimeout    = flag.Duration("fetch-timeout", 30*time.Second, "per-request timeout for whitelist fetches")
)

// server holds the cached whitelist and serves HTTP.
type server struct {
	mu sync.RWMutex
	wl *whitelist.Whitelist
}

func (s *server) get() *whitelist.Whitelist {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.wl
}

func (s *server) set(wl *whitelist.Whitelist) {
	s.mu.Lock()
	s.wl = wl
	s.mu.Unlock()
}

func fetchWhitelist(ctx context.Context, client whitelistclient.Client) (*whitelist.Whitelist, error) {
	return client.FetchWhitelist(ctx)
}

func fetchWithRetries(ctx context.Context, client whitelistclient.Client, retries int, delay time.Duration) (*whitelist.Whitelist, error) {
	var lastErr error
	for attempt := 1; attempt <= retries; attempt++ {
		fetchCtx, cancel := context.WithTimeout(ctx, *fetchTimeout)
		wl, err := fetchWhitelist(fetchCtx, client)
		cancel()
		if err == nil {
			return wl, nil
		}
		lastErr = err
		slog.Warn("fetch attempt failed", "attempt", attempt, "max", retries, "error", err)
		if attempt < retries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
	}
	return nil, fmt.Errorf("failed after %d attempts: %w", retries, lastErr)
}

func respondJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
}

func main() {
	flag.Parse()

	if *whitelistURL == "" {
		slog.Error("--whitelist-url is required")
		os.Exit(1)
	}

	slog.Info("initializing whitelist client", "url", *whitelistURL, "version", version)

	client := whitelistclient.NewClientWithHTTP(*whitelistURL, &http.Client{
		Timeout: *fetchTimeout,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	slog.Info("fetching whitelist")
	wl, err := fetchWithRetries(ctx, client, *maxRetries, *retryDelay)
	if err != nil {
		slog.Error("failed to load whitelist", "error", err)
		os.Exit(1)
	}
	slog.Info("whitelist loaded", "digests", len(wl.Digests))

	srv := &server{wl: wl}

	// Background refresh
	go func() {
		ticker := time.NewTicker(*refreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fetchCtx, fetchCancel := context.WithTimeout(ctx, *fetchTimeout)
				refreshed, err := fetchWhitelist(fetchCtx, client)
				fetchCancel()
				if err != nil {
					slog.Error("refresh failed (serving cached)", "error", err)
					continue
				}
				srv.set(refreshed)
				slog.Info("refreshed whitelist", "digests", len(refreshed.Digests))
			}
		}
	}()

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if srv.get() != nil {
			respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		} else {
			respondJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
		}
	})

	mux.HandleFunc("GET /digests", func(w http.ResponseWriter, r *http.Request) {
		wl := srv.get()
		if wl == nil {
			respondJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "whitelist not loaded"})
			return
		}
		respondJSON(w, http.StatusOK, wl)
	})

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/whitelist" {
			respondJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		wl := srv.get()
		if wl == nil {
			respondJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "whitelist not loaded"})
			return
		}
		respondJSON(w, http.StatusOK, wl)
	})

	addr := fmt.Sprintf(":%d", *port)
	httpSrv := &http.Server{Addr: addr, Handler: mux, ReadTimeout: *readTimeout, WriteTimeout: *writeTimeout}

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Info("received shutdown signal", "signal", sig)
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			slog.Error("server shutdown error", "error", err)
		}
	}()

	slog.Info("listening", "addr", addr, "refresh_interval", *refreshInterval)
	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
