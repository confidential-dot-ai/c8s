package issuer

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/time/rate"
)

var (
	rateLimitRejectionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cds_rate_limit_rejections_total",
		Help: "Total requests rejected by rate limiter.",
	})

	rateLimiterEntries = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cds_rate_limiter_entries",
		Help: "Current number of entries in the rate limiter.",
	})
)

type ipLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// IPRateLimiter implements keyed rate limiting with bounded memory. Entries
// beyond MaxEntries are evicted LRU in O(n); idle entries are evicted by
// EvictionLoop at IdleTimeout. RateLimitMiddleware keys on the source address;
// RateLimitBy keys on whatever identifies the caller.
type IPRateLimiter struct {
	mu         sync.Mutex
	limiters   map[string]*ipLimiterEntry
	rate       rate.Limit
	burst      int
	maxEntries int
}

func NewIPRateLimiter(r rate.Limit, burst, maxEntries int) (*IPRateLimiter, error) {
	if maxEntries <= 0 {
		// A non-positive cap makes len(limiters) >= maxEntries always true, so
		// every new source IP evicts an existing one — the limiter would track
		// one IP globally and rate limiting would collapse across clients.
		return nil, fmt.Errorf("rate limiter maxEntries must be positive, got %d", maxEntries)
	}
	return &IPRateLimiter{
		limiters:   make(map[string]*ipLimiterEntry),
		rate:       r,
		burst:      burst,
		maxEntries: maxEntries,
	}, nil
}

func (rl *IPRateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if entry, ok := rl.limiters[ip]; ok {
		entry.lastSeen = time.Now()
		return entry.limiter
	}
	if len(rl.limiters) >= rl.maxEntries {
		var oldestIP string
		var oldestTime time.Time
		for ip, entry := range rl.limiters {
			if oldestTime.IsZero() || entry.lastSeen.Before(oldestTime) {
				oldestIP = ip
				oldestTime = entry.lastSeen
			}
		}
		if oldestIP != "" {
			delete(rl.limiters, oldestIP)
		}
	}
	lim := rate.NewLimiter(rl.rate, rl.burst)
	rl.limiters[ip] = &ipLimiterEntry{
		limiter:  lim,
		lastSeen: time.Now(),
	}
	return lim
}

// EvictionLoop removes rate limiter entries idle longer than idleTimeout.
// It blocks until ctx is cancelled.
func (rl *IPRateLimiter) EvictionLoop(ctx context.Context, interval, idleTimeout time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.evict(idleTimeout)
		}
	}
}

func (rl *IPRateLimiter) evict(idleTimeout time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-idleTimeout)
	for ip, entry := range rl.limiters {
		if entry.lastSeen.Before(cutoff) {
			delete(rl.limiters, ip)
		}
	}
	rateLimiterEntries.Set(float64(len(rl.limiters)))
}

// KeyFunc names the bucket a request is charged to. Returning "" charges it to
// the source address.
//
// Keys carry a kind prefix so two namespaces can share one limiter without a
// value in either being able to name a bucket in the other.
type KeyFunc func(*http.Request) string

// RateLimitMiddleware wraps next with per-source-IP rate limiting against rl.
// On reject it returns 429 and increments the rejection counter.
func RateLimitMiddleware(rl *IPRateLimiter, next http.Handler) http.Handler {
	return RateLimitBy(rl, nil, next)
}

// RateLimitBy wraps next, charging each request to the bucket key names.
//
// Use it where the source address is not the caller: pods reach CDS through a
// NodePort and the host-network mesh proxy, so every pod on a node presents the
// same address and one of them could exhaust the bucket every other one shares.
// A request with no identity to key on still falls back to the address, so
// nothing escapes limiting by declining to identify itself.
func RateLimitBy(rl *IPRateLimiter, key KeyFunc, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bucket := ""
		if key != nil {
			bucket = key(r)
		}
		if bucket == "" {
			bucket = SourceAddrKey(r)
		}
		if !rl.getLimiter(bucket).Allow() {
			rateLimitRejectionsTotal.Inc()
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SourceAddrKey charges a request to the address it arrived from.
func SourceAddrKey(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	return "addr:" + ip
}
