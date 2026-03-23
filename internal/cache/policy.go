// Package cache provides caching for the image digest whitelist.
package cache

import (
	"sync"

	"github.com/lunal-dev/c8s/pkg/whitelist"
)

// PolicyCache caches the whitelist fetched from KBS.
type PolicyCache struct {
	mu        sync.RWMutex
	whitelist *whitelist.Whitelist
}

// NewPolicyCache creates a new policy cache.
func NewPolicyCache() *PolicyCache {
	return &PolicyCache{}
}

// GetWhitelist returns the cached whitelist.
func (c *PolicyCache) GetWhitelist() *whitelist.Whitelist {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.whitelist
}

// SetWhitelist stores the whitelist in the cache.
func (c *PolicyCache) SetWhitelist(wl *whitelist.Whitelist) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.whitelist = wl
}

// Clear removes the cached whitelist. Next CreateContainer triggers a fresh KBS fetch.
func (c *PolicyCache) Clear() {
	c.SetWhitelist(nil)
}
