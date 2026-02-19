package proxy

import (
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

type CloudflarePool struct {
	ips []string
	mu  sync.RWMutex
	rnd *rand.Rand
}

func NewCloudflarePool(ips []string) *CloudflarePool {
	return &CloudflarePool{
		ips: ips,
		rnd: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (p *CloudflarePool) UpdateIPs(ips []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ips = ips
}

func (p *CloudflarePool) GetIP() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	
	if len(p.ips) == 0 {
		return ""
	}
	
	// Random selection from the pool
	return p.ips[p.rnd.Intn(len(p.ips))]
}

func IsCloudflareDomain(host string) bool {
	host = strings.ToLower(host)
	// Common CF identifiers or provided by user preference
	// For now, simple suffix check. In real world, one might use a list of CF assigned domains
	// or rely on user enabling "Use CF Pool" flag per-rule.
	return strings.HasSuffix(host, ".cloudflare.com") || 
	       strings.HasSuffix(host, ".discord.com") ||
		   strings.HasSuffix(host, ".v2ex.com")
}

// Helper to check if an address is already an IP
func isIP(host string) bool {
	return net.ParseIP(host) != nil
}
