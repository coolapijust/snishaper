package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

type CertGenerator interface {
	GetCACert() *x509.Certificate
	GetCAKey() interface{}
	IsCAInstalled() bool
}

type ProxyServer struct {
	Server        *http.Server
	listenAddr    string
	rules         *RuleManager
	stats         *Stats
	running       bool
	mode          string // global runtime mode: "mitm" | "transparent"
	mu            sync.RWMutex
	certCacheMu   sync.RWMutex
	certCache     map[string]*tls.Certificate
	Fingerprint   string
	certGenerator CertGenerator
	recentIngress []string
	dohResolver   *DoHResolver
	cfPool        *CloudflarePool
}

type RuleManager struct {
	rules      []Rule
	siteGroups []SiteGroup
	upstreams  []Upstream
	configPath       string
	hitCount         map[string]int64
	cloudflareConfig CloudflareConfig
	mu               sync.RWMutex
}

type SiteGroup struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Website       string   `json:"website,omitempty"`
	Domains       []string `json:"domains"`
	Mode          string   `json:"mode"`
	Upstream      string   `json:"upstream"`
	Upstreams     []string `json:"upstreams,omitempty"`
	SniFake       string   `json:"sni_fake"`
	ConnectPolicy string   `json:"connect_policy,omitempty"` // "", "tunnel_origin", "tunnel_upstream", "mitm", "direct"
	SniPolicy     string   `json:"sni_policy,omitempty"`     // "", "auto", "original", "fake", "upstream", "none"
	AlpnPolicy    string   `json:"alpn_policy,omitempty"`    // "", "auto", "h1_only", "h2_h1"
	UTLSPolicy    string   `json:"utls_policy,omitempty"`    // "", "auto", "on", "off"
	Enabled       bool     `json:"enabled"`
	ECHEnabled    bool     `json:"ech_enabled"`
	ECHDomain     string   `json:"ech_domain"` // Domain used for ECH DoH lookup
	UseCFPool     bool     `json:"use_cf_pool"`
}

type Upstream struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Enabled bool   `json:"enabled"`
}

type Config struct {
	ListenPort       string           `json:"listen_port"`
	SiteGroups       []SiteGroup      `json:"site_groups"`
	Upstreams        []Upstream       `json:"upstreams"`
	CloudflareConfig CloudflareConfig `json:"cloudflare_config"`
}

type CloudflareConfig struct {
	PreferredIPs []string `json:"preferred_ips"`
	DoHURL       string   `json:"doh_url"`
}

type Stats struct {
	BytesIn  int64
	BytesOut int64
	Requests int64
	Accepted int64
	Connects int64
	mu       sync.Mutex
}

type trackingListener struct {
	net.Listener
	proxy *ProxyServer
}

func (l *trackingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if l.proxy != nil {
		l.proxy.trackAccepted(conn.RemoteAddr().String())
	}
	log.Printf("[Ingress] Accepted TCP from %s", conn.RemoteAddr())
	return conn, nil
}

type Rule struct {
	Domain        string
	Upstream      string
	Upstreams     []string
	Mode          string // "mitm", "transparent", "direct"
	SniFake       string
	ConnectPolicy string // "", "tunnel_origin", "tunnel_upstream", "mitm", "direct"
	SniPolicy     string // "", "auto", "original", "fake", "upstream", "none"
	AlpnPolicy    string // "", "auto", "h1_only", "h2_h1"
	UTLSPolicy    string // "", "auto", "on", "off"
	Enabled       bool
	SiteID        string
	ECHEnabled    bool
	ECHDomain     string
	UseCFPool     bool
}

func mergeRule(base, overlay Rule) Rule {
	out := base
	if strings.TrimSpace(overlay.Upstream) != "" {
		out.Upstream = overlay.Upstream
	}
	if len(overlay.Upstreams) > 0 {
		out.Upstreams = append([]string(nil), overlay.Upstreams...)
	}
	if strings.TrimSpace(overlay.SniFake) != "" {
		out.SniFake = overlay.SniFake
	}
	if strings.TrimSpace(overlay.ConnectPolicy) != "" {
		out.ConnectPolicy = overlay.ConnectPolicy
	}
	if strings.TrimSpace(overlay.SniPolicy) != "" {
		out.SniPolicy = overlay.SniPolicy
	}
	if strings.TrimSpace(overlay.AlpnPolicy) != "" {
		out.AlpnPolicy = overlay.AlpnPolicy
	}
	if strings.TrimSpace(overlay.UTLSPolicy) != "" {
		out.UTLSPolicy = overlay.UTLSPolicy
	}
	return out
}

type bufferedReadConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedReadConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func wrapHijackedConn(conn net.Conn, rw *bufio.ReadWriter) net.Conn {
	if rw == nil || rw.Reader == nil || rw.Reader.Buffered() == 0 {
		return conn
	}
	return &bufferedReadConn{
		Conn:   conn,
		reader: io.MultiReader(rw.Reader, conn),
	}
}

func normalizeHost(hostport string) string {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return ""
	}

	host, _, err := net.SplitHostPort(hostport)
	if err == nil {
		return strings.ToLower(strings.TrimSpace(host))
	}

	// Missing port or bracket-only IPv6 literals should still match rules.
	if strings.HasPrefix(hostport, "[") && strings.HasSuffix(hostport, "]") {
		return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]"))
	}

	return strings.ToLower(hostport)
}

func cleanWebsiteToken(token string) string {
	token = normalizeHost(token)
	token = strings.TrimPrefix(token, "*.")
	token = strings.TrimSuffix(token, "$")
	token = strings.Trim(token, "[]")
	if i := strings.Index(token, ":"); i >= 0 {
		token = token[:i]
	}
	return token
}

func tokenMatchesDomain(token, domain string) bool {
	token = cleanWebsiteToken(token)
	domain = cleanWebsiteToken(domain)
	if token == "" || domain == "" {
		return false
	}
	return token == domain || strings.HasSuffix(token, "."+domain)
}

func inferWebsiteFromSiteGroup(sg SiteGroup) string {
	tokens := []string{sg.Name, sg.Upstream, sg.SniFake}
	tokens = append(tokens, sg.Domains...)

	hasDomain := func(domains ...string) bool {
		for _, t := range tokens {
			for _, d := range domains {
				if tokenMatchesDomain(t, d) {
					return true
				}
			}
		}
		return false
	}

	switch {
	case hasDomain("google.com", "youtube.com", "gstatic.com", "googlevideo.com", "gvt1.com", "ytimg.com", "youtu.be", "ggpht.com"):
		return "google"
	case hasDomain("github.com", "githubusercontent.com", "githubassets.com", "github.io"):
		return "github"
	case hasDomain("telegram.org", "web.telegram.org", "cdn-telegram.org", "t.me", "telesco.pe", "tg.dev", "telegram.me"):
		return "telegram"
	case hasDomain("proton.me"):
		return "proton"
	case hasDomain("pixiv.net", "fanbox.cc", "pximg.net", "pixiv.org"):
		return "pixiv"
	case hasDomain("nyaa.si"):
		return "nyaa"
	case hasDomain("wikipedia.org", "wikimedia.org", "mediawiki.org", "wikibooks.org", "wikidata.org", "wikifunctions.org", "wikinews.org", "wikiquote.org", "wikisource.org", "wikiversity.org", "wikivoyage.org", "wiktionary.org"):
		return "wikipedia"
	case hasDomain("e-hentai.org", "exhentai.org", "ehgt.org", "hentaiverse.org", "ehwiki.org", "ehtracker.org"):
		return "ehentai"
	case hasDomain("facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com", "instagr.am", "ig.me", "whatsapp.com", "whatsapp.net"):
		return "meta"
	case hasDomain("twitter.com", "x.com", "t.co", "twimg.com"):
		return "x"
	case hasDomain("steamcommunity.com", "steampowered.com"):
		return "steam"
	case hasDomain("mega.nz", "mega.io", "mega.co.nz"):
		return "mega"
	case hasDomain("dailymotion.com"):
		return "dailymotion"
	case hasDomain("duckduckgo.com"):
		return "duckduckgo"
	case hasDomain("reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"):
		return "reddit"
	case hasDomain("twitch.tv"):
		return "twitch"
	case hasDomain("bbc.com", "bbc.co.uk", "bbci.co.uk"):
		return "bbc"
	}

	for _, d := range sg.Domains {
		d = cleanWebsiteToken(d)
		if d == "" || d == "off" {
			continue
		}
		parts := strings.Split(d, ".")
		if len(parts) >= 2 {
			return parts[len(parts)-2]
		}
		return d
	}

	for _, t := range tokens {
		t = cleanWebsiteToken(t)
		if t == "" || t == "off" {
			continue
		}
		parts := strings.Split(t, ".")
		if len(parts) >= 2 {
			return parts[len(parts)-2]
		}
		return t
	}
	return "misc"
}

func ensureAddrWithPort(addr, defaultPort string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}

	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		if port == "" {
			port = defaultPort
		}
		return net.JoinHostPort(host, port)
	}

	if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
		return net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]"), defaultPort)
	}

	return net.JoinHostPort(addr, defaultPort)
}

func resolveUpstreamHost(targetHost, upstream string) string {
	upstream = strings.TrimSpace(upstream)
	if upstream == "" {
		return ""
	}
	if strings.Contains(upstream, "$1") {
		firstLabel := targetHost
		if i := strings.Index(firstLabel, "."); i > 0 {
			firstLabel = firstLabel[:i]
		}
		upstream = strings.ReplaceAll(upstream, "$1", firstLabel)
	}
	return upstream
}

func resolveRuleUpstream(targetHost string, rule Rule) string {
	resolved := resolveUpstreamHost(targetHost, rule.Upstream)
	trimmed := strings.TrimSpace(resolved)
	if trimmed == "" && len(rule.Upstreams) > 0 {
		return strings.Join(rule.Upstreams, ",")
	}

	low := strings.ToLower(trimmed)
	if strings.HasPrefix(low, "$backend_ip") || strings.HasPrefix(low, "$upstream_host") || strings.HasPrefix(trimmed, "$") {
		if len(rule.Upstreams) > 0 {
			return strings.Join(rule.Upstreams, ",")
		}
		return net.JoinHostPort(targetHost, "443")
	}

	return resolved
}

func splitUpstreamCandidates(targetHost, upstream, defaultPort string) []string {
	resolved := resolveUpstreamHost(targetHost, upstream)
	if resolved == "" {
		return nil
	}
	parts := strings.Split(resolved, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		addr := ensureAddrWithPort(strings.TrimSpace(p), defaultPort)
		if addr == "" {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out
}

func firstUpstreamHost(targetHost, upstream string) string {
	candidates := splitUpstreamCandidates(targetHost, upstream, "443")
	if len(candidates) == 0 {
		return ""
	}
	host, _, err := net.SplitHostPort(candidates[0])
	if err != nil {
		return normalizeHost(candidates[0])
	}
	return normalizeHost(host)
}

func hostMatchesDomain(host, domain string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if host == "" || domain == "" {
		return false
	}
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, "$")

	// Extended pattern syntax: google.com.* (or any base.*)
	// Matches google.com.sg, www.google.com.sg, google.com.hk, etc.
	if strings.HasSuffix(domain, ".*") {
		base := strings.TrimSuffix(domain, ".*")
		if base == "" {
			return false
		}
		hostParts := strings.Split(host, ".")
		baseParts := strings.Split(base, ".")
		if len(hostParts) < len(baseParts)+1 {
			return false
		}
		for i := 0; i+len(baseParts) < len(hostParts); i++ {
			ok := true
			for j := 0; j < len(baseParts); j++ {
				if hostParts[i+j] != baseParts[j] {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
		return false
	}

	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}

func domainMatchScore(host, domain string) int {
	host = strings.ToLower(strings.TrimSpace(host))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if host == "" || domain == "" {
		return -1
	}

	if strings.HasPrefix(domain, "~") {
		pattern := strings.TrimSpace(strings.TrimPrefix(domain, "~"))
		if pattern == "" {
			return -1
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return -1
		}
		if re.MatchString(host) {
			return 900 + len(pattern) // exact(1000+) > regex(900+) > suffix/exact-domain
		}
		return -1
	}

	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, "$")

	// Pattern base.* => give base length score when matched.
	if strings.HasSuffix(domain, ".*") {
		base := strings.TrimSuffix(domain, ".*")
		if base == "" {
			return -1
		}
		hostParts := strings.Split(host, ".")
		baseParts := strings.Split(base, ".")
		if len(hostParts) < len(baseParts)+1 {
			return -1
		}
		for i := 0; i+len(baseParts) < len(hostParts); i++ {
			ok := true
			for j := 0; j < len(baseParts); j++ {
				if hostParts[i+j] != baseParts[j] {
					ok = false
					break
				}
			}
			if ok {
				return len(base)
			}
		}
		return -1
	}

	if host == domain {
		return len(domain) + 1000 // Prefer exact match over suffix match.
	}
	if strings.HasSuffix(host, "."+domain) {
		return len(domain)
	}
	return -1
}

func isLiteralIP(host string) bool {
	return net.ParseIP(strings.Trim(host, "[]")) != nil
}

func chooseUpstreamSNI(targetHost string, rule Rule) string {
	targetHost = normalizeHost(targetHost)
	hostAsToken := strings.Trim(targetHost, "[]")
	hostAsToken = strings.ReplaceAll(hostAsToken, ".", "-")
	hostAsToken = strings.ReplaceAll(hostAsToken, ":", "-")
	hostAsToken = strings.TrimSpace(hostAsToken)
	if hostAsToken == "" {
		hostAsToken = "g-cn"
	}
	resolvedUpstream := resolveRuleUpstream(targetHost, rule)

	switch strings.ToLower(strings.TrimSpace(rule.SniPolicy)) {
	case "none":
		// Explicitly disable SNI extension for upstream TLS ClientHello.
		return ""
	case "original":
		return targetHost
	case "fake":
		if strings.TrimSpace(rule.SniFake) != "" {
			return rule.SniFake
		}
		return hostAsToken
	case "upstream":
		if upstreamHost := firstUpstreamHost(targetHost, resolvedUpstream); upstreamHost != "" && !isLiteralIP(upstreamHost) {
			return upstreamHost
		}
		return targetHost
	}

	// MITM mode's core behavior: if fake SNI is configured, always use it.
	if strings.TrimSpace(rule.SniFake) != "" {
		return rule.SniFake
	}
	if resolvedUpstream != "" {
		if upstreamHost := firstUpstreamHost(targetHost, resolvedUpstream); upstreamHost != "" {
			if !isLiteralIP(upstreamHost) && upstreamHost != targetHost {
				return upstreamHost
			}
		}
	}
	// Auto mode should be predictable: when no fake/upstream SNI is available,
	// fall back to original host instead of implicit camouflage.
	return targetHost
}

func NewProxyServer(addr string) *ProxyServer {
	return &ProxyServer{
		listenAddr:  addr,
		rules:       &RuleManager{},
		stats:       &Stats{},
		mode:        "mitm",
		certCache:   map[string]*tls.Certificate{},
		Fingerprint: "Chrome",
		dohResolver: NewDoHResolver(""),
		cfPool:      NewCloudflarePool([]string{}),
	}
}

func (p *ProxyServer) SetRuleManager(rm *RuleManager) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = rm
}

func (p *ProxyServer) SetCertGenerator(cg CertGenerator) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.certGenerator = cg
}

func (p *ProxyServer) UpdateCloudflareConfig(cfg CloudflareConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.dohResolver != nil {
		p.dohResolver.ServerURL = cfg.DoHURL
		if p.dohResolver.ServerURL == "" {
			p.dohResolver.ServerURL = "https://223.5.5.5/dns-query"
		}
	}
	if p.cfPool != nil {
		p.cfPool.UpdateIPs(cfg.PreferredIPs)
	}
}

func (p *ProxyServer) SetListenAddr(addr string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return fmt.Errorf("cannot change address while proxy is running")
	}
	p.listenAddr = addr
	return nil
}

func (p *ProxyServer) GetListenAddr() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.listenAddr
}

func (p *ProxyServer) SetMode(mode string) error {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "mitm" && mode != "transparent" {
		return fmt.Errorf("invalid proxy mode: %s", mode)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mode = mode
	return nil
}

func (p *ProxyServer) GetMode() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.mode
}

func (p *ProxyServer) Start() error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return nil
	}

	srv := &http.Server{
		Addr: p.listenAddr,
		// Use raw handler instead of ServeMux: CONNECT uses authority-form
		// and may not be routed by path-based muxes.
		Handler:      http.HandlerFunc(p.handleRequest),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	listenAddr := p.listenAddr
	p.mu.Unlock()

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	p.mu.Lock()
	// Re-check state in case Stop/Start race happened while binding.
	if p.running {
		p.mu.Unlock()
		_ = ln.Close()
		return nil
	}
	p.Server = srv
	p.running = true
	p.mu.Unlock()

	go func() {
		log.Printf("[Proxy] Server started on %s", listenAddr)
		tl := &trackingListener{
			Listener: ln,
			proxy:    p,
		}
		if err := srv.Serve(tl); err != nil && err != http.ErrServerClosed {
			log.Printf("[Proxy] Server error: %v", err)
		}
		p.mu.Lock()
		if p.Server == srv {
			p.running = false
		}
		p.mu.Unlock()
	}()

	return nil
}

func (p *ProxyServer) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return nil
	}
	p.running = false
	if p.Server != nil {
		return p.Server.Close()
	}
	return nil
}

func (p *ProxyServer) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.running
}

func (p *ProxyServer) handleRequest(w http.ResponseWriter, req *http.Request) {
	p.stats.mu.Lock()
	p.stats.Requests++
	p.stats.mu.Unlock()

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	matchHost := normalizeHost(host)
	mode := p.GetMode()
	rule := p.rules.matchRule(matchHost, mode)
	if rule.SiteID != "" {
		p.rules.incrementRuleHit(rule.SiteID)
	}

	log.Printf("[Proxy] Request: %s -> %s (match: %s, runtime-mode: %s, rule-mode: %s)", req.Method, host, matchHost, mode, rule.Mode)

	switch req.Method {
	case http.MethodConnect:
		p.handleConnect(w, req, rule)
	default:
		p.handleHTTP(w, req, rule)
	}
}

func (p *ProxyServer) handleConnect(w http.ResponseWriter, req *http.Request, rule Rule) {
	p.stats.mu.Lock()
	p.stats.Connects++
	p.stats.mu.Unlock()

	targetAuthority := req.URL.Host
	if targetAuthority == "" {
		targetAuthority = req.Host
	}
	targetHost := normalizeHost(targetAuthority)
	targetAddr := ensureAddrWithPort(targetAuthority, "443")
	effectiveMode := rule.Mode
	resolvedUpstream := resolveRuleUpstream(targetHost, rule)

	switch strings.ToLower(strings.TrimSpace(rule.ConnectPolicy)) {
	case "tunnel_origin":
		effectiveMode = "transparent"
		resolvedUpstream = ""
	case "tunnel_upstream":
		effectiveMode = "transparent"
	case "mitm":
		effectiveMode = "mitm"
	case "direct":
		effectiveMode = "direct"
		resolvedUpstream = ""
	}

	// Stage-2 match: if stage-1 produced a dynamic upstream host (eg. *.gvt1.com),
	// allow that upstream host to hit another rule and override policies.
	if (effectiveMode == "mitm" || effectiveMode == "transparent") && strings.TrimSpace(resolvedUpstream) != "" {
		upHost := firstUpstreamHost(targetHost, resolvedUpstream)
		if upHost != "" {
			upRule := p.rules.matchRule(upHost, effectiveMode)
			if upRule.SiteID != "" {
				baseSite := rule.SiteID
				rule = mergeRule(rule, upRule)
				if strings.TrimSpace(rule.Upstream) != "" {
					resolvedUpstream = resolveRuleUpstream(upHost, rule)
				}
				log.Printf("[Connect] Stage-2 upstream rule applied: host=%s site=%s over base=%s", upHost, upRule.SiteID, baseSite)
			}
		}
	}

	log.Printf("[Connect] target=%s host=%s mode=%s->%s upstream=%s sni_fake=%s", targetAddr, targetHost, rule.Mode, effectiveMode, resolvedUpstream, rule.SniFake)

	// 对于 direct 模式，直接连接目标
	if effectiveMode == "direct" {
		p.directConnect(w, req)
		return
	}

	var conn net.Conn
	var err error
	dialAddr := targetAddr
	dialCandidates := []string{dialAddr}

	// For MITM/transparent rules, upstream should be respected if configured.
	if (effectiveMode == "mitm" || effectiveMode == "transparent") && strings.TrimSpace(resolvedUpstream) != "" {
		dialCandidates = splitUpstreamCandidates(targetHost, resolvedUpstream, "443")
		if len(dialCandidates) == 0 {
			dialCandidates = []string{targetAddr}
		}
		dialAddr = dialCandidates[0]
		log.Printf("[Connect] Using upstream candidates %v for host %s (mode: %s)", dialCandidates, targetHost, effectiveMode)
	}

	// Cloudflare Preferred IP Pool integration
	if rule.UseCFPool && p.cfPool != nil {
		if preferred := p.cfPool.GetIP(); preferred != "" {
			preferredAddr := net.JoinHostPort(preferred, "443")
			// Prepend preferred IP to candidates
			dialCandidates = append([]string{preferredAddr}, dialCandidates...)
			dialAddr = preferredAddr
			log.Printf("[Connect] Using preferred Cloudflare IP: %s for %s", preferred, targetHost)
		}
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	// Parallel Dialing (Racing)
	if len(dialCandidates) > 1 {
		type dialResult struct {
			conn net.Conn
			err  error
			addr string
		}
		resChan := make(chan dialResult, len(dialCandidates))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		for _, addr := range dialCandidates {
			go func(target string) {
				d := &net.Dialer{Timeout: 5 * time.Second}
				c, e := d.DialContext(ctx, "tcp", target)
				select {
				case resChan <- dialResult{c, e, target}:
					if e == nil {
						cancel()
					}
				case <-ctx.Done():
					if c != nil {
						c.Close()
					}
				}
			}(addr)
			time.Sleep(50 * time.Millisecond)
		}

		for i := 0; i < len(dialCandidates); i++ {
			r := <-resChan
			if r.err == nil {
				conn = r.conn
				dialAddr = r.addr
				log.Printf("[Connect] Parallel dial winner: %s", dialAddr)
				break
			}
			err = r.err
		}
	} else {
		for _, candidate := range dialCandidates {
			conn, err = dialer.Dial("tcp", candidate)
			if err == nil {
				dialAddr = candidate
				break
			}
			log.Printf("[Connect] Connect failed to %s: %v", candidate, err)
		}
	}
	if err != nil || conn == nil {
		http.Error(w, "Failed to connect to upstream", http.StatusBadGateway)
		log.Printf("[Connect] All upstream connect attempts failed: %v", dialCandidates)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijack not supported", http.StatusInternalServerError)
		conn.Close()
		return
	}

	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		log.Printf("[Connect] Hijack failed: %v", err)
		conn.Close()
		return
	}
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		log.Printf("[Connect] Write 200 failed: %v", err)
		clientConn.Close()
		conn.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		log.Printf("[Connect] Flush 200 failed: %v", err)
		clientConn.Close()
		conn.Close()
		return
	}
	clientConn = wrapHijackedConn(clientConn, rw)
	_ = clientConn.SetDeadline(time.Time{})
	_ = conn.SetDeadline(time.Time{})

	// 注意：不要在 hijack 后使用 defer，因为我们需要保持连接打开
	if effectiveMode == "mitm" {
		p.handleMITM(clientConn, conn, targetHost, rule, dialCandidates, dialAddr)
	} else {
		p.handleTransparent(clientConn, conn, targetHost, rule)
	}
}

func (p *ProxyServer) directConnect(w http.ResponseWriter, req *http.Request) {
	targetAuthority := req.URL.Host
	if targetAuthority == "" {
		targetAuthority = req.Host
	}
	targetAddr := ensureAddrWithPort(targetAuthority, "443")

	log.Printf("[Direct] Connecting to %s", targetAddr)

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		http.Error(w, "Failed to connect", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijack not supported", http.StatusInternalServerError)
		conn.Close()
		return
	}

	clientConn, rw, err := hijacker.Hijack()
	if err != nil {
		conn.Close()
		return
	}
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		clientConn.Close()
		conn.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		clientConn.Close()
		conn.Close()
		return
	}
	clientConn = wrapHijackedConn(clientConn, rw)
	_ = clientConn.SetDeadline(time.Time{})
	_ = conn.SetDeadline(time.Time{})

	// 双向复制数据
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(conn, clientConn)
		p.stats.mu.Lock()
		p.stats.BytesOut += n
		p.stats.mu.Unlock()
		conn.Close()
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(clientConn, conn)
		p.stats.mu.Lock()
		p.stats.BytesIn += n
		p.stats.mu.Unlock()
		clientConn.Close()
	}()
	wg.Wait()
}

func (p *ProxyServer) handleHTTP(w http.ResponseWriter, req *http.Request, rule Rule) {
	// 创建新的请求，避免修改原始请求
	newReq := req.Clone(req.Context())
	newReq.RequestURI = ""
	newReq.Header.Del("Proxy-Connection")

	if newReq.URL.Scheme == "" {
		if req.TLS != nil {
			newReq.URL.Scheme = "https"
		} else {
			newReq.URL.Scheme = "http"
		}
	}
	if newReq.URL.Host == "" {
		newReq.URL.Host = req.Host
	}
	if newReq.Host == "" {
		newReq.Host = req.Host
	}
	if newReq.Host == "" {
		newReq.Host = newReq.URL.Host
	}

	if rule.Mode == "direct" {
		// 直接转发请求
		transport := &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}

		resp, err := transport.RoundTrip(newReq)
		if err != nil {
			log.Printf("[HTTP] Direct proxy failed: %v", err)
			http.Error(w, "Failed to proxy", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// 复制响应头
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return
	}

	if rule.Upstream != "" {
		defaultPort := "80"
		if strings.EqualFold(newReq.URL.Scheme, "https") {
			defaultPort = "443"
		}
		candidates := splitUpstreamCandidates(normalizeHost(newReq.Host), rule.Upstream, defaultPort)
		if len(candidates) > 0 {
			newReq.URL.Host = candidates[0]
		}
	}

	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	resp, err := transport.RoundTrip(newReq)
	if err != nil {
		log.Printf("[HTTP] HTTPS proxy failed: %v", err)
		http.Error(w, "Failed to proxy", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 复制响应头
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)
	p.stats.mu.Lock()
	p.stats.BytesIn += n
	p.stats.mu.Unlock()
}

func (p *ProxyServer) handleMITM(clientConn, upstreamConn net.Conn, host string, rule Rule, dialCandidates []string, initialDialAddr string) {
	log.Printf("[MITM] Handling %s with SNI: %s", host, rule.SniFake)

	if p.certGenerator == nil {
		log.Printf("[MITM] No cert generator, falling back to direct")
		p.directTunnel(clientConn, upstreamConn)
		return
	}

	caCert := p.certGenerator.GetCACert()
	caKey := p.certGenerator.GetCAKey()
	if caCert == nil || caKey == nil {
		log.Printf("[MITM] CA cert/key not available")
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	cert, err := p.generateCert(host, caCert, caKey)
	if err != nil {
		log.Printf("[MITM] Failed to generate cert: %v", err)
		clientConn.Close()
		upstreamConn.Close()
		return
	}

	alpnPolicy := strings.ToLower(strings.TrimSpace(rule.AlpnPolicy))
	clientNextProtos := []string{"h2", "http/1.1"}
	if alpnPolicy == "h1_only" {
		clientNextProtos = []string{"http/1.1"}
	}
	if alpnPolicy == "h2_h1" {
		clientNextProtos = []string{"h2", "http/1.1"}
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   clientNextProtos,
	}

	clientTls := tls.Server(clientConn, tlsConfig)
	if err := clientTls.Handshake(); err != nil {
		log.Printf("[MITM] Client TLS handshake failed: %v", err)
		clientConn.Close()
		upstreamConn.Close()
		return
	}
	clientALPN := clientTls.ConnectionState().NegotiatedProtocol

	sniHost := chooseUpstreamSNI(host, rule)
	log.Printf("[MITM] Upstream handshake SNI selected: %s, client ALPN: %s", sniHost, clientALPN)

	orderedCandidates := make([]string, 0, len(dialCandidates))
	if strings.TrimSpace(initialDialAddr) != "" {
		orderedCandidates = append(orderedCandidates, initialDialAddr)
	}
	for _, c := range dialCandidates {
		if strings.TrimSpace(c) == "" || c == initialDialAddr {
			continue
		}
		orderedCandidates = append(orderedCandidates, c)
	}
	if len(orderedCandidates) == 0 {
		orderedCandidates = append(orderedCandidates, net.JoinHostPort(host, "443"))
	}

	var upstreamRW io.ReadWriteCloser
	var lastErr error
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	utlsPolicy := strings.ToLower(strings.TrimSpace(rule.UTLSPolicy))
	sniPolicy := strings.ToLower(strings.TrimSpace(rule.SniPolicy))
	effectiveFakeSNI := strings.TrimSpace(rule.SniFake) != "" || (sniPolicy == "fake" && strings.TrimSpace(sniHost) != "" && !strings.EqualFold(strings.TrimSpace(sniHost), strings.TrimSpace(host)))

	for idx, candidate := range orderedCandidates {
		var rawConn net.Conn
		var err error
		// Parallel Dialing (Racing)
		// If multiple candidates, try them in parallel with a slight delay (Happy Eyeballs style)
		// For now, simpler implementation: if more than 1 candidate, use a racing helper.
		if len(orderedCandidates) > 1 {
			type dialResult struct {
				conn net.Conn
				err  error
				addr string
			}
			resChan := make(chan dialResult, len(orderedCandidates))
			ctx, cancel := context.WithCancel(context.Background())
			
			for _, addr := range orderedCandidates {
				go func(target string) {
					d := &net.Dialer{Timeout: 5 * time.Second}
					c, e := d.DialContext(ctx, "tcp", target)
					select {
					case resChan <- dialResult{c, e, target}:
						if e == nil {
							cancel() // Stop others if we won
						}
					case <-ctx.Done():
						if c != nil {
							c.Close()
						}
					}
				}(addr)
				// Slight delay before launching the next one to prefer order but minimize total wait
				time.Sleep(50 * time.Millisecond)
			}

			var winner dialResult
			count := 0
			for i := 0; i < len(orderedCandidates); i++ {
				r := <-resChan
				count++
				if r.err == nil {
					winner = r
					break
				}
				lastErr = r.err
			}
			cancel() // Final cleanup
			
			if winner.conn != nil {
				rawConn = winner.conn
				candidate = winner.addr
				log.Printf("[MITM] Parallel dial winner: %s", candidate)
			} else {
				break // All failed
			}
		} else {
			// Single candidate logic
			if idx == 0 && upstreamConn != nil && candidate == initialDialAddr {
				rawConn = upstreamConn
			} else {
				rawConn, err = dialer.Dial("tcp", candidate)
				if err != nil {
					lastErr = err
					log.Printf("[MITM] Upstream dial failed %s: %v", candidate, err)
					continue
				}
			}
		}
		
		_ = rawConn.SetDeadline(time.Time{})

		useUTLS := false
		switch utlsPolicy {
		case "off":
			useUTLS = false
		case "on":
			useUTLS = true
		default: // auto / empty
			useUTLS = effectiveFakeSNI
		}

		if useUTLS {
			upstreamALPN := strings.TrimSpace(clientALPN)
			if upstreamALPN == "" {
				upstreamALPN = "http/1.1"
			}

			var echConfig []byte
			if rule.ECHEnabled && p.dohResolver != nil {
				// Use ECHDomain if configured, otherwise use original host
				echLookupDomain := rule.ECHDomain
				if echLookupDomain == "" {
					echLookupDomain = host
				}
				log.Printf("[MITM] Attempting ECH fetch for %s (using %s)", host, echLookupDomain)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if val, err := p.dohResolver.ResolveECH(ctx, echLookupDomain); err == nil {
					echConfig = val
					log.Printf("[MITM] ECH config fetched successfully (%d bytes)", len(echConfig))
				} else {
					log.Printf("[MITM] ECH fetch failed: %v", err)
				}
				cancel()
			}

			// If ECH is enabled and config is present/tried, allow uTLS to handle outer SNI.
			// The ServerName given to uTLS MUST be the real target (Inner SNI).
			// If we kept `sniHost` as `linux-do` (from fake policy), ECH would imply `linux-do` as the standard SNI, which fails.
			targetSNI := sniHost
			if len(echConfig) > 0 {
				targetSNI = host
			}

			uconn := p.GetUConn(rawConn, targetSNI, true, upstreamALPN, echConfig)
			if err := uconn.Handshake(); err == nil {
				negotiated := uconn.ConnectionState().NegotiatedProtocol
				if upstreamALPN != "" && negotiated != upstreamALPN {
					lastErr = fmt.Errorf("utls alpn mismatch want=%s got=%s", upstreamALPN, negotiated)
					log.Printf("[MITM] Upstream uTLS ALPN mismatch on %s: want=%s got=%s", candidate, upstreamALPN, negotiated)
					_ = uconn.Close()
				} else {
					log.Printf("[MITM] Upstream (uTLS) negotiated ALPN: %s via %s", negotiated, candidate)
					upstreamRW = uconn
					break
				}
			} else {
				lastErr = err
				log.Printf("[MITM] Upstream uTLS handshake failed on %s: %v", candidate, err)
			}
		}

		if upstreamRW == nil {
			upTLSConfig := &tls.Config{
				ServerName:         sniHost,
				InsecureSkipVerify: true,
			}
			switch alpnPolicy {
			case "h1_only":
				upTLSConfig.NextProtos = []string{"http/1.1"}
			case "h2_h1":
				upTLSConfig.NextProtos = []string{"h2", "http/1.1"}
			default:
				if strings.TrimSpace(clientALPN) != "" {
					upTLSConfig.NextProtos = []string{clientALPN}
				} else {
					upTLSConfig.NextProtos = []string{"http/1.1"}
				}
			}
			upstreamTLS := tls.Client(rawConn, upTLSConfig)
			if err := upstreamTLS.Handshake(); err != nil {
				lastErr = err
				log.Printf("[MITM] Upstream TLS handshake failed on %s: %v", candidate, err)
				_ = rawConn.Close()
				continue
			}
			log.Printf("[MITM] Upstream (std TLS) negotiated ALPN: %s via %s", upstreamTLS.ConnectionState().NegotiatedProtocol, candidate)
			upstreamRW = upstreamTLS
			break
		}
	}

	if upstreamRW == nil {
		log.Printf("[MITM] No usable upstream candidate, last err: %v", lastErr)
		clientTls.Close()
		if upstreamConn != nil {
			upstreamConn.Close()
		}
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(upstreamRW, clientTls)
		p.stats.mu.Lock()
		p.stats.BytesOut += n
		p.stats.mu.Unlock()
		upstreamRW.Close()
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(clientTls, upstreamRW)
		p.stats.mu.Lock()
		p.stats.BytesIn += n
		p.stats.mu.Unlock()
		clientTls.Close()
	}()
	wg.Wait()
}

func (p *ProxyServer) directTunnel(clientConn, upstreamConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		n, _ := io.Copy(upstreamConn, clientConn)
		p.stats.mu.Lock()
		p.stats.BytesOut += n
		p.stats.mu.Unlock()
		upstreamConn.Close()
	}()
	go func() {
		defer wg.Done()
		n, _ := io.Copy(clientConn, upstreamConn)
		p.stats.mu.Lock()
		p.stats.BytesIn += n
		p.stats.mu.Unlock()
		clientConn.Close()
	}()
	wg.Wait()
}

func (p *ProxyServer) generateCert(host string, caCert *x509.Certificate, caKey interface{}) (*tls.Certificate, error) {
	host = normalizeHost(host)
	p.certCacheMu.RLock()
	if cert, ok := p.certCache[host]; ok && cert != nil {
		p.certCacheMu.RUnlock()
		return cert, nil
	}
	p.certCacheMu.RUnlock()

	serial := big.NewInt(time.Now().UnixNano())
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host},
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	
	keyBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	p.certCacheMu.Lock()
	p.certCache[host] = &cert
	p.certCacheMu.Unlock()
	return &cert, nil
}

func (p *ProxyServer) handleTransparent(clientConn, upstreamConn net.Conn, host string, rule Rule) {
	// Transparent mode should forward raw TLS bytes without terminating TLS.
	// Terminating TLS here would require MITM on the client side as well.
	log.Printf("[Transparent] Tunneling %s -> %s (raw TCP)", host, rule.Upstream)
	p.directTunnel(clientConn, upstreamConn)
}

func (r *RuleManager) SetRules(rules []Rule) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = rules
}

func (r *RuleManager) matchRule(host, mode string) Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	host = normalizeHost(host)
	mode = strings.ToLower(strings.TrimSpace(mode))
	best := Rule{}
	bestScore := -1
	for _, rule := range r.rules {
		if !rule.Enabled {
			continue
		}
		// Enforce global runtime mode so UI mode switch actually changes traffic handling.
		if mode == "mitm" || mode == "transparent" {
			if rule.Mode != mode {
				continue
			}
		}
		score := domainMatchScore(host, rule.Domain)
		if score >= 0 && score > bestScore {
			best = rule
			bestScore = score
		}
	}
	if bestScore >= 0 {
		return best
	}

	return Rule{Mode: "direct", Enabled: true}
}

func (p *ProxyServer) GetStats() (int64, int64, int64) {
	p.stats.mu.Lock()
	defer p.stats.mu.Unlock()
	return p.stats.BytesIn, p.stats.BytesOut, p.stats.Requests
}

func (p *ProxyServer) trackAccepted(remote string) {
	p.stats.mu.Lock()
	p.stats.Accepted++
	p.stats.mu.Unlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.recentIngress) >= 10 {
		p.recentIngress = p.recentIngress[1:]
	}
	p.recentIngress = append(p.recentIngress, remote)
}

func (p *ProxyServer) GetDiagnostics() (int64, int64, int64, []string) {
	p.stats.mu.Lock()
	accepted := p.stats.Accepted
	requests := p.stats.Requests
	connects := p.stats.Connects
	p.stats.mu.Unlock()

	p.mu.RLock()
	recent := append([]string(nil), p.recentIngress...)
	p.mu.RUnlock()
	return accepted, requests, connects, recent
}

func NewRuleManager(configPath string) *RuleManager {
	return &RuleManager{
		configPath: configPath,
		rules:      []Rule{},
		hitCount:   map[string]int64{},
	}
}

func (rm *RuleManager) LoadConfig() error {
	data, err := os.ReadFile(rm.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return rm.saveDefaultConfig()
		}
		return err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	rm.siteGroups = config.SiteGroups
	rm.upstreams = config.Upstreams
	rm.cloudflareConfig = config.CloudflareConfig

	// Sync Cloudflare Config if ProxyServer is linked
	// Note: In current architecture, RuleManager doesn't have a back-pointer to ProxyServer.
	// ProxyServer.SetRuleManager is used. We might need to update ProxyServer's pool elsewhere.
	// But actually, ProxyServer holds the pool, so when LoadConfig is called via the RuleManager
	// inside ProxyServer, it should be updated.
	// Wait, ProxyServer has a pointer to RuleManager.

	migrated := false
	for i := range rm.siteGroups {
		rm.siteGroups[i].Website = strings.TrimSpace(rm.siteGroups[i].Website)
		if rm.siteGroups[i].Website == "" {
			rm.siteGroups[i].Website = inferWebsiteFromSiteGroup(rm.siteGroups[i])
			migrated = true
		}
	}

	rm.buildRules()
	if migrated {
		if err := rm.saveConfig(); err != nil {
			log.Printf("[Config] migrate website field failed: %v", err)
		} else {
			log.Printf("[Config] migrated website field for existing site groups")
		}
	}
	return nil
}

func (rm *RuleManager) saveDefaultConfig() error {
	siteGroups, upstreams, err := loadEmbeddedRules()
	if err != nil {
		return err
	}

	rm.siteGroups = siteGroups
	rm.upstreams = upstreams
	rm.buildRules()

	return rm.saveConfig()
}

func loadEmbeddedRules() ([]SiteGroup, []Upstream, error) {
	var siteGroups []SiteGroup
	var upstreams []Upstream

	execPath := os.Args[0]
	if filepath.IsAbs(execPath) == false {
		var err error
		execPath, err = os.Executable()
		if err != nil {
			execPath = os.Args[0]
		}
	}
	execDir := filepath.Dir(execPath)

	ruleFiles := []string{
		filepath.Join(execDir, "rules", "mitm.json"),
		filepath.Join(execDir, "rules", "transparent.json"),
	}

	log.Printf("[Config] Searching for rules in: %s", execDir)

	for _, file := range ruleFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			log.Printf("[Config] Cannot read rule file: %s, err: %v", file, err)
			continue
		}

		var configFile ConfigFile
		if err := json.Unmarshal(data, &configFile); err != nil {
			log.Printf("[Config] Failed to parse %s: %v", file, err)
			continue
		}

		log.Printf("[Config] Loaded rule file: %s, found %d rules", file, len(configFile.Rules))

		for _, rule := range configFile.Rules {
			sg := SiteGroup{
				ID:            generateID(),
				Name:          rule.Name,
				Website:       strings.TrimSpace(rule.Website),
				Domains:       rule.Domains,
				Mode:          configFile.Type,
				Upstream:      rule.Upstream,
				Upstreams:     append([]string(nil), rule.Upstreams...),
				SniFake:       rule.SniFake,
				ConnectPolicy: strings.ToLower(strings.TrimSpace(rule.ConnectPolicy)),
				SniPolicy:     strings.ToLower(strings.TrimSpace(rule.SniPolicy)),
				AlpnPolicy:    strings.ToLower(strings.TrimSpace(rule.AlpnPolicy)),
				UTLSPolicy:    strings.ToLower(strings.TrimSpace(rule.UTLSPolicy)),
				Enabled:       rule.Enabled,
			}
			siteGroups = append(siteGroups, sg)
		}
	}

	if len(siteGroups) == 0 {
		return nil, nil, fmt.Errorf("no embedded rules found")
	}

	// No hardcoded upstream fallback. All upstream selection must be rule-driven.
	upstreams = []Upstream{}

	log.Printf("[Config] Loaded %d rules from embedded files", len(siteGroups))
	return siteGroups, upstreams, nil
}

func (rm *RuleManager) buildRules() {
	rm.rules = []Rule{}
	for _, sg := range rm.siteGroups {
		if !sg.Enabled {
			continue
		}
		for _, domain := range sg.Domains {
			rule := Rule{
				Domain:        domain,
				Mode:          sg.Mode,
				Upstream:      sg.Upstream,
				Upstreams:     append([]string(nil), sg.Upstreams...),
				SniFake:       sg.SniFake,
				ConnectPolicy: strings.TrimSpace(sg.ConnectPolicy),
				SniPolicy:     strings.TrimSpace(sg.SniPolicy),
				AlpnPolicy:    strings.TrimSpace(sg.AlpnPolicy),
				UTLSPolicy:    strings.TrimSpace(sg.UTLSPolicy),
				Enabled:       true,
				SiteID:        sg.ID,
				ECHEnabled:    sg.ECHEnabled,
				ECHDomain:     sg.ECHDomain,
				UseCFPool:     sg.UseCFPool,
			}
			rm.rules = append(rm.rules, rule)
		}
	}
}

func (rm *RuleManager) incrementRuleHit(siteID string) {
	if siteID == "" {
		return
	}
	rm.mu.Lock()
	rm.hitCount[siteID]++
	rm.mu.Unlock()
}

func (rm *RuleManager) GetRuleHitCounts() map[string]int64 {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	out := make(map[string]int64, len(rm.hitCount))
	for k, v := range rm.hitCount {
		out[k] = v
	}
	return out
}

func (rm *RuleManager) GetSiteGroups() []SiteGroup {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.siteGroups
}

func (rm *RuleManager) GetCloudflareConfig() CloudflareConfig {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.cloudflareConfig
}

func (rm *RuleManager) UpdateCloudflareConfig(cfg CloudflareConfig) error {
	rm.mu.Lock()
	rm.cloudflareConfig = cfg
	rm.mu.Unlock()
	return rm.saveConfig()
}

func (rm *RuleManager) AddSiteGroup(sg SiteGroup) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	sg.ID = generateID()
	sg.Website = strings.TrimSpace(sg.Website)
	rm.siteGroups = append(rm.siteGroups, sg)
	rm.buildRules()
	return rm.saveConfig()
}

func (rm *RuleManager) UpdateSiteGroup(sg SiteGroup) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	sg.Website = strings.TrimSpace(sg.Website)
	for i, s := range rm.siteGroups {
		if s.ID == sg.ID {
			rm.siteGroups[i] = sg
			break
		}
	}
	rm.buildRules()
	return rm.saveConfig()
}

func (rm *RuleManager) DeleteSiteGroup(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, s := range rm.siteGroups {
		if s.ID == id {
			rm.siteGroups = append(rm.siteGroups[:i], rm.siteGroups[i+1:]...)
			break
		}
	}
	rm.buildRules()
	return rm.saveConfig()
}

func (rm *RuleManager) GetUpstreams() []Upstream {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.upstreams
}

func (rm *RuleManager) AddUpstream(u Upstream) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	u.ID = generateID()
	rm.upstreams = append(rm.upstreams, u)
	return rm.saveConfig()
}

func (rm *RuleManager) UpdateUpstream(u Upstream) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, up := range rm.upstreams {
		if up.ID == u.ID {
			rm.upstreams[i] = u
			break
		}
	}
	return rm.saveConfig()
}

func (rm *RuleManager) DeleteUpstream(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	for i, up := range rm.upstreams {
		if up.ID == id {
			rm.upstreams = append(rm.upstreams[:i], rm.upstreams[i+1:]...)
			break
		}
	}
	return rm.saveConfig()
}

func (rm *RuleManager) saveConfig() error {
	config := Config{
		ListenPort:       "8080",
		SiteGroups:       rm.siteGroups,
		Upstreams:        rm.upstreams,
		CloudflareConfig: rm.cloudflareConfig,
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(rm.configPath, data, 0644)
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

func (p *ProxyServer) GetUConn(conn net.Conn, sni string, allowInsecure bool, alpn string, echConfig []byte) *utls.UConn {
	config := &utls.Config{
		ServerName:                     sni,
		InsecureSkipVerify:             allowInsecure,
		EncryptedClientHelloConfigList: echConfig,
	}
	if strings.TrimSpace(alpn) != "" {
		config.NextProtos = []string{alpn}
	} else {
		config.NextProtos = []string{"http/1.1"}
	}

	clientHelloID := utls.HelloChrome_Auto
	if strings.EqualFold(strings.TrimSpace(alpn), "http/1.1") {
		clientHelloID = utls.HelloFirefox_Auto
	}
	uconn := utls.UClient(conn, config, clientHelloID)
	return uconn
}
