package proxy

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
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
}

type RuleManager struct {
	rules      []Rule
	siteGroups []SiteGroup
	upstreams  []Upstream
	configPath string
	mu         sync.RWMutex
}

type SiteGroup struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Domains  []string `json:"domains"`
	Mode     string   `json:"mode"`
	Upstream string   `json:"upstream"`
	SniFake  string   `json:"sni_fake"`
	Enabled  bool     `json:"enabled"`
}

type Upstream struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Enabled bool   `json:"enabled"`
}

type Config struct {
	ListenPort string      `json:"listen_port"`
	SiteGroups []SiteGroup `json:"site_groups"`
	Upstreams  []Upstream  `json:"upstreams"`
}

type Stats struct {
	BytesIn  int64
	BytesOut int64
	Requests int64
	mu       sync.Mutex
}

type Rule struct {
	Domain   string
	Upstream string
	Mode     string // "mitm", "transparent", "direct"
	SniFake  string
	Enabled  bool
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

func hostMatchesDomain(host, domain string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if host == "" || domain == "" {
		return false
	}
	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}

func isLiteralIP(host string) bool {
	return net.ParseIP(strings.Trim(host, "[]")) != nil
}

func chooseUpstreamSNI(targetHost string, rule Rule) string {
	targetHost = normalizeHost(targetHost)
	// MITM mode's core behavior: if fake SNI is configured, always use it.
	if strings.TrimSpace(rule.SniFake) != "" {
		return rule.SniFake
	}
	if rule.Upstream != "" {
		if upstreamHost := normalizeHost(resolveUpstreamHost(targetHost, rule.Upstream)); upstreamHost != "" {
			return upstreamHost
		}
	}
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

	p.Server = &http.Server{
		Addr:         p.listenAddr,
		// Use raw handler instead of ServeMux: CONNECT uses authority-form
		// and may not be routed by path-based muxes.
		Handler:      http.HandlerFunc(p.handleRequest),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	p.running = true
	p.mu.Unlock()

	go func() {
		log.Printf("[Proxy] Server started on %s", p.listenAddr)
		if err := p.Server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[Proxy] Server error: %v", err)
		}
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

	log.Printf("[Proxy] Request: %s -> %s (match: %s, runtime-mode: %s, rule-mode: %s)", req.Method, host, matchHost, mode, rule.Mode)

	switch req.Method {
	case http.MethodConnect:
		p.handleConnect(w, req, rule)
	default:
		p.handleHTTP(w, req, rule)
	}
}

func (p *ProxyServer) handleConnect(w http.ResponseWriter, req *http.Request, rule Rule) {
	targetAuthority := req.URL.Host
	if targetAuthority == "" {
		targetAuthority = req.Host
	}
	targetHost := normalizeHost(targetAuthority)
	targetAddr := ensureAddrWithPort(targetAuthority, "443")
	effectiveMode := rule.Mode
	resolvedUpstream := resolveUpstreamHost(targetHost, rule.Upstream)

	// Planning docs define transparent tunneling as baseline mode.
	// If CA is not trusted by the OS/browser, MITM will fail during TLS handshake.
	if effectiveMode == "mitm" && p.certGenerator != nil && !p.certGenerator.IsCAInstalled() {
		log.Printf("[Connect] CA not installed, downgrade MITM -> transparent for host %s", targetHost)
		effectiveMode = "transparent"
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

	// For MITM/transparent rules, upstream should be respected if configured.
	if (effectiveMode == "mitm" || effectiveMode == "transparent") && rule.Upstream != "" {
		dialAddr = ensureAddrWithPort(resolvedUpstream, "443")
		log.Printf("[Connect] Using upstream %s for host %s (mode: %s)", dialAddr, targetHost, effectiveMode)
	}

	conn, err = net.Dial("tcp", dialAddr)

	if err != nil {
		http.Error(w, "Failed to connect to upstream", http.StatusBadGateway)
		log.Printf("[Connect] Connect failed to %s: %v", dialAddr, err)
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

	// 注意：不要在 hijack 后使用 defer，因为我们需要保持连接打开
	if effectiveMode == "mitm" {
		p.handleMITM(clientConn, conn, targetHost, rule)
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

	conn, err := net.Dial("tcp", targetAddr)
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
		newReq.URL.Host = ensureAddrWithPort(rule.Upstream, defaultPort)
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

func (p *ProxyServer) handleMITM(clientConn, upstreamConn net.Conn, host string, rule Rule) {
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

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2", "http/1.1"},
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

	var upstreamRW io.ReadWriteCloser
	// MITM mode should mimic browser TLS fingerprint when possible.
	if strings.TrimSpace(rule.SniFake) != "" && strings.TrimSpace(clientALPN) != "" {
		uconn := p.GetUConn(upstreamConn, sniHost, true, clientALPN)
		if err := uconn.Handshake(); err == nil {
			log.Printf("[MITM] Upstream (uTLS) negotiated ALPN: %s", uconn.ConnectionState().NegotiatedProtocol)
			upstreamRW = uconn
		} else {
			log.Printf("[MITM] Upstream uTLS handshake failed, fallback to std TLS: %v", err)
		}
	}

	if upstreamRW == nil {
		upTLSConfig := &tls.Config{
			ServerName:         sniHost,
			InsecureSkipVerify: true,
		}
		if strings.TrimSpace(clientALPN) != "" {
			upTLSConfig.NextProtos = []string{clientALPN}
		} else {
			upTLSConfig.NextProtos = []string{"http/1.1"}
		}
		upstreamTLS := tls.Client(upstreamConn, upTLSConfig)
		if err := upstreamTLS.Handshake(); err != nil {
			log.Printf("[MITM] Upstream TLS handshake failed: %v", err)
			clientTls.Close()
			upstreamConn.Close()
			return
		}
		log.Printf("[MITM] Upstream (std TLS) negotiated ALPN: %s", upstreamTLS.ConnectionState().NegotiatedProtocol)
		upstreamRW = upstreamTLS
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
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

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
		if hostMatchesDomain(host, normalizeHost(rule.Domain)) {
			return rule
		}
	}

	return Rule{Mode: "direct", Enabled: true}
}

func (p *ProxyServer) GetStats() (int64, int64, int64) {
	p.stats.mu.Lock()
	defer p.stats.mu.Unlock()
	return p.stats.BytesIn, p.stats.BytesOut, p.stats.Requests
}

func NewRuleManager(configPath string) *RuleManager {
	return &RuleManager{
		configPath: configPath,
		rules:      []Rule{},
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

	rm.buildRules()
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
				ID:       generateID(),
				Name:     rule.Name,
				Domains:  rule.Domains,
				Mode:     configFile.Type,
				Upstream: rule.Upstream,
				SniFake:  rule.SniFake,
				Enabled:  rule.Enabled,
			}
			siteGroups = append(siteGroups, sg)
		}
	}

	if len(siteGroups) == 0 {
		return nil, nil, fmt.Errorf("no embedded rules found")
	}

	upstreams = []Upstream{
		{
			ID:      "google-cn",
			Name:    "Google境内节点",
			Address: "8.137.102.117:443",
			Enabled: true,
		},
	}

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
				Domain:   domain,
				Mode:     sg.Mode,
				Upstream: sg.Upstream,
				SniFake:  sg.SniFake,
				Enabled:  true,
			}
			rm.rules = append(rm.rules, rule)
		}
	}
}

func (rm *RuleManager) GetSiteGroups() []SiteGroup {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.siteGroups
}

func (rm *RuleManager) AddSiteGroup(sg SiteGroup) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	sg.ID = generateID()
	rm.siteGroups = append(rm.siteGroups, sg)
	rm.buildRules()
	return rm.saveConfig()
}

func (rm *RuleManager) UpdateSiteGroup(sg SiteGroup) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

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
		ListenPort: "8080",
		SiteGroups: rm.siteGroups,
		Upstreams:  rm.upstreams,
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

func (p *ProxyServer) GetUConn(conn net.Conn, sni string, allowInsecure bool, alpn string) *utls.UConn {
	config := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: allowInsecure,
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
