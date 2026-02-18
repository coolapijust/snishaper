package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type configFile struct {
	SiteGroups []siteGroup `json:"site_groups"`
}

type siteGroup struct {
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	Upstream  string   `json:"upstream"`
	SNIFake   string   `json:"sni_fake"`
	SNIPolicy string   `json:"sni_policy,omitempty"`
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	configPath := flag.String("config", "build/bin/config.json", "path to config.json")
	ruleName := flag.String("rule", "wikipedia", "site group name to diagnose")
	targetHost := flag.String("target", "wikipedia.org", "target host for host header / CONNECT")
	proxyAddr := flag.String("proxy", "127.0.0.1:8080", "local proxy address")
	proxyCheck := flag.Bool("proxy-check", true, "run CONNECT check through local proxy")
	fetchURL := flag.String("fetch-url", "", "optional: fetch this URL through local proxy and print status/CORS headers")
	origin := flag.String("origin", "", "optional: Origin header used with -fetch-url")
	timeout := flag.Duration("timeout", 8*time.Second, "dial/handshake timeout")
	flag.Parse()

	sg, err := loadSiteGroup(*configPath, *ruleName)
	if err != nil {
		log.Fatalf("load rule failed: %v", err)
	}

	log.Printf("[diag] rule=%s target=%s", sg.Name, *targetHost)
	log.Printf("[diag] upstream(raw)=%s sni_fake=%s sni_policy=%s", sg.Upstream, sg.SNIFake, sg.SNIPolicy)

	upstreams := splitUpstreams(sg.Upstream, "443")
	if len(upstreams) == 0 {
		log.Fatalf("no upstream parsed from %q", sg.Upstream)
	}

	upstreamSNI := pickSNI(*targetHost, sg)
	log.Printf("[diag] chosen upstream SNI=%s", upstreamSNI)
	for i, up := range upstreams {
		log.Printf("[direct #%d] testing upstream=%s", i+1, up)
		testDirect(up, upstreamSNI, *targetHost, *timeout)
	}

	if *proxyCheck {
		log.Printf("[proxy] testing via local proxy %s", *proxyAddr)
		testViaProxy(*proxyAddr, *targetHost, *timeout)
	}
	if strings.TrimSpace(*fetchURL) != "" {
		log.Printf("[proxy-fetch] fetching %s via %s", *fetchURL, *proxyAddr)
		fetchViaProxy(*proxyAddr, *fetchURL, *origin, *timeout)
	}
}

func loadSiteGroup(path, name string) (siteGroup, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return siteGroup{}, err
	}
	var cfg configFile
	if err := json.Unmarshal(b, &cfg); err != nil {
		return siteGroup{}, err
	}
	for _, sg := range cfg.SiteGroups {
		if strings.EqualFold(strings.TrimSpace(sg.Name), strings.TrimSpace(name)) {
			return sg, nil
		}
	}
	return siteGroup{}, fmt.Errorf("site group not found: %s", name)
}

func splitUpstreams(raw, defaultPort string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		addr := withPort(p, defaultPort)
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

func withPort(addr, defaultPort string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, defaultPort)
}

func pickSNI(target string, sg siteGroup) string {
	policy := strings.ToLower(strings.TrimSpace(sg.SNIPolicy))
	switch policy {
	case "fake":
		if strings.TrimSpace(sg.SNIFake) != "" {
			return strings.TrimSpace(sg.SNIFake)
		}
		return "g.cn"
	case "original":
		return target
	default:
		if strings.TrimSpace(sg.SNIFake) != "" {
			return strings.TrimSpace(sg.SNIFake)
		}
		return "g.cn"
	}
}

func testDirect(upstream, sni, host string, timeout time.Duration) {
	d := net.Dialer{Timeout: timeout, KeepAlive: 20 * time.Second}
	start := time.Now()
	raw, err := d.Dial("tcp", upstream)
	if err != nil {
		log.Printf("[direct] tcp FAIL upstream=%s err=%v", upstream, err)
		return
	}
	log.Printf("[direct] tcp OK upstream=%s elapsed=%s", upstream, time.Since(start))

	tcfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	tconn := tls.Client(raw, tcfg)
	_ = tconn.SetDeadline(time.Now().Add(timeout))
	start = time.Now()
	if err := tconn.Handshake(); err != nil {
		log.Printf("[direct] tls FAIL upstream=%s sni=%s err=%v", upstream, sni, err)
		_ = raw.Close()
		return
	}
	st := tconn.ConnectionState()
	cn := ""
	if len(st.PeerCertificates) > 0 {
		cn = st.PeerCertificates[0].Subject.CommonName
	}
	log.Printf("[direct] tls OK upstream=%s sni=%s alpn=%s cn=%s elapsed=%s", upstream, sni, st.NegotiatedProtocol, cn, time.Since(start))
	_ = tconn.Close()

	// For application-layer probe, force HTTP/1.1 to avoid h2 framing mismatch.
	raw2, err := d.Dial("tcp", upstream)
	if err != nil {
		log.Printf("[direct] http probe tcp FAIL upstream=%s err=%v", upstream, err)
		return
	}
	tconn2 := tls.Client(raw2, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})
	_ = tconn2.SetDeadline(time.Now().Add(timeout))
	if err := tconn2.Handshake(); err != nil {
		log.Printf("[direct] http probe tls FAIL upstream=%s sni=%s err=%v", upstream, sni, err)
		_ = raw2.Close()
		return
	}

	path := "/"
	if strings.EqualFold(host, "wikipedia.org") {
		path = "/wiki/Main_Page"
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: wiki-diagnose/1.0\r\nConnection: close\r\n\r\n", path, host)
	_ = tconn2.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(tconn2, req); err != nil {
		log.Printf("[direct] http write FAIL upstream=%s err=%v", upstream, err)
		_ = tconn2.Close()
		return
	}
	br := bufio.NewReader(tconn2)
	line, err := br.ReadString('\n')
	if err != nil {
		log.Printf("[direct] http read FAIL upstream=%s err=%v", upstream, err)
		_ = tconn2.Close()
		return
	}
	log.Printf("[direct] http status upstream=%s %s", upstream, strings.TrimSpace(line))
	_ = tconn2.Close()
}

func testViaProxy(proxyAddr, targetHost string, timeout time.Duration) {
	targetAddr := withPort(targetHost, "443")
	d := net.Dialer{Timeout: timeout, KeepAlive: 20 * time.Second}
	conn, err := d.Dial("tcp", proxyAddr)
	if err != nil {
		log.Printf("[proxy] dial FAIL proxy=%s err=%v", proxyAddr, err)
		return
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n", targetAddr, targetAddr)
	if _, err := io.WriteString(conn, connectReq); err != nil {
		log.Printf("[proxy] write CONNECT FAIL err=%v", err)
		return
	}
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		log.Printf("[proxy] read CONNECT FAIL err=%v", err)
		return
	}
	log.Printf("[proxy] CONNECT response=%s", strings.TrimSpace(status))
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			log.Printf("[proxy] read CONNECT headers FAIL err=%v", err)
			return
		}
		if line == "\r\n" {
			break
		}
	}
	if !strings.Contains(status, "200") {
		log.Printf("[proxy] CONNECT not established")
		return
	}

	// Reuse buffered reader bytes before conn.
	wrapped := &readPrefixedConn{Conn: conn, r: br}
	tlsConn := tls.Client(wrapped, &tls.Config{
		ServerName:         targetHost,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[proxy] client->localproxy TLS FAIL target=%s err=%v", targetHost, err)
		return
	}
	st := tlsConn.ConnectionState()
	subject := ""
	issuer := ""
	if len(st.PeerCertificates) > 0 {
		subject = st.PeerCertificates[0].Subject.String()
		issuer = st.PeerCertificates[0].Issuer.String()
	}
	log.Printf("[proxy] client->localproxy TLS OK alpn=%s subject=%q issuer=%q", st.NegotiatedProtocol, subject, issuer)

	path := "/"
	if strings.EqualFold(targetHost, "wikipedia.org") {
		path = "/wiki/Main_Page"
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: wiki-diagnose/1.0\r\nConnection: close\r\n\r\n", path, targetHost)
	writeStart := time.Now()
	n, err := io.WriteString(tlsConn, req)
	if err != nil {
		log.Printf("[proxy] https write FAIL err=%v", err)
		return
	}
	log.Printf("[proxy] https write OK bytes=%d elapsed=%s", n, time.Since(writeStart))
	tbr := bufio.NewReader(tlsConn)
	readStart := time.Now()
	line, err := tbr.ReadString('\n')
	if err != nil {
		log.Printf("[proxy] https read FAIL elapsed=%s err=%v", time.Since(readStart), err)
		return
	}
	log.Printf("[proxy] https status via local proxy elapsed=%s: %s", time.Since(readStart), strings.TrimSpace(line))
}

func fetchViaProxy(proxyAddr, rawURL, origin string, timeout time.Duration) {
	pu, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		log.Printf("[proxy-fetch] invalid proxy addr: %v", err)
		return
	}
	tr := &http.Transport{
		Proxy: http.ProxyURL(pu),
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 20 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout + 4*time.Second,
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		log.Printf("[proxy-fetch] build request failed: %v", err)
		return
	}
	if strings.TrimSpace(origin) != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[proxy-fetch] request failed: %v", err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))

	log.Printf("[proxy-fetch] status=%d", resp.StatusCode)
	for _, h := range []string{
		"access-control-allow-origin",
		"access-control-allow-credentials",
		"content-type",
		"location",
		"server",
		"x-cache",
	} {
		if v := resp.Header.Get(h); v != "" {
			log.Printf("[proxy-fetch] %s: %s", h, v)
		}
	}
}

type readPrefixedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *readPrefixedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
