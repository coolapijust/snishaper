package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Config struct {
	SiteGroups []SiteGroup `json:"site_groups"`
}

type SiteGroup struct {
	Name      string   `json:"name"`
	Website   string   `json:"website"`
	Domains   []string `json:"domains"`
	Mode      string   `json:"mode"`
	Upstream  string   `json:"upstream"`
	SniFake   string   `json:"sni_fake"`
	SniPolicy string   `json:"sni_policy"`
	Enabled   bool     `json:"enabled"`
}

type StageResult struct {
	Stage  string `json:"stage"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type TargetReport struct {
	TargetURL   string        `json:"target_url"`
	Host        string        `json:"host"`
	Website     string        `json:"website"`
	RuleName    string        `json:"rule_name"`
	Mode        string        `json:"mode"`
	UpstreamRaw string        `json:"upstream_raw"`
	SNIPolicy   string        `json:"sni_policy"`
	SNIFake     string        `json:"sni_fake"`
	Stages      []StageResult `json:"stages"`
	Summary     string        `json:"summary"`
}

type Report struct {
	Timestamp   string         `json:"timestamp"`
	HostInfo    string         `json:"host_info"`
	ConfigPath  string         `json:"config_path"`
	ProxyAddr   string         `json:"proxy_addr"`
	Targets     []TargetReport `json:"targets"`
	QuickAdvice []string       `json:"quick_advice"`
}

type TargetSpec struct {
	URL           string
	PreferredSite string
}

func main() {
	execPath, _ := os.Executable()
	execDir := filepath.Dir(execPath)

	configPath := filepath.Join(execDir, "config.json")
	if _, err := os.Stat(configPath); err != nil {
		wd, _ := os.Getwd()
		try := filepath.Join(wd, "config.json")
		if _, err2 := os.Stat(try); err2 == nil {
			configPath = try
		}
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Printf("[FATAL] load config failed: %v\n", err)
		os.Exit(1)
	}

	proxyAddr := "127.0.0.1:8080"
	targets := []TargetSpec{
		{URL: "https://www.google.com/generate_204", PreferredSite: "google"},
		{URL: "https://www.pixiv.net/", PreferredSite: "pixiv"},
		{URL: "https://i.pximg.net/", PreferredSite: "pixiv"},
	}

	hostName, _ := os.Hostname()
	report := Report{
		Timestamp:  time.Now().Format(time.RFC3339),
		HostInfo:   hostName,
		ConfigPath: configPath,
		ProxyAddr:  proxyAddr,
	}

	fmt.Println("=== SniShaper Customer Diagnose ===")
	fmt.Printf("config: %s\n", configPath)
	fmt.Printf("proxy : %s\n", proxyAddr)
	fmt.Println("targets:")
	for _, t := range targets {
		fmt.Printf("- %s (site=%s)\n", t.URL, t.PreferredSite)
	}
	fmt.Println()

	for _, t := range targets {
		tr := diagnoseTarget(cfg, proxyAddr, t)
		report.Targets = append(report.Targets, tr)
		printTargetSummary(tr)
	}

	report.QuickAdvice = buildAdvice(report.Targets)

	base := fmt.Sprintf("diag_report_%s", time.Now().Format("20060102_150405"))
	txtPath := filepath.Join(execDir, base+".txt")
	jsonPath := filepath.Join(execDir, base+".json")
	if err := writeTextReport(txtPath, report); err != nil {
		fmt.Printf("[WARN] write txt failed: %v\n", err)
	} else {
		fmt.Printf("\nTXT report : %s\n", txtPath)
	}
	if err := writeJSONReport(jsonPath, report); err != nil {
		fmt.Printf("[WARN] write json failed: %v\n", err)
	} else {
		fmt.Printf("JSON report: %s\n", jsonPath)
	}

	fmt.Println("\nDone.")
	fmt.Print("Press Enter to exit...")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

func loadConfig(path string) (Config, error) {
	var cfg Config
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func diagnoseTarget(cfg Config, proxyAddr string, spec TargetSpec) TargetReport {
	targetURL := spec.URL
	u, _ := url.Parse(targetURL)
	host := u.Hostname()

	tr := TargetReport{
		TargetURL: targetURL,
		Host:      host,
	}

	sg := pickSiteGroup(cfg.SiteGroups, host, spec.PreferredSite)
	if sg != nil {
		tr.Website = sg.Website
		tr.RuleName = sg.Name
		tr.Mode = sg.Mode
		tr.UpstreamRaw = sg.Upstream
		tr.SNIPolicy = strings.TrimSpace(strings.ToLower(sg.SniPolicy))
		tr.SNIFake = sg.SniFake
	} else {
		tr.Stages = append(tr.Stages, StageResult{
			Stage:  "rule_match",
			OK:     false,
			Detail: "no matching site_group in config",
		})
		tr.Summary = "rule not matched; check domains/website in config."
		return tr
	}

	tr.Stages = append(tr.Stages, StageResult{Stage: "rule_match", OK: true, Detail: fmt.Sprintf("website=%s rule=%s mode=%s", tr.Website, tr.RuleName, tr.Mode)})

	// Stage 1: proxy tcp reachable
	if err := tcpPing(proxyAddr, 3*time.Second); err != nil {
		tr.Stages = append(tr.Stages, StageResult{Stage: "proxy_tcp", OK: false, Detail: err.Error()})
		tr.Summary = "local proxy unreachable on 127.0.0.1:8080."
		return tr
	}
	tr.Stages = append(tr.Stages, StageResult{Stage: "proxy_tcp", OK: true, Detail: "reachable"})

	// Stage 2-3 via local proxy (CONNECT + local TLS)
	connectOK, tlsOK, _, proxyDetail := probeViaProxy(proxyAddr, host, u.RequestURI())
	tr.Stages = append(tr.Stages, StageResult{Stage: "proxy_connect", OK: connectOK, Detail: proxyDetail.connect})
	if !connectOK {
		tr.Summary = "CONNECT failed; traffic may not enter proxy chain."
		return tr
	}

	tr.Stages = append(tr.Stages, StageResult{Stage: "proxy_tls_local", OK: tlsOK, Detail: proxyDetail.tls})
	if !tlsOK {
		tr.Summary = "local MITM TLS failed (cert trust or local handshake)."
		return tr
	}

	ok, detail := probeHTTPViaProxy(targetURL, proxyAddr)
	tr.Stages = append(tr.Stages, StageResult{Stage: "proxy_https_request", OK: ok, Detail: detail})

	// Stage 5-7 upstream direct from rule
	upstreams := splitUpstreams(resolveUpstream(host, tr.UpstreamRaw))
	if len(upstreams) == 0 {
		tr.Stages = append(tr.Stages, StageResult{Stage: "upstream_parse", OK: false, Detail: "empty upstream"})
		tr.Summary = "rule upstream is empty."
		return tr
	}
	tr.Stages = append(tr.Stages, StageResult{Stage: "upstream_parse", OK: true, Detail: strings.Join(upstreams, ", ")})

	sni := chooseSNI(host, tr.SNIPolicy, tr.SNIFake, upstreams[0])
	upstreamProbe := probeUpstream(upstreams, sni, host, u.RequestURI())
	tr.Stages = append(tr.Stages, upstreamProbe...)

	tr.Summary = summarize(tr)
	return tr
}

type proxyProbeDetail struct {
	connect string
	tls     string
}

func probeViaProxy(proxyAddr, host, path string) (bool, bool, string, proxyProbeDetail) {
	detail := proxyProbeDetail{}
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		detail.connect = err.Error()
		return false, false, "", detail
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	target := net.JoinHostPort(host, "443")
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n\r\n", target, target)
	if _, err := io.WriteString(conn, connectReq); err != nil {
		detail.connect = "write CONNECT failed: " + err.Error()
		return false, false, "", detail
	}

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		detail.connect = "read CONNECT failed: " + err.Error()
		return false, false, "", detail
	}
	status = strings.TrimSpace(status)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			detail.connect = "read CONNECT headers failed: " + err.Error()
			return false, false, "", detail
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	if !strings.Contains(status, "200") {
		detail.connect = status
		return false, false, "", detail
	}
	detail.connect = status

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})
	if err := tlsConn.Handshake(); err != nil {
		detail.tls = err.Error()
		return true, false, "", detail
	}
	st := tlsConn.ConnectionState()
	issuer := ""
	if len(st.PeerCertificates) > 0 {
		issuer = st.PeerCertificates[0].Issuer.String()
	}
	detail.tls = fmt.Sprintf("ok alpn=%s issuer=%s", st.NegotiatedProtocol, issuer)

	reqPath := path
	if reqPath == "" {
		reqPath = "/"
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: snishaper-customer-diagnose/1.0\r\nConnection: close\r\n\r\n", reqPath, host)
	if _, err := io.WriteString(tlsConn, req); err != nil {
		return true, true, "", detail
	}
	respReader := bufio.NewReader(tlsConn)
	line, _ := respReader.ReadString('\n')
	return true, true, strings.TrimSpace(line), detail
}

func probeUpstream(candidates []string, sni, host, path string) []StageResult {
	out := []StageResult{}
	for i, c := range candidates {
		if i >= 3 {
			break
		}
		start := time.Now()
		conn, err := net.DialTimeout("tcp", c, 6*time.Second)
		if err != nil {
			out = append(out, StageResult{Stage: "upstream_tcp", OK: false, Detail: fmt.Sprintf("%s tcp fail: %v", c, err)})
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		out = append(out, StageResult{Stage: "upstream_tcp", OK: true, Detail: fmt.Sprintf("%s tcp ok in %s", c, time.Since(start).Round(time.Millisecond))})

		tlsCfg := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		}
		if strings.TrimSpace(sni) != "" {
			tlsCfg.ServerName = sni
		}
		tc := tls.Client(conn, tlsCfg)
		if err := tc.Handshake(); err != nil {
			out = append(out, StageResult{Stage: "upstream_tls", OK: false, Detail: fmt.Sprintf("%s tls fail (sni=%q): %v", c, sni, err)})
			_ = conn.Close()
			continue
		}
		state := tc.ConnectionState()
		out = append(out, StageResult{Stage: "upstream_tls", OK: true, Detail: fmt.Sprintf("%s tls ok (sni=%q alpn=%s)", c, sni, state.NegotiatedProtocol)})
		if state.NegotiatedProtocol == "h2" {
			out = append(out, StageResult{
				Stage:  "upstream_http",
				OK:     true,
				Detail: fmt.Sprintf("%s skipped raw HTTP/1.1 probe because ALPN=h2", c),
			})
			_ = tc.Close()
			return out
		}

		reqPath := path
		if reqPath == "" {
			reqPath = "/"
		}
		req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: snishaper-customer-diagnose/1.0\r\nConnection: close\r\n\r\n", reqPath, host)
		if _, err := io.WriteString(tc, req); err != nil {
			out = append(out, StageResult{Stage: "upstream_http", OK: false, Detail: fmt.Sprintf("%s write fail: %v", c, err)})
			_ = tc.Close()
			continue
		}
		br := bufio.NewReader(tc)
		line, err := br.ReadString('\n')
		if err != nil {
			out = append(out, StageResult{Stage: "upstream_http", OK: false, Detail: fmt.Sprintf("%s read fail: %v", c, err)})
			_ = tc.Close()
			continue
		}
		out = append(out, StageResult{Stage: "upstream_http", OK: true, Detail: fmt.Sprintf("%s %s", c, strings.TrimSpace(line))})
		_ = tc.Close()
		return out
	}
	return out
}

func probeHTTPViaProxy(targetURL, proxyAddr string) (bool, string) {
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		return false, "invalid proxy addr: " + err.Error()
	}
	client := &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			ForceAttemptHTTP2: true,
		},
	}
	req, _ := http.NewRequest(http.MethodGet, targetURL, nil)
	req.Header.Set("User-Agent", "snishaper-customer-diagnose/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return false, err.Error()
	}
	defer resp.Body.Close()
	return true, resp.Status
}

func pickSiteGroup(siteGroups []SiteGroup, host, preferredWebsite string) *SiteGroup {
	host = strings.ToLower(strings.TrimSpace(host))
	preferredWebsite = strings.ToLower(strings.TrimSpace(preferredWebsite))
	type scored struct {
		score int
		sg    *SiteGroup
	}
	var best scored
	for i := range siteGroups {
		sg := &siteGroups[i]
		if !sg.Enabled {
			continue
		}
		if preferredWebsite != "" && strings.ToLower(strings.TrimSpace(sg.Website)) != preferredWebsite {
			continue
		}
		for _, d := range sg.Domains {
			s := domainScore(host, strings.ToLower(strings.TrimSpace(d)))
			if s > best.score {
				best = scored{score: s, sg: sg}
			}
		}
	}
	if best.sg != nil {
		return best.sg
	}
	// fallback: ignore preferred website
	for i := range siteGroups {
		sg := &siteGroups[i]
		if !sg.Enabled {
			continue
		}
		for _, d := range sg.Domains {
			s := domainScore(host, strings.ToLower(strings.TrimSpace(d)))
			if s > best.score {
				best = scored{score: s, sg: sg}
			}
		}
	}
	return best.sg
}

func domainScore(host, pattern string) int {
	if pattern == "" {
		return 0
	}
	if host == pattern {
		return 1000 + len(pattern)
	}
	if strings.HasPrefix(pattern, "*.") {
		base := strings.TrimPrefix(pattern, "*.")
		if host == base || strings.HasSuffix(host, "."+base) {
			return 500 + len(base)
		}
		return 0
	}
	// suffix-style fallback for plain domains
	if strings.HasSuffix(host, "."+pattern) {
		return 300 + len(pattern)
	}
	return 0
}

func resolveUpstream(host, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	if strings.Contains(raw, "$1") {
		first := strings.Split(host, ".")[0]
		raw = strings.ReplaceAll(raw, "$1", first)
	}
	return raw
}

func splitUpstreams(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func chooseSNI(host, policy, fake, firstUpstream string) string {
	policy = strings.ToLower(strings.TrimSpace(policy))
	fake = strings.TrimSpace(fake)
	host = strings.TrimSpace(host)
	token := strings.ReplaceAll(strings.ReplaceAll(host, ".", "-"), ":", "-")
	if token == "" {
		token = "g-cn"
	}
	switch policy {
	case "none":
		return ""
	case "original":
		return host
	case "fake":
		if fake != "" {
			return fake
		}
		return token
	case "upstream":
		h := firstHost(firstUpstream)
		if h != "" && net.ParseIP(strings.Trim(h, "[]")) == nil {
			return h
		}
		return host
	default:
		if fake != "" {
			return fake
		}
		return host
	}
}

func firstHost(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, "[") {
		end := strings.Index(addr, "]")
		if end > 0 {
			return addr[1:end]
		}
		return strings.Trim(addr, "[]")
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func tcpPing(addr string, timeout time.Duration) error {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	_ = c.Close()
	return nil
}

func summarize(tr TargetReport) string {
	// prefer first failing stage
	for _, s := range tr.Stages {
		if !s.OK {
			switch s.Stage {
			case "proxy_tcp":
				return "local proxy port unreachable."
			case "proxy_connect":
				return "CONNECT failed; traffic may not enter proxy chain."
			case "proxy_tls_local":
				return "local MITM TLS failed (likely cert trust issue)."
			case "upstream_tcp":
				return "upstream TCP failed."
			case "upstream_tls":
				return "upstream TLS failed (SNI/policy mismatch or reset)."
			case "upstream_http":
				return "upstream HTTP response abnormal."
			default:
				return "some stages failed; check details."
			}
		}
	}
	return "all checked stages passed."
}

func buildAdvice(targets []TargetReport) []string {
	adv := []string{}
	needProxy := false
	needCert := false
	needSNI := false
	for _, t := range targets {
		for _, s := range t.Stages {
			if s.OK {
				continue
			}
			switch s.Stage {
			case "proxy_tcp", "proxy_connect":
				needProxy = true
			case "proxy_tls_local":
				needCert = true
			case "upstream_tls", "upstream_tcp":
				needSNI = true
			}
		}
	}
	if needProxy {
		adv = append(adv, "Check system proxy points to 127.0.0.1:8080 and SniShaper is started.")
	}
	if needCert {
		adv = append(adv, "Check whether system/browser trusts SniShaper CA cert.")
	}
	if needSNI {
		adv = append(adv, "Check rule upstream, sni_policy, and sni_fake for the target website.")
	}
	if len(adv) == 0 {
		adv = append(adv, "Google/Pixiv checks passed.")
	}
	sort.Strings(adv)
	return adv
}

func printTargetSummary(tr TargetReport) {
	fmt.Printf("---- %s ----\n", tr.TargetURL)
	fmt.Printf("rule: %s | website: %s | mode: %s\n", tr.RuleName, tr.Website, tr.Mode)
	fmt.Printf("upstream: %s | sni_policy: %s | sni_fake: %s\n", tr.UpstreamRaw, tr.SNIPolicy, tr.SNIFake)
	for _, s := range tr.Stages {
		flag := "OK"
		if !s.OK {
			flag = "FAIL"
		}
		fmt.Printf("[%s] %-18s %s\n", flag, s.Stage, s.Detail)
	}
	fmt.Printf("summary: %s\n\n", tr.Summary)
}

func writeTextReport(path string, rep Report) error {
	var b strings.Builder
	b.WriteString("SniShaper Connectivity Report\n")
	b.WriteString("=============================\n")
	b.WriteString(fmt.Sprintf("time:   %s\n", rep.Timestamp))
	b.WriteString(fmt.Sprintf("host:   %s\n", rep.HostInfo))
	b.WriteString(fmt.Sprintf("config: %s\n", rep.ConfigPath))
	b.WriteString(fmt.Sprintf("proxy:  %s\n\n", rep.ProxyAddr))

	for _, tr := range rep.Targets {
		b.WriteString(fmt.Sprintf("Target: %s\n", tr.TargetURL))
		b.WriteString(fmt.Sprintf("Rule:   %s (website=%s mode=%s)\n", tr.RuleName, tr.Website, tr.Mode))
		b.WriteString(fmt.Sprintf("Route:  upstream=%s | sni_policy=%s | sni_fake=%s\n", tr.UpstreamRaw, tr.SNIPolicy, tr.SNIFake))
		for _, s := range tr.Stages {
			flag := "OK"
			if !s.OK {
				flag = "FAIL"
			}
			b.WriteString(fmt.Sprintf("  - [%s] %s: %s\n", flag, s.Stage, s.Detail))
		}
		b.WriteString(fmt.Sprintf("Summary: %s\n\n", tr.Summary))
	}

	b.WriteString("Quick Advice\n")
	b.WriteString("------------\n")
	for _, a := range rep.QuickAdvice {
		b.WriteString("- " + a + "\n")
	}

	return os.WriteFile(path, []byte(b.String()), 0644)
}

func writeJSONReport(path string, rep Report) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Keep static binary footprint small: avoid net/http transport probe; raw stages are enough.
var _ = http.MethodGet
