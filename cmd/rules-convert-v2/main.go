package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type ConfigFile struct {
	Version string       `json:"version"`
	Type    string       `json:"type"`
	Rules   []ConfigRule `json:"rules"`
}

type ConfigRule struct {
	Name      string   `json:"name"`
	Website   string   `json:"website,omitempty"`
	Enabled   bool     `json:"enabled"`
	Domains   []string `json:"domains"`
	Upstream  string   `json:"upstream,omitempty"`
	Upstreams []string `json:"upstreams,omitempty"`
	SniFake   string   `json:"sni_fake,omitempty"`
	SNIMode   string   `json:"sni_mode,omitempty"` // fake|original|off
}

type Rejected struct {
	BlockType string `json:"block_type"`
	Name      string `json:"name"`
	Reason    string `json:"reason"`
	Snippet   string `json:"snippet,omitempty"`
}

type upstreamBlock struct {
	Name    string
	Servers []string
}

type serverBlock struct {
	ServerNames      []string
	RawServerNames   []string
	Listens          []string
	ProxyPassTargets []string
	ProxySSLName     string
	ProxySSLServerOn *bool
	HostOverride     string
	Snippet          []string
}

var (
	domainRe = regexp.MustCompile(`^[a-z0-9.-]+$`)
)

func main() {
	in := flag.String("in", "", "input nginx.conf path")
	out := flag.String("out", "rules/mitm.generated.json", "output rules json path")
	rejectedOut := flag.String("rejected", "rules/mitm.rejected.json", "rejected blocks report path")
	modeType := flag.String("type", "mitm", "output rule type")
	flag.Parse()

	if strings.TrimSpace(*in) == "" {
		fmt.Fprintln(os.Stderr, "missing -in")
		os.Exit(2)
	}

	data, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read input failed: %v\n", err)
		os.Exit(1)
	}

	upstreams, servers, rejects := parseNginx(string(data))
	rules, moreRejects := convertServers(upstreams, servers)
	rejects = append(rejects, moreRejects...)

	cfg := ConfigFile{
		Version: "2.0",
		Type:    strings.TrimSpace(*modeType),
		Rules:   rules,
	}

	if err := writeJSON(*out, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "write out failed: %v\n", err)
		os.Exit(1)
	}
	if err := writeJSON(*rejectedOut, rejects); err != nil {
		fmt.Fprintf(os.Stderr, "write rejected failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("converted rules: %d\n", len(rules))
	fmt.Printf("rejected blocks: %d\n", len(rejects))
	fmt.Printf("output: %s\n", *out)
	fmt.Printf("rejected: %s\n", *rejectedOut)
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func parseNginx(content string) (map[string]upstreamBlock, []serverBlock, []Rejected) {
	upstreams := map[string]upstreamBlock{}
	servers := make([]serverBlock, 0, 256)
	rejects := make([]Rejected, 0, 64)

	sc := bufio.NewScanner(strings.NewReader(content))
	const maxToken = 1024 * 1024
	sc.Buffer(make([]byte, 0, 64*1024), maxToken)

	var inUpstream bool
	var upDepth int
	var up upstreamBlock

	var inServer bool
	var srvDepth int
	var srv serverBlock

	for sc.Scan() {
		raw := sc.Text()
		line := stripComment(raw)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if !inUpstream && !inServer {
			if name, ok := parseBlockStart(line, "upstream"); ok {
				inUpstream = true
				upDepth = 1
				up = upstreamBlock{Name: name}
				continue
			}
			if isServerBlockStart(line) {
				inServer = true
				srvDepth = 1
				srv = serverBlock{}
				srv.Snippet = append(srv.Snippet, line)
				continue
			}
			continue
		}

		if inUpstream {
			upDepth += strings.Count(line, "{")
			upDepth -= strings.Count(line, "}")
			if strings.HasPrefix(line, "server ") {
				v := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "server")), ";")
				v = strings.Fields(v)[0]
				up.Servers = append(up.Servers, v)
			}
			if upDepth <= 0 {
				inUpstream = false
				if strings.TrimSpace(up.Name) != "" {
					upstreams[up.Name] = up
				}
			}
			continue
		}

		if inServer {
			srv.Snippet = append(srv.Snippet, line)
			if strings.HasPrefix(line, "server_name ") {
				val := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "server_name")), ";")
				for _, tok := range strings.Fields(val) {
					srv.RawServerNames = append(srv.RawServerNames, tok)
				}
			}
			if strings.HasPrefix(line, "listen ") {
				val := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "listen")), ";")
				srv.Listens = append(srv.Listens, val)
			}
			if strings.HasPrefix(line, "proxy_ssl_name ") {
				srv.ProxySSLName = strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "proxy_ssl_name")), ";")
			}
			if strings.HasPrefix(line, "proxy_ssl_server_name ") {
				val := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "proxy_ssl_server_name")), ";")
				on := strings.EqualFold(val, "on")
				off := strings.EqualFold(val, "off")
				if on || off {
					srv.ProxySSLServerOn = &on
				}
			}
			if strings.HasPrefix(line, "proxy_pass ") {
				val := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "proxy_pass")), ";")
				srv.ProxyPassTargets = append(srv.ProxyPassTargets, val)
			}
			if strings.HasPrefix(line, "proxy_set_header ") {
				rest := strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, "proxy_set_header")), ";")
				parts := strings.Fields(rest)
				if len(parts) >= 2 && strings.EqualFold(parts[0], "Host") {
					srv.HostOverride = parts[1]
				}
			}

			srvDepth += strings.Count(line, "{")
			srvDepth -= strings.Count(line, "}")
			if srvDepth <= 0 {
				inServer = false
				servers = append(servers, srv)
			}
		}
	}

	if err := sc.Err(); err != nil {
		rejects = append(rejects, Rejected{
			BlockType: "parser",
			Reason:    fmt.Sprintf("scanner error: %v", err),
		})
	}
	return upstreams, servers, rejects
}

func parseBlockStart(line, keyword string) (string, bool) {
	if !strings.HasPrefix(line, keyword+" ") {
		return "", false
	}
	if !strings.Contains(line, "{") {
		return "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, keyword))
	rest = strings.TrimSuffix(rest, "{")
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", false
	}
	return strings.Fields(rest)[0], true
}

func isServerBlockStart(line string) bool {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "server") {
		return false
	}
	// Accept both "server {" and "server\t{"
	if strings.HasPrefix(line, "server_name ") {
		return false
	}
	return strings.Contains(line, "{")
}

func stripComment(s string) string {
	if idx := strings.Index(s, "#"); idx >= 0 {
		return s[:idx]
	}
	return s
}

func pickProxyPassTarget(targets []string) string {
	if len(targets) == 0 {
		return ""
	}
	seen := map[string]struct{}{}
	for _, t := range targets {
		x := strings.TrimSpace(strings.TrimSuffix(t, ";"))
		if x == "" {
			continue
		}
		seen[x] = struct{}{}
	}
	if len(seen) == 0 {
		return ""
	}
	// Prefer variable proxy_pass when present, this is usually the intended dynamic backend.
	for x := range seen {
		if strings.Contains(x, "$") {
			return x
		}
	}
	for x := range seen {
		return x
	}
	return ""
}

func convertServers(upstreams map[string]upstreamBlock, servers []serverBlock) ([]ConfigRule, []Rejected) {
	rules := make([]ConfigRule, 0, len(servers))
	rejects := make([]Rejected, 0, len(servers)/3)

	seen := map[string]bool{}

	for _, s := range servers {
		if !isTLS443Server(s.Listens) {
			continue
		}
		if len(s.ProxyPassTargets) == 0 {
			rejects = append(rejects, Rejected{
				BlockType: "server",
				Reason:    "no proxy_pass target",
				Snippet:   strings.Join(s.Snippet, "\n"),
			})
			continue
		}
		proxyPassTarget := pickProxyPassTarget(s.ProxyPassTargets)
		if proxyPassTarget == "" {
			rejects = append(rejects, Rejected{
				BlockType: "server",
				Reason:    "no usable proxy_pass target",
				Snippet:   strings.Join(s.Snippet, "\n"),
			})
			continue
		}

		domains, bad := normalizeServerNames(s.RawServerNames)
		if len(bad) > 0 {
			rejects = append(rejects, Rejected{
				BlockType: "server",
				Reason:    "unsupported server_name tokens: " + strings.Join(bad, ", "),
				Snippet:   strings.Join(s.Snippet, "\n"),
			})
		}
		if len(domains) == 0 {
			continue
		}

		up, upList, err := resolveProxyPass(proxyPassTarget, upstreams)
		if err != nil {
			rejects = append(rejects, Rejected{
				BlockType: "server",
				Name:      domains[0],
				Reason:    "proxy_pass parse failed: " + err.Error(),
				Snippet:   s.ProxyPassTargets[0],
			})
			continue
		}

		sniMode := "original"
		sniFake := ""
		if s.ProxySSLServerOn != nil && !*s.ProxySSLServerOn {
			sniMode = "off"
		} else if x := normalizeHostToken(s.ProxySSLName); x != "" {
			sniMode = "fake"
			sniFake = x
		}

		name := domains[0]
		website := inferWebsite(name)
		key := strings.Join(domains, ",") + "|" + up + "|" + sniMode + "|" + sniFake
		if seen[key] {
			continue
		}
		seen[key] = true
		rules = append(rules, ConfigRule{
			Name:      name,
			Website:   website,
			Enabled:   true,
			Domains:   domains,
			Upstream:  up,
			Upstreams: upList,
			SniFake:   sniFake,
			SNIMode:   sniMode,
		})
	}

	sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	return rules, rejects
}

func isTLS443Server(listens []string) bool {
	for _, l := range listens {
		lc := strings.ToLower(l)
		if strings.Contains(lc, "443") && strings.Contains(lc, "ssl") {
			return true
		}
	}
	return false
}

func normalizeServerNames(raw []string) ([]string, []string) {
	out := make([]string, 0, len(raw))
	bad := make([]string, 0, 2)
	seen := map[string]bool{}
	for _, t := range raw {
		n, ok := normalizeServerNameToken(t)
		if !ok {
			bad = append(bad, t)
			continue
		}
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out, bad
}

func normalizeServerNameToken(t string) (string, bool) {
	t = strings.TrimSpace(strings.TrimSuffix(t, ";"))
	if t == "" {
		return "", false
	}
	if strings.HasPrefix(t, "~") {
		p := strings.TrimSpace(strings.TrimPrefix(t, "~"))
		if p == "" {
			return "", false
		}
		return "~" + p, true
	}
	if t == "_" || strings.EqualFold(t, "off") {
		return "", true
	}
	if strings.ContainsAny(t, "^()[]+?\\|") {
		return "", false
	}
	t = strings.TrimSuffix(t, "$")
	if strings.Contains(t, "*") {
		if strings.HasPrefix(t, "*.") && strings.Count(t, "*") == 1 {
			t = strings.TrimPrefix(t, "*.")
		} else {
			return "", false
		}
	}
	t = normalizeHostToken(t)
	if t == "" {
		return "", false
	}
	if !isValidDomainOrIP(t) {
		return "", false
	}
	return t, true
}

func resolveProxyPass(raw string, upstreams map[string]upstreamBlock) (string, []string, error) {
	v := strings.TrimSpace(raw)
	v = strings.TrimSuffix(v, ";")
	v = strings.TrimPrefix(v, "https://")
	v = strings.TrimPrefix(v, "http://")
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil, errors.New("empty proxy_pass")
	}
	if strings.Contains(v, "$") {
		// Preserve nginx variable-based proxy_pass for runtime resolution.
		if i := strings.Index(v, "/"); i >= 0 {
			v = v[:i]
		}
		v = strings.TrimSpace(v)
		if v == "" {
			return "", nil, errors.New("variable proxy_pass is empty")
		}
		if !strings.Contains(v, ":") {
			v = v + ":443"
		}
		return v, []string{v}, nil
	}
	// remove path
	if i := strings.Index(v, "/"); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil, errors.New("invalid proxy_pass host")
	}
	if up, ok := upstreams[v]; ok {
		clean := make([]string, 0, len(up.Servers))
		for _, s := range up.Servers {
			x := normalizeHostPortToken(s, "443")
			if x != "" {
				clean = append(clean, x)
			}
		}
		if len(clean) == 0 {
			return "", nil, fmt.Errorf("upstream %s has no valid servers", v)
		}
		primary := pickPrimaryUpstream(clean)
		return primary, clean, nil
	}
	single := normalizeHostPortToken(v, "443")
	return single, []string{single}, nil
}

func pickPrimaryUpstream(list []string) string {
	for _, x := range list {
		host := x
		if i := strings.LastIndex(x, ":"); i > 0 {
			host = x[:i]
		}
		host = strings.Trim(host, "[]")
		if parseIPv4(host) {
			return x
		}
	}
	return list[0]
}

func normalizeHostToken(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ";")
	s = strings.TrimSuffix(s, "$")
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, ".")
	return strings.ToLower(strings.TrimSpace(s))
}

func normalizeHostPortToken(s, defaultPort string) string {
	s = strings.TrimSpace(strings.TrimSuffix(s, ";"))
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if s == "" {
		return ""
	}
	if host, port, err := netSplitHostPortLoose(s); err == nil {
		host = normalizeHostToken(host)
		if host == "" {
			return ""
		}
		if port == "" {
			port = defaultPort
		}
		return host + ":" + port
	}
	host := normalizeHostToken(s)
	if host == "" {
		return ""
	}
	return host + ":" + defaultPort
}

func netSplitHostPortLoose(s string) (string, string, error) {
	// host:port where host can be fqdn or ipv4
	if i := strings.LastIndex(s, ":"); i > 0 && i < len(s)-1 && !strings.Contains(s[i+1:], "]") {
		return s[:i], s[i+1:], nil
	}
	return "", "", errors.New("no port")
}

func isValidDomainOrIP(s string) bool {
	if netIP := parseIPv4(s); netIP {
		return true
	}
	if !domainRe.MatchString(s) || strings.Contains(s, "..") || strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	return true
}

func parseIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		n := 0
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return false
			}
			n = n*10 + int(ch-'0')
		}
		if n < 0 || n > 255 {
			return false
		}
	}
	return true
}

func inferWebsite(domain string) string {
	domain = normalizeHostToken(domain)
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}
	return parts[len(parts)-2]
}
