package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
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
	SNIMode   string   `json:"sni_mode,omitempty"`
}

var domainRe = regexp.MustCompile(`^[a-z0-9.-]+$`)

func main() {
	in := flag.String("in", "", "rules json path")
	flag.Parse()
	if strings.TrimSpace(*in) == "" {
		fmt.Fprintln(os.Stderr, "missing -in")
		os.Exit(2)
	}

	data, err := os.ReadFile(*in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read failed: %v\n", err)
		os.Exit(1)
	}
	var cfg ConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "parse failed: %v\n", err)
		os.Exit(1)
	}

	errs := lint(cfg)
	if len(errs) > 0 {
		sort.Strings(errs)
		for _, e := range errs {
			fmt.Println("ERROR:", e)
		}
		os.Exit(1)
	}
	fmt.Printf("LINT_OK rules=%d type=%s version=%s\n", len(cfg.Rules), cfg.Type, cfg.Version)
}

func lint(cfg ConfigFile) []string {
	errs := make([]string, 0)
	seenRule := map[string]bool{}
	for i, r := range cfg.Rules {
		id := fmt.Sprintf("%d:%s", i+1, strings.TrimSpace(r.Name))
		if strings.TrimSpace(r.Name) == "" {
			errs = append(errs, id+" empty name")
		}
		if len(r.Domains) == 0 {
			errs = append(errs, id+" empty domains")
		}
		dSeen := map[string]bool{}
		for _, d := range r.Domains {
			dn := normalize(d)
			if dn == "" {
				errs = append(errs, id+" invalid domain token: "+d)
				continue
			}
			if dn == "server_name" || dn == "off" {
				errs = append(errs, id+" polluted keyword in domains: "+dn)
			}
			if !isDomainOrIPv4(dn) {
				errs = append(errs, id+" invalid domain format: "+dn)
			}
			if dSeen[dn] {
				errs = append(errs, id+" duplicate domain: "+dn)
			}
			dSeen[dn] = true
		}

		up := normalizeHostPort(r.Upstream)
		if up == "" {
			errs = append(errs, id+" invalid upstream: "+r.Upstream)
		}
		if strings.Contains(up, "$") {
			errs = append(errs, id+" upstream contains variable: "+up)
		}
		for _, u := range r.Upstreams {
			uu := normalizeHostPort(u)
			if uu == "" {
				errs = append(errs, id+" invalid upstreams item: "+u)
			}
		}

		switch strings.TrimSpace(strings.ToLower(r.SNIMode)) {
		case "", "fake", "original", "off":
		default:
			errs = append(errs, id+" invalid sni_mode: "+r.SNIMode)
		}
		if strings.EqualFold(r.SNIMode, "fake") {
			sf := normalize(r.SniFake)
			if sf == "" || !isDomainOrIPv4(sf) {
				errs = append(errs, id+" fake mode requires valid sni_fake")
			}
		}

		finger := strings.Join(sortedCopyKeys(dSeen), ",") + "|" + up + "|" + r.SNIMode + "|" + strings.ToLower(strings.TrimSpace(r.SniFake))
		if seenRule[finger] {
			errs = append(errs, id+" duplicate semantic rule")
		}
		seenRule[finger] = true
	}
	return errs
}

func sortedCopyKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func normalize(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimSuffix(s, ";")
	s = strings.TrimSuffix(s, "$")
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, ".")
	return s
}

func normalizeHostPort(s string) string {
	s = normalize(s)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if s == "" {
		return ""
	}
	host := s
	if i := strings.LastIndex(s, ":"); i > 0 && i < len(s)-1 {
		host = s[:i]
	}
	if !isDomainOrIP(host) {
		return ""
	}
	return s
}

func isDomainOrIP(s string) bool {
	if isIPv4(s) {
		return true
	}
	if isBracketIPv6(s) {
		return true
	}
	if !domainRe.MatchString(s) || strings.Contains(s, "..") || !strings.Contains(s, ".") {
		return false
	}
	return true
}

func isDomainOrIPv4(s string) bool {
	return isDomainOrIP(s)
}

func isIPv4(s string) bool {
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

func isBracketIPv6(s string) bool {
	if !(strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]")) {
		return false
	}
	ip := strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	parsed := net.ParseIP(ip)
	return parsed != nil && strings.Contains(ip, ":")
}
