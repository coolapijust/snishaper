package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

func ensureAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(addr, "443")
}

func parseTLSVersion(v string) (uint16, error) {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "", "default":
		return 0, nil
	case "1.2", "tls1.2":
		return tls.VersionTLS12, nil
	case "1.3", "tls1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported tls version: %s", v)
	}
}

func parseALPN(v string) []string {
	v = strings.TrimSpace(strings.ToLower(v))
	switch v {
	case "", "auto":
		return []string{"h2", "http/1.1"}
	case "h1":
		return []string{"http/1.1"}
	case "h2":
		return []string{"h2"}
	default:
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		if len(out) == 0 {
			return []string{"h2", "http/1.1"}
		}
		return out
	}
}

func probeStdTLS(addr, sni string, tlsMin, tlsMax uint16, alpn []string) error {
	conn, err := net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	tc := tls.Client(conn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tlsMin,
		MaxVersion:         tlsMax,
		NextProtos:         alpn,
	})
	return tc.Handshake()
}

func probeUTLS(addr, sni string, alpn []string) error {
	conn, err := net.DialTimeout("tcp", addr, 8*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	uc := utls.UClient(conn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         alpn,
	}, utls.HelloChrome_Auto)
	return uc.Handshake()
}

func main() {
	addr := flag.String("addr", "", "upstream host:port")
	sni := flag.String("sni", "", "server name indication")
	tlsVer := flag.String("tls", "default", "default|1.2|1.3")
	alpnOpt := flag.String("alpn", "auto", "auto|h1|h2|custom(comma-separated)")
	flag.Parse()

	if strings.TrimSpace(*addr) == "" || strings.TrimSpace(*sni) == "" {
		fmt.Println("usage: go run ./cmd/tls-probe -addr 1.2.3.4:443 -sni example.com|none [-tls 1.2] [-alpn h1]")
		return
	}
	sniVal := strings.TrimSpace(*sni)
	if strings.EqualFold(sniVal, "none") {
		sniVal = ""
	}
	tv, err := parseTLSVersion(*tlsVer)
	if err != nil {
		fmt.Println(err)
		return
	}
	alpn := parseALPN(*alpnOpt)
	target := ensureAddr(*addr)
	fmt.Printf("target=%s sni=%q tls=%s alpn=%v\n", target, sniVal, *tlsVer, alpn)

	if err := probeStdTLS(target, sniVal, tv, tv, alpn); err != nil {
		fmt.Printf("std_tls=FAIL err=%v\n", err)
	} else {
		fmt.Println("std_tls=OK")
	}

	if err := probeUTLS(target, sniVal, alpn); err != nil {
		fmt.Printf("utls=FAIL err=%v\n", err)
	} else {
		fmt.Println("utls=OK")
	}
}
