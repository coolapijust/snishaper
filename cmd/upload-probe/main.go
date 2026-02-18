package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type probeCase struct {
	Name   string
	SNI    string
	UseH2  bool
	Target string
}

func main() {
	upstream := flag.String("upstream", "208.80.153.240:443", "upstream address host:port")
	path := flag.String("path", "/wikipedia/commons/8/82/Codex_icon_close.svg", "request path on upload.wikimedia.org")
	timeout := flag.Duration("timeout", 12*time.Second, "request timeout")
	flag.Parse()

	cases := []probeCase{
		{Name: "original+h1", SNI: "upload.wikimedia.org", UseH2: false, Target: *upstream},
		{Name: "original+h2", SNI: "upload.wikimedia.org", UseH2: true, Target: *upstream},
		{Name: "fake+h1", SNI: "upload-wikipedia-org", UseH2: false, Target: *upstream},
		{Name: "fake+h2", SNI: "upload-wikipedia-org", UseH2: true, Target: *upstream},
	}

	for _, c := range cases {
		runCase(c, *path, *timeout)
	}
}

func runCase(c probeCase, path string, timeout time.Duration) {
	target := c.Target
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}

	dialer := &net.Dialer{
		Timeout:   8 * time.Second,
		KeepAlive: 20 * time.Second,
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, target)
		},
		TLSClientConfig: &tls.Config{
			ServerName:         c.SNI,
			InsecureSkipVerify: true,
		},
		Proxy: nil,
	}

	if c.UseH2 {
		tr.ForceAttemptHTTP2 = true
	} else {
		tr.ForceAttemptHTTP2 = false
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
	defer tr.CloseIdleConnections()

	url := "https://upload.wikimedia.org" + path
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		fmt.Printf("[%s] build request err: %v\n", c.Name, err)
		return
	}
	req.Header.Set("Origin", "https://zh.wikipedia.org")
	req.Header.Set("User-Agent", "upload-probe/1.0")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		fmt.Printf("[%s] err=%v elapsed=%s\n", c.Name, err, elapsed)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	fmt.Printf("[%s] status=%d proto=%s elapsed=%s\n", c.Name, resp.StatusCode, resp.Proto, elapsed)
	printIf(resp, "server")
	printIf(resp, "content-type")
	printIf(resp, "access-control-allow-origin")
	printIf(resp, "location")
	fmt.Println("---")
}

func printIf(resp *http.Response, key string) {
	if v := resp.Header.Get(key); strings.TrimSpace(v) != "" {
		fmt.Printf("  %s: %s\n", key, v)
	}
}

