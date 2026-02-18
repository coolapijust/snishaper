package main

import (
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
	"path/filepath"
	"time"

	"snishaper/cert"
	"snishaper/proxy"
)

func mustJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return b
}

func pickFreeLoopback() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer ln.Close()
	return ln.Addr().String(), nil
}

func main() {
	targetURL := flag.String("url", "https://www.google.com/generate_204", "target https url via proxy")
	upstream := flag.String("upstream", "google.com", "rule upstream (host or ip:port)")
	sniFake := flag.String("sni-fake", "g.cn", "rule fake sni")
	flag.Parse()

	workDir, err := os.MkdirTemp("", "snishaper-google-check-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(workDir)

	listenAddr, err := pickFreeLoopback()
	if err != nil {
		log.Fatal(err)
	}

	cfgPath := filepath.Join(workDir, "config.json")
	cfg := proxy.Config{
		ListenPort: "8080",
		SiteGroups: []proxy.SiteGroup{
			{
				ID:       "google-check",
				Name:     "google-check",
				Website:  "google",
				Domains:  []string{"google.com", "www.google.com"},
				Mode:     "mitm",
				Upstream: *upstream,
				SniFake:  *sniFake,
				Enabled:  true,
			},
		},
		Upstreams: []proxy.Upstream{},
	}
	if err := os.WriteFile(cfgPath, mustJSON(cfg), 0644); err != nil {
		log.Fatal(err)
	}

	rm := proxy.NewRuleManager(cfgPath)
	if err := rm.LoadConfig(); err != nil {
		log.Fatalf("load config failed: %v", err)
	}

	cm, err := cert.InitCertManager(filepath.Join(workDir, "cert"))
	if err != nil {
		log.Fatalf("init cert failed: %v", err)
	}

	ps := proxy.NewProxyServer(listenAddr)
	ps.SetRuleManager(rm)
	ps.SetCertGenerator(cm)
	if err := ps.SetMode("mitm"); err != nil {
		log.Fatalf("set mode failed: %v", err)
	}
	if err := ps.Start(); err != nil {
		log.Fatalf("start proxy failed: %v", err)
	}
	defer ps.Stop()

	log.Printf("proxy started on %s", listenAddr)

	proxyURL, _ := url.Parse("http://" + listenAddr)
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
	}

	req, _ := http.NewRequest(http.MethodGet, *targetURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("google request failed: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	fmt.Printf("GOOGLE_CHECK_OK status=%d\n", resp.StatusCode)
}
