package main

import (
	"crypto/tls"
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

func pickFreeLoopback() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer ln.Close()
	return ln.Addr().String(), nil
}

func main() {
	configPath := flag.String("config", "build/bin/config.json", "path to config.json")
	mode := flag.String("mode", "mitm", "proxy mode: mitm|transparent")
	targetURL := flag.String("url", "https://www.google.com/generate_204", "url to request via local proxy")
	timeout := flag.Duration("timeout", 20*time.Second, "request timeout")
	flag.Parse()

	listenAddr, err := pickFreeLoopback()
	if err != nil {
		log.Fatalf("pick free port failed: %v", err)
	}

	rm := proxy.NewRuleManager(*configPath)
	if err := rm.LoadConfig(); err != nil {
		log.Fatalf("load config failed: %v", err)
	}

	tmpCertDir, err := os.MkdirTemp("", "snishaper-smoke-cert-*")
	if err != nil {
		log.Fatalf("create temp cert dir failed: %v", err)
	}
	defer os.RemoveAll(tmpCertDir)

	cm, err := cert.InitCertManager(filepath.Join(tmpCertDir, "cert"))
	if err != nil {
		log.Fatalf("init cert manager failed: %v", err)
	}

	ps := proxy.NewProxyServer(listenAddr)
	ps.SetRuleManager(rm)
	ps.SetCertGenerator(cm)
	if err := ps.SetMode(*mode); err != nil {
		log.Fatalf("set mode failed: %v", err)
	}
	if err := ps.Start(); err != nil {
		log.Fatalf("start proxy failed: %v", err)
	}
	defer ps.Stop()

	pu, _ := url.Parse("http://" + listenAddr)
	tr := &http.Transport{
		Proxy: http.ProxyURL(pu),
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
		Transport: tr,
		Timeout:   *timeout,
	}

	req, err := http.NewRequest(http.MethodGet, *targetURL, nil)
	if err != nil {
		log.Fatalf("build request failed: %v", err)
	}
	req.Header.Set("User-Agent", "snishaper-proxy-smoke/1.0")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("SMOKE_FAIL url=%s mode=%s err=%v\n", *targetURL, *mode, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	fmt.Printf("SMOKE_OK url=%s mode=%s status=%d elapsed=%s\n", *targetURL, *mode, resp.StatusCode, time.Since(start))
}

