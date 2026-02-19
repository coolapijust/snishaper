package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"snishaper/proxy"
	"snishaper/cert"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// 1. Setup RuleManager
	// We point to the config we just modified
	configPath := "build/bin/config.json"
	rm := proxy.NewRuleManager(configPath)
	if err := rm.LoadConfig(); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Println("Config loaded successfully.")

	// 2. Setup CertManager
	// Ensure directory exists
	certPath := "build/bin/cert"
	if err := os.MkdirAll(certPath, 0755); err != nil {
		log.Fatalf("Failed to create cert dir: %v", err)
	}
	
	cm, err := cert.InitCertManager(certPath)
	if err != nil {
		log.Printf("Warning: CertManager init failed: %v", err)
	} else {
		log.Println("CertManager initialized.")
	}

	// 3. Setup ProxyServer
	p := proxy.NewProxyServer(":18080") 
	p.SetRuleManager(rm)
	p.SetCertGenerator(cm)
	p.UpdateCloudflareConfig(rm.GetCloudflareConfig())

	// 4. Start Proxy
	// Port 18080 is set in constructor
	port := 18080
	go func() {
		log.Printf("Starting proxy on :%d...", port)
		if err := p.Start(); err != nil {
			log.Fatalf("Proxy start failed: %v", err)
		}
	}()
	time.Sleep(2 * time.Second) // Wait for start

	// 5. Test Request
	proxyUrl, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyUrl),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Self-signed MITM cert
				NextProtos:         []string{"h2", "http/1.1"},
			},
		},
		Timeout: 30 * time.Second,
	}

	target := "https://linux.do"
	log.Printf("Sending request to %s via proxy...", target)
	resp, err := client.Get(target)
	if err != nil {
		log.Fatalf("Request passed to proxy but failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Protocol: %s\n", resp.Proto)
	
	// Print headers to see if CF handled it
	for k, v := range resp.Header {
		if k == "Server" || k == "Cf-Ray" {
			fmt.Printf("%s: %v\n", k, v)
		}
	}
}
