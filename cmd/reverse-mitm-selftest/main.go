package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type reverseRule struct {
	Host     string
	Upstream string
	SNIFake  string
}

type reverseMITM struct {
	listenAddr string
	rule       reverseRule
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	certMu     sync.RWMutex
	certCache  map[string]*tls.Certificate
	ln         net.Listener
}

func newReverseMITM(listenAddr string, rule reverseRule) (*reverseMITM, error) {
	caCert, caKey, err := generateCA()
	if err != nil {
		return nil, err
	}
	return &reverseMITM{
		listenAddr: listenAddr,
		rule:       rule,
		caCert:     caCert,
		caKey:      caKey,
		certCache:  map[string]*tls.Certificate{},
	}, nil
}

func (r *reverseMITM) start() error {
	ln, err := net.Listen("tcp", r.listenAddr)
	if err != nil {
		return err
	}
	r.ln = ln
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				log.Printf("reverse accept error: %v", err)
				continue
			}
			go r.handleConn(conn)
		}
	}()
	return nil
}

func (r *reverseMITM) stop() error {
	if r.ln == nil {
		return nil
	}
	return r.ln.Close()
}

func (r *reverseMITM) handleConn(clientRaw net.Conn) {
	defer clientRaw.Close()
	_ = clientRaw.SetDeadline(time.Now().Add(15 * time.Second))

	leafCert, err := r.getOrCreateLeafCert(r.rule.Host)
	if err != nil {
		log.Printf("leaf cert failed: %v", err)
		return
	}
	clientTLS := tls.Server(clientRaw, &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
		NextProtos:   []string{"http/1.1"},
	})
	if err := clientTLS.Handshake(); err != nil {
		log.Printf("client tls handshake failed: %v", err)
		return
	}
	_ = clientRaw.SetDeadline(time.Time{})

	upRaw, err := net.DialTimeout("tcp", r.rule.Upstream, 10*time.Second)
	if err != nil {
		log.Printf("upstream dial failed: %v", err)
		return
	}
	defer upRaw.Close()
	_ = upRaw.SetDeadline(time.Now().Add(15 * time.Second))

	sni := strings.TrimSpace(r.rule.SNIFake)
	if sni == "" {
		sni = r.rule.Host
	}
	upTLS := tls.Client(upRaw, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	})
	if err := upTLS.Handshake(); err != nil {
		log.Printf("upstream tls handshake failed: %v", err)
		return
	}
	_ = upRaw.SetDeadline(time.Time{})

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upTLS, clientTLS)
		_ = upTLS.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientTLS, upTLS)
		_ = clientTLS.Close()
	}()
	wg.Wait()
}

func (r *reverseMITM) getOrCreateLeafCert(host string) (*tls.Certificate, error) {
	r.certMu.RLock()
	if c, ok := r.certCache[host]; ok {
		r.certMu.RUnlock()
		return c, nil
	}
	r.certMu.RUnlock()

	cert, err := generateLeaf(r.caCert, r.caKey, host)
	if err != nil {
		return nil, err
	}

	r.certMu.Lock()
	r.certCache[host] = cert
	r.certMu.Unlock()
	return cert, nil
}

func generateCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "ReverseMITM Test CA",
			Organization: []string{"SniShaper Lab"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func generateLeaf(ca *x509.Certificate, caKey *rsa.PrivateKey, host string) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &pair, nil
}

type tinyDNS struct {
	addr   string
	host   string
	target net.IP
	conn   *net.UDPConn
}

func newTinyDNS(addr, host string, target net.IP) *tinyDNS {
	return &tinyDNS{addr: addr, host: strings.ToLower(strings.TrimSuffix(host, ".")), target: target}
}

func (d *tinyDNS) start() error {
	udpAddr, err := net.ResolveUDPAddr("udp", d.addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	d.conn = conn
	go d.loop()
	return nil
}

func (d *tinyDNS) stop() error {
	if d.conn == nil {
		return nil
	}
	return d.conn.Close()
}

func (d *tinyDNS) loop() {
	buf := make([]byte, 1500)
	for {
		n, addr, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("dns read error: %v", err)
			continue
		}
		resp, err := d.handlePacket(buf[:n])
		if err != nil {
			log.Printf("dns handle error: %v", err)
			continue
		}
		if _, err := d.conn.WriteToUDP(resp, addr); err != nil {
			log.Printf("dns write error: %v", err)
		}
	}
}

func (d *tinyDNS) handlePacket(pkt []byte) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(pkt)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	_ = p.SkipAllQuestions()

	name := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 h.ID,
		Response:           true,
		RecursionAvailable: true,
	})
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(q); err != nil {
		return nil, err
	}
	if err := builder.StartAnswers(); err != nil {
		return nil, err
	}
	if q.Type == dnsmessage.TypeA && name == d.host {
		ip4 := d.target.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("target ip is not ipv4: %v", d.target)
		}
		if err := builder.AResource(dnsmessage.ResourceHeader{
			Name:  q.Name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   30,
		}, dnsmessage.AResource{A: [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}}); err != nil {
			return nil, err
		}
	}
	return builder.Finish()
}

func startMockUpstream(addr string, sniCh chan<- string) (net.Listener, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "upstream.local",
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"upstream.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, "", err
	}

	ln, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{pair},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case sniCh <- chi.ServerName:
			default:
			}
			return nil, nil
		},
		NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		return nil, "", err
	}

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
				reader := bufio.NewReader(conn)
				req, err := http.ReadRequest(reader)
				if err != nil {
					return
				}
				_ = req.Body.Close()
				resp := &http.Response{
					StatusCode: 200,
					Status:     "200 OK",
					Proto:      "HTTP/1.1",
					ProtoMajor: 1,
					ProtoMinor: 1,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("ok")),
				}
				resp.Header.Set("Content-Length", "2")
				_ = resp.Write(conn)
			}(c)
		}
	}()
	return ln, ln.Addr().String(), nil
}

func queryA(serverAddr, host string) (string, error) {
	var m dnsmessage.Message
	m.Header.RecursionDesired = true
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return "", err
	}
	m.Questions = []dnsmessage.Question{{
		Name:  name,
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}}
	wire, err := m.Pack()
	if err != nil {
		return "", err
	}

	conn, err := net.Dial("udp", serverAddr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(wire); err != nil {
		return "", err
	}
	respBuf := make([]byte, 1500)
	n, err := conn.Read(respBuf)
	if err != nil {
		return "", err
	}
	var out dnsmessage.Message
	if err := out.Unpack(respBuf[:n]); err != nil {
		return "", err
	}
	for _, ans := range out.Answers {
		if a, ok := ans.Body.(*dnsmessage.AResource); ok {
			ip := net.IPv4(a.A[0], a.A[1], a.A[2], a.A[3])
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no a answer")
}

func runSelfTest() error {
	log.Printf("[selftest] starting mock upstream...")
	sniCh := make(chan string, 4)
	upstreamLN, upstreamAddr, err := startMockUpstream("127.0.0.1:0", sniCh)
	if err != nil {
		return err
	}
	defer upstreamLN.Close()

	log.Printf("[selftest] starting reverse mitm...")
	rule := reverseRule{
		Host:     "example.test",
		Upstream: upstreamAddr,
		SNIFake:  "g.cn",
	}
	rev, err := newReverseMITM("127.0.0.1:0", rule)
	if err != nil {
		return err
	}
	if err := rev.start(); err != nil {
		return err
	}
	defer rev.stop()

	log.Printf("[selftest] starting tiny dns...")
	dnsSrv := newTinyDNS("127.0.0.1:0", "example.test", net.ParseIP("127.0.0.1").To4())
	if err := dnsSrv.start(); err != nil {
		return err
	}
	defer dnsSrv.stop()

	dnsAddr := dnsSrv.conn.LocalAddr().String()
	gotIP, err := queryA(dnsAddr, "example.test")
	if err != nil {
		return fmt.Errorf("dns selftest failed: %w", err)
	}
	if gotIP != "127.0.0.1" {
		return fmt.Errorf("dns selftest got ip=%s, want 127.0.0.1", gotIP)
	}
	log.Printf("[selftest] dns ok: example.test -> %s", gotIP)

	reverseAddr := rev.ln.Addr().String()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         "example.test",
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 5 * time.Second}
				return tls.DialWithDialer(d, "tcp", reverseAddr, &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         "example.test",
					NextProtos:         []string{"http/1.1"},
				})
			},
		},
		Timeout: 8 * time.Second,
	}
	req, _ := http.NewRequest(http.MethodGet, "https://example.test/", nil)
	req.Host = "example.test"
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("reverse selftest request failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "ok" {
		return fmt.Errorf("reverse selftest bad response: code=%d body=%q", resp.StatusCode, string(body))
	}

	select {
	case sni := <-sniCh:
		if sni != "g.cn" {
			return fmt.Errorf("upstream sni mismatch: got=%q want=%q", sni, "g.cn")
		}
		log.Printf("[selftest] upstream sni ok: %s", sni)
	case <-time.After(3 * time.Second):
		return fmt.Errorf("no upstream sni captured")
	}
	log.Printf("[selftest] PASS")
	return nil
}

func exportCAPEM() error {
	ca, key, err := generateCA()
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	fmt.Printf("%s\n%s\n", certPEM, keyPEM)
	return nil
}

func main() {
	mode := flag.String("mode", "selftest", "selftest|export-ca")
	flag.Parse()

	switch *mode {
	case "selftest":
		if err := runSelfTest(); err != nil {
			log.Fatalf("selftest failed: %v", err)
		}
	case "export-ca":
		if err := exportCAPEM(); err != nil {
			log.Fatalf("export-ca failed: %v", err)
		}
	default:
		log.Fatalf("unknown mode: %s", *mode)
	}
}
