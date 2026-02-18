package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	certPath := flag.String("cert", "SNIBypassCrt.crt", "cert output path")
	keyPath := flag.String("key", "SNIBypassKey.key", "key output path")
	cn := flag.String("cn", "SniShaper Local", "certificate CN")
	flag.Parse()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: *cn,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		log.Fatal(err)
	}

	cf, err := os.Create(*certPath)
	if err != nil {
		log.Fatal(err)
	}
	defer cf.Close()
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		log.Fatal(err)
	}

	kf, err := os.Create(*keyPath)
	if err != nil {
		log.Fatal(err)
	}
	defer kf.Close()
	if err := pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		log.Fatal(err)
	}
}

