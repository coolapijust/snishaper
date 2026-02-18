package main

import (
	"crypto/tls"
	"flag"
	"fmt"
)

func main() {
	cert := flag.String("cert", "", "cert path")
	key := flag.String("key", "", "key path")
	flag.Parse()
	if *cert == "" || *key == "" {
		fmt.Println("usage: go run ./cmd/checkpair -cert a.crt -key a.key")
		return
	}
	_, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		fmt.Printf("PAIR_FAIL err=%v\n", err)
		return
	}
	fmt.Println("PAIR_OK")
}

