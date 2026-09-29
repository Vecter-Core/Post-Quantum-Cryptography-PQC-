// Independent TLS peer (Go crypto/tls) for the hybrid TLS interop test.
// It only allows X25519MLKEM768, so a successful handshake proves both sides negotiated it.
//
//	server ADDR CERT KEY   echo server
//	client ADDR CA NAME    send a line, expect it echoed
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
)

var hybridOnly = []tls.CurveID{tls.X25519MLKEM768}

func die(err error) {
	fmt.Fprintln(os.Stderr, "tls-go:", err)
	os.Exit(1)
}

func main() {
	switch os.Args[1] {
	case "server":
		cert, err := tls.LoadX509KeyPair(os.Args[3], os.Args[4])
		if err != nil {
			die(err)
		}
		l, err := tls.Listen("tcp", os.Args[2], &tls.Config{
			Certificates:     []tls.Certificate{cert},
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: hybridOnly,
		})
		if err != nil {
			die(err)
		}
		fmt.Println("ready")
		for {
			c, err := l.Accept()
			if err != nil {
				die(err)
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	case "client":
		pem, err := os.ReadFile(os.Args[3])
		if err != nil {
			die(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		c, err := tls.Dial("tcp", os.Args[2], &tls.Config{
			RootCAs:          pool,
			ServerName:       os.Args[4],
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: hybridOnly,
		})
		if err != nil {
			die(err)
		}
		defer c.Close()
		fmt.Fprintln(c, "hello from go")
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			die(err)
		}
		fmt.Print("echo: ", line)
	}
}
