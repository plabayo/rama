// Command peer is the independent MASQUE peer of Rama's CONNECT-UDP interop tests:
// masque-go as a proxy, or as a client tunneling HTTP/3 through a proxy.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: peer proxy|client [flags]")
	}
	switch os.Args[1] {
	case "proxy":
		runProxy(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	default:
		log.Fatalf("unknown role %q", os.Args[1])
	}
}

// runProxy serves CONNECT-UDP for template on bind, printing "ready" once listening.
func runProxy(args []string) {
	flags := flag.NewFlagSet("proxy", flag.ExitOnError)
	templateStr := flags.String("t", "", "URI template")
	bind := flags.String("b", "127.0.0.1:0", "UDP address to bind")
	_ = flags.Parse(args)
	template, err := uritemplate.New(*templateStr)
	if err != nil {
		log.Fatalf("invalid template: %v", err)
	}
	u, err := url.Parse(*templateStr)
	if err != nil {
		log.Fatalf("invalid template URL: %v", err)
	}
	cert, err := selfSigned()
	if err != nil {
		log.Fatalf("certificate: %v", err)
	}
	conn, err := net.ListenPacket("udp", *bind)
	if err != nil {
		log.Fatalf("bind: %v", err)
	}
	proxy := masque.Proxy{}
	mux := http.NewServeMux()
	mux.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		req, err := masque.ParseProxyRequest(r, template)
		if err != nil {
			if perr, ok := errors.AsType[*masque.ProxyRequestParseError](err); ok {
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = proxy.Proxy(w, req)
	})
	server := http3.Server{
		Handler:         mux,
		TLSConfig:       http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		EnableDatagrams: true,
		QUICConfig:      &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350, MaxIdleTimeout: 3 * time.Minute},
	}
	fmt.Printf("ready %s\n", conn.LocalAddr())
	if err := server.Serve(conn); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

// runClient GETs url n times, each over a new CONNECT-UDP tunnel through the proxy template,
// printing one line per success and exiting non-zero on the first failure.
func runClient(args []string) {
	flags := flag.NewFlagSet("client", flag.ExitOnError)
	templateStr := flags.String("t", "", "proxy URI template")
	runs := flags.Int("n", 1, "consecutive runs")
	_ = flags.Parse(args)
	if flags.NArg() != 1 {
		log.Fatal("usage: peer client -t <template> [-n runs] <url>")
	}
	target, err := url.Parse(flags.Arg(0))
	if err != nil {
		log.Fatalf("url: %v", err)
	}
	template := uritemplate.MustNew(*templateStr)
	insecure := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // loopback test peers
	for run := 1; run <= *runs; run++ {
		body, err := getThrough(template, target, insecure)
		if err != nil {
			log.Fatalf("run %d: %v", run, err)
		}
		fmt.Printf("run %d ok: %q\n", run, body)
	}
}

func getThrough(template *uritemplate.Template, target *url.URL, insecure *tls.Config) (string, error) {
	tunnels := masque.Transport{
		TLSClientConfig: http3.ConfigureTLSConfig(insecure),
		QUICConfig:      &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350},
	}
	// Each tunnel is closed after its run, ending its CONNECT-UDP stream and outer connection:
	// QUIC never closes a packet connection it was handed.
	var opened []*masque.Conn
	defer func() {
		// The inner connection's close is a datagram queued on the tunnel: let it leave
		// before closing the tunnel takes the outer connection down with it.
		time.Sleep(100 * time.Millisecond)
		for _, tunnel := range opened {
			_ = tunnel.Close()
		}
	}()
	transport := &http3.Transport{
		TLSClientConfig: insecure,
		Dial: func(ctx context.Context, _ string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
			remote, err := net.ResolveUDPAddr("udp", target.Host)
			if err != nil {
				return nil, err
			}
			req, err := masque.NewRequest(ctx, template, remote.String())
			if err != nil {
				return nil, err
			}
			tunnel, rsp, err := tunnels.Dial(req)
			if err != nil {
				return nil, fmt.Errorf("CONNECT-UDP: %w", err)
			}
			opened = append(opened, tunnel)
			if rsp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("CONNECT-UDP status %d", rsp.StatusCode)
			}
			quicConf = quicConf.Clone()
			quicConf.DisablePathMTUDiscovery = true
			return quic.DialEarly(ctx, tunnel, remote, tlsConf, quicConf)
		},
	}
	defer transport.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return "", err
	}
	rsp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return "", err
	}
	defer rsp.Body.Close()
	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		return "", err
	}
	if rsp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", rsp.StatusCode)
	}
	return string(body), nil
}

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "masque-go interop peer"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
