// Independent HTTP/3 and CONNECT-UDP oracle. Protocol implementations come from
// quic-go and masque-go; this program only supplies deterministic workloads.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

var mode = flag.String("mode", "server", "server, client, masque-client, or tunneled-client")
var address = flag.String("address", "127.0.0.1:0", "listen or peer address")
var certificate = flag.String("cert", "", "server certificate")
var key = flag.String("key", "", "server private key")
var authority = flag.String("ca", "", "trusted test authority")
var templatePath = flag.String("template", "/.well-known/masque/udp/{target_host}/{target_port}/", "proxy URI template path")
var target = flag.String("target", "", "UDP target")
var auth = flag.String("auth", "", "Proxy-Authorization value")
var expectedStatus = flag.Int("expect-status", 200, "expected CONNECT-UDP status")

func runCoverage(args []string) {
	flag.CommandLine.Parse(args)
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if *mode == "server" {
		return serve()
	}
	if *mode != "client" && *mode != "masque-client" && *mode != "tunneled-client" {
		return fmt.Errorf("unknown coverage mode %q", *mode)
	}
	tlsConfig := &tls.Config{ServerName: "localhost", NextProtos: []string{http3.NextProtoH3}}
	if *authority == "" {
		tlsConfig.InsecureSkipVerify = true // loopback fixture only
	} else {
		pem, err := os.ReadFile(*authority)
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return errors.New("no test roots")
		}
		tlsConfig.RootCAs = roots
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if *mode == "masque-client" {
		return udpClient(ctx, tlsConfig)
	}
	tr := &http3.Transport{TLSClientConfig: tlsConfig}
	if *mode == "tunneled-client" {
		var sockets []net.PacketConn
		var socketMu sync.Mutex
		defer func() {
			socketMu.Lock()
			defer socketMu.Unlock()
			for _, s := range sockets {
				s.Close()
			}
		}()
		proxy := &masque.Transport{TLSClientConfig: tlsConfig}
		tr.Dial = func(ctx context.Context, addr string, tlsConf *tls.Config, qconf *quic.Config) (*quic.Conn, error) {
			req, err := masque.NewRequest(ctx, uritemplate.MustNew("https://"+*address+*templatePath), addr)
			if err != nil {
				return nil, err
			}
			if *auth != "" {
				req.Header().Set("Proxy-Authorization", *auth)
			}
			socket, _, err := proxy.Dial(req)
			if err != nil {
				return nil, err
			}
			socketMu.Lock()
			sockets = append(sockets, socket)
			socketMu.Unlock()
			remote, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			qconf = qconf.Clone()
			qconf.DisablePathMTUDiscovery = true
			qconf.InitialPacketSize = 1200
			return quic.DialEarly(ctx, socket, remote, tlsConf, qconf)
		}
	}
	// Close the inner connection before closing its outer CONNECT-UDP sockets.
	defer func() { cancel(); tr.Close() }()
	base := "https://" + *address
	if *mode == "tunneled-client" {
		base = "https://" + *target
	}
	if err := httpWorkload(ctx, &http.Client{Transport: tr}, base); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "mode": *mode})
}

func serve() error {
	var cert tls.Certificate
	var err error
	if *certificate == "" {
		cert, err = selfSigned()
	} else {
		cert, err = tls.LoadX509KeyPair(*certificate, *key)
	}
	if err != nil {
		return err
	}
	socket, err := net.ListenPacket("udp", *address)
	if err != nil {
		return err
	}
	defer socket.Close()
	proxy := &masque.Proxy{}
	defer proxy.Close()
	template := uritemplate.MustNew("https://" + socket.LocalAddr().String() + *templatePath)
	server := &http3.Server{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		// This origin is also reached through CONNECT-UDP. Leave room for the
		// outer QUIC/HTTP datagram headers and do not probe beyond that inner MTU.
		QUICConfig:      &quic.Config{EnableDatagrams: true, InitialPacketSize: 1200, DisablePathMTUDiscovery: true},
		EnableDatagrams: true,
	}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-observed-peer", r.RemoteAddr)
		fmt.Printf("request peer=%s path=%s\n", r.RemoteAddr, r.URL.Path)
		if r.URL.Path == "/" {
			w.Write([]byte("independent quic-go origin"))
			return
		}
		if r.Method == http.MethodConnect {
			if *auth != "" && r.Header.Get("Proxy-Authorization") != *auth {
				w.WriteHeader(407)
				return
			}
			req, err := masque.ParseProxyRequest(r, template)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			if err := proxy.Proxy(w, req); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
			return
		}
		if r.URL.Path == "/status" {
			w.WriteHeader(418)
			return
		}
		if r.URL.Path == "/cancel" {
			buf := bytes.Repeat([]byte{0x71}, 16384)
			for i := 0; i < 1024; i++ {
				if _, err := w.Write(buf); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
			return
		}
		if r.URL.Path != "/echo" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Trailer", "x-body-sha256")
		w.Header().Set("x-peer", "quic-go")
		hash := sha256.New()
		if _, err := io.Copy(io.MultiWriter(w, hash), r.Body); err != nil {
			return
		}
		w.Header().Set("x-body-sha256", fmt.Sprintf("%x", hash.Sum(nil)))
	})
	defer server.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); server.Close() }()
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{"address": socket.LocalAddr().String()}); err != nil {
		return err
	}
	err = server.Serve(socket)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func httpWorkload(ctx context.Context, client *http.Client, base string) error {
	check := func(size int, seed byte) error {
		body := bytes.Repeat([]byte{seed}, size)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/echo", io.NopCloser(bytes.NewReader(body)))
		if err != nil {
			return err
		}
		// An unknown request length forces streaming instead of relying on Content-Length.
		req.ContentLength = -1
		req.Header.Set("x-repeated-header", strings.Repeat("independent-interop-", 32))
		if size == 997 {
			req.Header.Set("x-after-cancel", "1")
		}
		rsp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer rsp.Body.Close()
		got, err := io.ReadAll(rsp.Body)
		if err != nil {
			return err
		}
		if rsp.StatusCode != 200 || rsp.ProtoMajor != 3 || !bytes.Equal(got, body) {
			return errors.New("HTTP/3 echo status/version/payload mismatch")
		}
		want := fmt.Sprintf("%x", sha256.Sum256(body))
		if rsp.Trailer.Get("x-body-sha256") != want {
			return fmt.Errorf("trailer mismatch: %q != %q", rsp.Trailer.Get("x-body-sha256"), want)
		}
		return nil
	}
	if err := check(2<<20, 0x52); err != nil {
		return err
	}
	var wg sync.WaitGroup
	errorsCh := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); errorsCh <- check(32768+i, byte(i)) }(i)
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			return err
		}
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", base+"/cancel", nil)
	rsp, err := client.Do(req)
	if err != nil {
		return err
	}
	buf := make([]byte, 1024)
	_, err = io.ReadFull(rsp.Body, buf)
	rsp.Body.Close()
	if err != nil {
		return err
	}
	if err := check(997, 0x63); err != nil {
		return fmt.Errorf("request after cancellation: %w", err)
	}
	req, _ = http.NewRequestWithContext(ctx, "GET", base+"/status", nil)
	rsp, err = client.Do(req)
	if err != nil {
		return err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != 418 {
		return errors.New("application status lost")
	}
	return nil
}

func udpClient(ctx context.Context, tlsConfig *tls.Config) error {
	conn, err := quic.DialAddr(ctx, *address, tlsConfig, &quic.Config{EnableDatagrams: true, InitialPacketSize: 1400})
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "finished")
	tr := &masque.Transport{}
	client, err := tr.NewClientConn(conn)
	if err != nil {
		return err
	}
	var sockets []*masque.Conn
	defer func() {
		for _, socket := range sockets {
			socket.Close()
		}
	}()
	for i := 0; i < 8; i++ {
		req, err := masque.NewRequest(ctx, uritemplate.MustNew("https://"+*address+*templatePath), *target)
		if err != nil {
			return err
		}
		if *auth != "" {
			req.Header().Set("Proxy-Authorization", *auth)
		}
		socket, rsp, err := client.Dial(req)
		if *expectedStatus != 200 {
			if err == nil || rsp == nil || rsp.StatusCode != *expectedStatus {
				return fmt.Errorf("expected refusal %d, got response %v and error %v", *expectedStatus, rsp, err)
			}
			if *expectedStatus == 502 && !strings.Contains(rsp.Header.Get("Proxy-Status"), "destination_ip_prohibited") {
				return fmt.Errorf("expected destination policy refusal, got %q", rsp.Header.Get("Proxy-Status"))
			}
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "refused": rsp.StatusCode})
		}
		if err != nil {
			return err
		}
		sockets = append(sockets, socket)
		if rsp.StatusCode != 200 {
			return fmt.Errorf("tunnel status %d", rsp.StatusCode)
		}
	}
	for i, socket := range sockets {
		for _, size := range []int{0, 1, 1000, 1200} {
			payload := bytes.Repeat([]byte{byte(i + 1)}, size)
			socket.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := socket.WriteTo(payload, nil); err != nil {
				return err
			}
			buf := make([]byte, 1600)
			n, _, err := socket.ReadFrom(buf)
			if err != nil {
				return err
			}
			if !bytes.Equal(payload, buf[:n]) {
				return errors.New("UDP payload crossed tunnel contexts or changed")
			}
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "tunnels": len(sockets), "target": url.QueryEscape(*target)})
}
