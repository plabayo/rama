// Independent Go client and origin for native Rama relay packet comparisons.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

const maximumBody = 65536

type options struct {
	mode, protocol, listen, url, certificate, key, ca, keylog, body, flow string
	version                                                               int
	retry                                                                 bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var args options
	flag.StringVar(&args.mode, "mode", "client", "client or origin")
	flag.StringVar(&args.protocol, "protocol", "h1", "h1, h2 or h3")
	flag.StringVar(&args.listen, "listen", "127.0.0.1:0", "origin listen address")
	flag.StringVar(&args.url, "url", "", "client target URL")
	flag.StringVar(&args.certificate, "cert", "", "origin certificate PEM")
	flag.StringVar(&args.key, "key", "", "origin private key PEM")
	flag.StringVar(&args.ca, "ca", "", "client trust anchor PEM")
	flag.StringVar(&args.keylog, "keylog", "", "new private TLS key-log file")
	flag.StringVar(&args.body, "body", "external-relay-body", "POST payload")
	flag.IntVar(&args.version, "version", 1, "QUIC version: 1 or 2")
	flag.StringVar(&args.flow, "flow", "all", "client flows: all, http or websocket")
	flag.BoolVar(&args.retry, "retry", false, "origin negative control: require QUIC Retry")
	flag.Parse()
	if args.flow != "all" && args.flow != "http" && args.flow != "websocket" {
		return fmt.Errorf("unsupported flow %q", args.flow)
	}
	if args.protocol != "h1" && args.protocol != "h2" && args.protocol != "h3" {
		return fmt.Errorf("unsupported protocol %q", args.protocol)
	}
	if args.version != 1 && args.version != 2 {
		return fmt.Errorf("unsupported QUIC version %d", args.version)
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13}
	if args.keylog != "" {
		file, err := os.OpenFile(args.keylog, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer file.Close()
		config.KeyLogWriter = file
	}
	if args.mode == "origin" {
		return serve(args, config)
	}
	if args.mode == "client" {
		return request(args, config)
	}
	return fmt.Errorf("unsupported mode %q", args.mode)
}

func quicConfig(version int) *quic.Config {
	selected := quic.Version1
	if version == 2 {
		selected = quic.Version2
	}
	return &quic.Config{
		Versions: []quic.Version{selected}, EnableDatagrams: true,
		HandshakeIdleTimeout: 5 * time.Second, MaxIdleTimeout: 15 * time.Second,
	}
}

func origin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/ws" {
		websocketOrigin(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maximumBody+1))
	if err != nil || len(body) > maximumBody {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodPost && r.Trailer.Get("X-Interop-Request-End") != "complete" {
		http.Error(w, "missing request trailer", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Interop-Peer", "Go")
	w.Header().Set("Trailer", "X-Interop-End")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		return
	}
	w.Header().Set("X-Interop-End", "complete")
}

func serve(args options, config *tls.Config) error {
	identity, err := tls.LoadX509KeyPair(args.certificate, args.key)
	if err != nil {
		return err
	}
	config.Certificates = []tls.Certificate{identity}
	stopped, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if args.protocol == "h3" {
		socket, err := net.ListenPacket("udp", args.listen)
		if err != nil {
			return err
		}
		defer socket.Close()
		server := &http3.Server{TLSConfig: config, QUICConfig: quicConfig(args.version), EnableDatagrams: true, Handler: http.HandlerFunc(origin)}
		defer server.Close()
		go func() { <-stopped.Done(); _ = server.Close() }()
		if err := ready(socket.LocalAddr().String()); err != nil {
			return err
		}
		transport := &quic.Transport{
			Conn: socket,
			// The wire fixture measures one Initial flight; Retry is an explicit negative control.
			VerifySourceAddress: func(net.Addr) bool { return args.retry },
		}
		defer transport.Close()
		listener, err := transport.ListenEarly(http3.ConfigureTLSConfig(config), quicConfig(args.version))
		if err != nil {
			return err
		}
		defer listener.Close()
		err = server.ServeListener(listener)
		if stopped.Err() != nil {
			return nil
		}
		return err
	}
	listener, err := net.Listen("tcp", args.listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{TLSConfig: config, Handler: http.HandlerFunc(origin), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second}
	if args.protocol == "h2" {
		if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
			return err
		}
		server.TLSConfig.NextProtos = []string{"h2"}
	} else {
		server.TLSConfig.NextProtos = []string{"http/1.1"}
	}
	defer server.Close()
	go func() { <-stopped.Done(); _ = server.Close() }()
	if err := ready(listener.Addr().String()); err != nil {
		return err
	}
	err = server.Serve(tls.NewListener(listener, server.TLSConfig))
	if stopped.Err() != nil {
		return nil
	}
	return err
}

func ready(address string) error {
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"ready": address, "peer": "Go"})
}

func request(args options, config *tls.Config) error {
	pem, err := os.ReadFile(args.ca)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("invalid trust anchor")
	}
	config.RootCAs, config.ServerName = roots, "localhost"
	var transport http.RoundTripper
	var closeTransport func()
	switch args.protocol {
	case "h1":
		config.NextProtos = []string{"http/1.1"}
		tcp := &http.Transport{TLSClientConfig: config, ForceAttemptHTTP2: false, DisableCompression: true}
		transport, closeTransport = tcp, tcp.CloseIdleConnections
	case "h2":
		config.NextProtos = []string{"h2"}
		tcp := &http2.Transport{TLSClientConfig: config, DisableCompression: true}
		transport, closeTransport = tcp, tcp.CloseIdleConnections
	case "h3":
		udp := &http3.Transport{TLSClientConfig: config, QUICConfig: quicConfig(args.version), EnableDatagrams: true}
		transport, closeTransport = udp, func() { _ = udp.Close() }
	}
	defer closeTransport()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	methods := []string{http.MethodGet, http.MethodPost}
	if args.flow == "websocket" {
		methods = nil
	}
	for _, method := range methods {
		body := ""
		if method == http.MethodPost {
			body = args.body
		}
		req, err := http.NewRequest(method, args.url+"/"+method, bytes.NewBufferString(body))
		if err != nil {
			return err
		}
		// A stable logical authority is independent of the ephemeral relay port.
		req.Host = "localhost"
		// Explicitly negotiate response trailers on the HTTP/1 hop as well.
		req.Header.Set("TE", "trailers")
		if args.protocol == "h1" {
			req.Header.Set("Connection", "TE")
		}
		req.Header.Set("X-Interop-First", "one")
		req.Header.Add("X-Interop-Repeat", "a")
		req.Header.Add("X-Interop-Repeat", "b")
		if method == http.MethodPost {
			req.ContentLength = -1
			req.Trailer = http.Header{"X-Interop-Request-End": []string{"complete"}}
		}
		response, err := client.Do(req)
		if err != nil {
			return err
		}
		result, err := io.ReadAll(io.LimitReader(response.Body, maximumBody+1))
		_ = response.Body.Close()
		if err != nil {
			return err
		}
		wanted := map[string]string{"h1": "HTTP/1.1", "h2": "HTTP/2.0", "h3": "HTTP/3.0"}[args.protocol]
		if response.Proto != wanted || response.StatusCode != 200 || string(result) != body || response.Trailer.Get("X-Interop-End") != "complete" {
			return fmt.Errorf("%s exchange failed: protocol=%s status=%d body=%q trailers=%v", method, response.Proto, response.StatusCode, result, response.Trailer)
		}
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"method": method, "protocol": response.Proto, "status": response.StatusCode, "body": string(result), "trailers": response.Trailer}); err != nil {
			return err
		}
	}
	if args.flow == "http" {
		return nil
	}
	return websocketRequest(args, config, transport)
}
