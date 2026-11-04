// Early-data HTTP interop. quic-go owns TLS, QUIC and HTTP/3; this fixture owns
// a deliberately explicit 425 recovery policy, independent of either library.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type earlyConnectionKey struct{}

// Delay the first packet read so early writes cannot lose a loopback scheduling
// race to handshake completion. Subsequent traffic is unmodified.
type earlyReadGate struct {
	net.PacketConn
	once sync.Once
}

func (c *earlyReadGate) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	c.once.Do(func() { time.Sleep(100 * time.Millisecond) })
	return n, addr, err
}

// Hold each connection's first server flight so the client has time to write
// its early request, independent of local scheduler speed.
type earlyWriteGate struct {
	net.PacketConn
	peers sync.Map
}

func (c *earlyWriteGate) WriteTo(p []byte, addr net.Addr) (int, error) {
	if _, seen := c.peers.LoadOrStore(addr.String(), true); !seen {
		time.Sleep(100 * time.Millisecond)
	}
	return c.PacketConn.WriteTo(p, addr)
}

func runEarly(args []string) {
	f := flag.NewFlagSet("early", flag.ExitOnError)
	mode := f.String("mode", "server", "server or client")
	addr := f.String("address", "127.0.0.1:0", "listen or peer address")
	cert := f.String("cert", "", "server certificate")
	key := f.String("key", "", "server private key")
	ca := f.String("ca", "", "trusted test authority")
	f.Parse(args)
	var err error
	switch *mode {
	case "server":
		err = serveEarly(*addr, *cert, *key)
	case "client":
		err = requestEarly(*addr, *ca)
	default:
		err = fmt.Errorf("unknown early mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serveEarly(address, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	socket, err := net.ListenPacket("udp", address)
	if err != nil {
		return err
	}
	defer socket.Close()
	server := &http3.Server{
		TLSConfig:  &tls.Config{Certificates: []tls.Certificate{cert}},
		QUICConfig: &quic.Config{Allow0RTT: true},
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			return context.WithValue(ctx, earlyConnectionKey{}, conn)
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn := r.Context().Value(earlyConnectionKey{}).(*quic.Conn)
			w.Header().Set("x-quic-used-0rtt", fmt.Sprint(conn.ConnectionState().Used0RTT))
			if r.URL.Path == "/warm" {
				io.WriteString(w, "warm")
				return
			}
			if r.Header.Get("x-confirmed") != "1" {
				w.Header().Set("x-rejection", "preserved")
				w.WriteHeader(http.StatusTooEarly)
				io.WriteString(w, "retry after confirmation")
				return
			}
			select {
			case <-conn.HandshakeComplete():
			default:
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if r.Header.Get("Early-Data") != "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			io.WriteString(w, "processed once")
		}),
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"address": socket.LocalAddr().String()}); err != nil {
		return err
	}
	return server.Serve(&earlyWriteGate{PacketConn: socket})
}

func requestEarly(address, caFile string) error {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("no test roots")
	}
	config := &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{http3.NextProtoH3}, ClientSessionCache: tls.NewLRUClientSessionCache(4)}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dial := func() (*quic.Conn, *http3.ClientConn, net.PacketConn, error) {
		socket, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return nil, nil, nil, err
		}
		remote, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			socket.Close()
			return nil, nil, nil, err
		}
		conn, err := quic.DialEarly(ctx, &earlyReadGate{PacketConn: socket}, remote, config, &quic.Config{})
		if err != nil {
			socket.Close()
			return nil, nil, nil, err
		}
		return conn, (&http3.Transport{}).NewClientConn(conn), socket, nil
	}
	exchange := func(client *http3.ClientConn, method, path string, confirmed bool) (int, string, error) {
		req, err := http.NewRequestWithContext(ctx, method, "https://"+address+path, nil)
		if err != nil {
			return 0, "", err
		}
		if confirmed {
			req.Header.Set("x-confirmed", "1")
		}
		response, err := client.RoundTrip(req)
		if err != nil {
			return 0, "", err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		return response.StatusCode, string(body), err
	}
	warm, client, socket, err := dial()
	if err != nil {
		return err
	}
	status, _, err := exchange(client, http.MethodGet, "/warm", false)
	warm.CloseWithError(0, "warm complete")
	socket.Close()
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("warm status %d", status)
	}
	conn, client, socket, err := dial()
	if err != nil {
		return err
	}
	defer socket.Close()
	defer conn.CloseWithError(0, "complete")
	status, _, err = exchange(client, http3.MethodGet0RTT, "/operation", false)
	if err != nil {
		return err
	}
	if status != 425 {
		return fmt.Errorf("early status %d, expected 425", status)
	}
	select {
	case <-conn.HandshakeComplete():
	case <-ctx.Done():
		return ctx.Err()
	}
	if !conn.ConnectionState().Used0RTT {
		return errors.New("no actual 0-RTT acceptance")
	}
	status, body, err := exchange(client, http.MethodGet, "/operation", true)
	if err != nil {
		return err
	}
	if status != 200 || body != "processed once" {
		return fmt.Errorf("confirmed response %d %q", status, body)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "used_0rtt": true, "recovered_425": true})
}
