package main

// Independent capsule-only clients. Go's HTTP/1.1 and HTTP/2 stacks and quic-go
// own the HTTP framing; quic-go's capsule codec owns RFC 9297 framing. Native
// QUIC datagrams are explicitly disabled on the inner HTTP/3 connection.
import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	masque "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

var carrier = flag.String("carrier", "h3", "capsule carrier: h1, h2, h3")
var via = flag.String("via", "", "intercepting outer proxy address")
var viaAuth = flag.String("via-auth", "", "outer Proxy-Authorization value")

type capsuleSession struct {
	reader      io.Reader
	writer      io.Writer
	close       func()
	response    *http.Response
	certificate string
}

func capsuleRequest(ctx context.Context) (*http.Request, error) {
	host, port, err := net.SplitHostPort(*target)
	if err != nil {
		return nil, err
	}
	variables := uritemplate.Values{}
	variables.Set("target_host", uritemplate.String(host))
	variables.Set("target_port", uritemplate.String(port))
	uri, err := uritemplate.MustNew("https://" + *address + *templatePath).Expand(variables)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, uri, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Capsule-Protocol", "?1")
	if *auth != "" {
		req.Header.Set("Proxy-Authorization", *auth)
	}
	return req, nil
}

func dialProxyQUIC(ctx context.Context, tlsConfig *tls.Config, native bool) (*quic.Conn, func(), error) {
	size := uint16(1200)
	if native && *via == "" {
		size = 1400
	}
	qconf := &quic.Config{EnableDatagrams: native, InitialPacketSize: size, DisablePathMTUDiscovery: true}
	var conn *quic.Conn
	var outer net.PacketConn
	var err error
	if *via == "" {
		conn, err = dialQUIC(ctx, *address, tlsConfig, qconf)
	} else {
		transport := &masque.Transport{TLSClientConfig: tlsConfig, DialAddr: dialQUIC}
		request, e := masque.NewRequest(ctx, uritemplate.MustNew("https://"+*via+"/.well-known/masque/udp/{target_host}/{target_port}/"), *address)
		if e != nil {
			return nil, nil, e
		}
		request.Header().Set("Proxy-Authorization", *viaAuth)
		outer, _, err = transport.Dial(request)
		if err != nil {
			return nil, nil, err
		}
		remote, e := net.ResolveUDPAddr("udp", *address)
		if e != nil {
			outer.Close()
			return nil, nil, e
		}
		conn, err = quic.Dial(ctx, outer, remote, tlsConfig, qconf)
	}
	if err != nil {
		if outer != nil {
			outer.Close()
		}
		return nil, nil, err
	}
	return conn, func() {
		conn.CloseWithError(0, "finished")
		if outer != nil {
			outer.Close()
		}
	}, nil
}

func capsuleOpen(ctx context.Context, tlsConfig *tls.Config) (*capsuleSession, error) {
	req, err := capsuleRequest(ctx)
	if err != nil {
		return nil, err
	}
	fingerprint := func(state tls.ConnectionState) string {
		return fmt.Sprintf("%x", sha256.Sum256(state.PeerCertificates[0].Raw))
	}
	if *carrier == "h3" {
		conn, cleanup, err := dialProxyQUIC(ctx, tlsConfig, false)
		if err != nil {
			return nil, err
		}
		if conn.ConnectionState().SupportsDatagrams.Local {
			cleanup()
			return nil, errors.New("native datagrams unexpectedly enabled")
		}
		tr := &http3.Transport{EnableDatagrams: false}
		client := tr.NewClientConn(conn)
		select {
		case <-client.ReceivedSettings():
		case <-ctx.Done():
			cleanup()
			return nil, ctx.Err()
		}
		if !client.Settings().EnableExtendedConnect {
			cleanup()
			return nil, errors.New("extended CONNECT not advertised")
		}
		stream, e := client.OpenRequestStream(ctx)
		if e != nil {
			cleanup()
			return nil, e
		}
		req.Proto = "connect-udp"
		if e = stream.SendRequestHeader(req); e != nil {
			cleanup()
			return nil, e
		}
		response, e := stream.ReadResponse()
		if e != nil {
			cleanup()
			return nil, e
		}
		return &capsuleSession{stream, stream, cleanup, response, fingerprint(conn.ConnectionState().TLS)}, nil
	}
	if *carrier != "h1" && *carrier != "h2" {
		return nil, fmt.Errorf("unknown carrier %q", *carrier)
	}
	destination := *address
	if *via != "" {
		destination = *via
	}
	socket, err := (&net.Dialer{}).DialContext(ctx, "tcp", destination)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		socket.SetDeadline(deadline)
	}
	if *via != "" {
		_, err = fmt.Fprintf(socket, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n", *address, *address, *viaAuth)
		if err != nil {
			socket.Close()
			return nil, err
		}
		reader := bufio.NewReader(socket)
		response, e := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
		if e != nil {
			socket.Close()
			return nil, e
		}
		if response.StatusCode != 200 || reader.Buffered() != 0 {
			socket.Close()
			return nil, fmt.Errorf("outer CONNECT status %d or unexpected buffered data", response.StatusCode)
		}
	}
	config := tlsConfig.Clone()
	config.NextProtos = []string{"http/1.1"}
	if *carrier == "h2" {
		config.NextProtos = []string{"h2"}
	}
	secured := tls.Client(socket, config)
	if err := secured.HandshakeContext(ctx); err != nil {
		socket.Close()
		return nil, err
	}
	certificate := fingerprint(secured.ConnectionState())
	if *carrier == "h1" {
		req.Method = http.MethodGet
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "connect-udp")
		if err := req.Write(secured); err != nil {
			secured.Close()
			return nil, err
		}
		reader := bufio.NewReader(secured)
		response, err := http.ReadResponse(reader, req)
		if err != nil {
			secured.Close()
			return nil, err
		}
		return &capsuleSession{reader, secured, func() { secured.Close() }, response, certificate}, nil
	}
	client, err := (&http2.Transport{}).NewClientConn(secured)
	if err != nil {
		secured.Close()
		return nil, err
	}
	input, output := io.Pipe()
	req.Body = input
	req.Header.Set(":protocol", "connect-udp")
	response, err := client.RoundTrip(req)
	if err != nil {
		input.Close()
		output.Close()
		client.Close()
		return nil, err
	}
	return &capsuleSession{response.Body, output, func() { output.Close(); response.Body.Close(); client.Close() }, response, certificate}, nil
}

func capsuleClient(ctx context.Context, tlsConfig *tls.Config) error {
	var certificate string
	for tunnel := 0; tunnel < 8; tunnel++ {
		session, err := capsuleOpen(ctx, tlsConfig)
		if err != nil {
			return err
		}
		err = func() error {
			defer session.close()
			if *via == "" && certificate != "" && certificate != session.certificate {
				return errors.New("direct proxy certificate changed between connections")
			}
			certificate = session.certificate
			expected := *expectedStatus
			if expected == 200 && *carrier == "h1" {
				expected = 101
			}
			if session.response.StatusCode != expected {
				return fmt.Errorf("expected %d, got %d", expected, session.response.StatusCode)
			}
			if *expectedStatus != 200 {
				if *expectedStatus == 502 && !strings.Contains(session.response.Header.Get("Proxy-Status"), "destination_ip_prohibited") {
					return errors.New("missing private-target policy evidence")
				}
				return nil
			}
			if session.response.Header.Get("Capsule-Protocol") != "?1" {
				return errors.New("capsule protocol was not accepted")
			}
			if *carrier == "h1" && !strings.EqualFold(session.response.Header.Get("Upgrade"), "connect-udp") {
				return errors.New("wrong HTTP/1.1 upgrade protocol")
			}
			writer := quicvarint.NewWriter(session.writer)
			// Unknown capsule types and unregistered context IDs must not leak
			// to UDP or disturb subsequent context-zero datagrams.
			if err := http3.WriteCapsule(writer, 0x1234, []byte("ignored")); err != nil {
				return err
			}
			if err := http3.WriteCapsule(writer, 0, []byte{1, 0x42}); err != nil {
				return err
			}
			parser := http3.NewCapsuleParser(session.reader)
			for _, size := range []int{0, 1, 1000, 1200} {
				payload := bytes.Repeat([]byte{byte(tunnel + 1)}, size)
				framed := append([]byte{0}, payload...)
				if err := http3.WriteCapsule(writer, 0, framed); err != nil {
					return err
				}
				var value io.Reader
				for {
					kind, next, err := parser.Next()
					if err != nil {
						return err
					}
					if kind == 0 {
						value = next
						break
					}
					// RFC 9297 permits unknown capsule types, including grease.
					if _, err := io.Copy(io.Discard, next); err != nil {
						return err
					}
				}
				received, err := io.ReadAll(io.LimitReader(value, 2048))
				if err != nil {
					return err
				}
				if !bytes.Equal(received, framed) {
					return errors.New("capsule context or UDP bytes changed")
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
		if *expectedStatus != 200 {
			break
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": true, "carrier": *carrier, "native_datagrams": false, "peer_certificate_sha256": certificate, "refused": *expectedStatus != 200})
}
