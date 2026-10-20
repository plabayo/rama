package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func TestHTTPContractsUseActualFramingAndBodylessResponses(t *testing.T) {
	for _, protocol := range []string{"h1", "h2"} {
		t.Run(protocol, func(t *testing.T) {
			var lock sync.Mutex
			lengths := make(map[string]int64)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				lock.Lock()
				lengths[r.URL.Path] = r.ContentLength
				lock.Unlock()
				origin(w, r)
			})
			server := httptest.NewUnstartedServer(handler)
			server.EnableHTTP2 = protocol == "h2"
			server.StartTLS()
			defer server.Close()
			const payload = "independent framing probe"
			if err := httpRequests(server.Client(), options{url: server.URL, protocol: protocol, body: payload}); err != nil {
				t.Fatal(err)
			}
			lock.Lock()
			defer lock.Unlock()
			if len(lengths) != 9 {
				t.Fatalf("expected nine distinct request/response contracts, got %d", len(lengths))
			}
			for path, expected := range map[string]int64{
				"/POST":         -1,
				"/fixed":        int64(len(payload)),
				"/empty":        0,
				"/empty-stream": -1,
			} {
				if actual, found := lengths[path]; !found || actual != expected {
					t.Errorf("%s: framing length %d (present %t), want %d", path, actual, found, expected)
				}
			}
		})
	}
}

// A real QUIC transport exposes the library's automatic 204 Content-Length;
// TCP-only httptest coverage cannot detect that invalid H3 origin behavior.
func TestH3OriginEmitsValidBodylessResponses(t *testing.T) {
	identity := httptest.NewTLSServer(http.HandlerFunc(origin))
	defer identity.Close()
	packets, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http3.Server{TLSConfig: identity.TLS.Clone(), Handler: http.HandlerFunc(origin)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(packets)
	}()
	transport := &http3.Transport{TLSClientConfig: identity.Client().Transport.(*http.Transport).TLSClientConfig.Clone()}
	defer func() {
		_ = transport.Close()
		_ = server.Close()
		_ = packets.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("owned QUIC origin failed to stop")
		}
	}()
	// RootCAs come from the independent test identity; TLS verification remains enabled.
	if err := httpRequests(&http.Client{Transport: transport, Timeout: 10 * time.Second}, options{url: "https://" + packets.LocalAddr().String(), protocol: "h3", body: "independent H3 framing probe"}); err != nil {
		t.Fatal(err)
	}
}
