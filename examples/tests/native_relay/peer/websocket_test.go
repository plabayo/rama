package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

// An origin may wait for request EOF before completing its response. Exercise
// the real probe through both CONNECT transports with that ordering requirement.
func TestWebsocketConnectFinishesRequestBeforeCloseReply(t *testing.T) {
	for _, protocol := range []string{"h2", "h3"} {
		t.Run(protocol, func(t *testing.T) {
			completed := make(chan error, 1)
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				response, output := io.Pipe()
				finished := make(chan struct{})
				go func() {
					select {
					case <-request.Context().Done():
						_ = output.CloseWithError(request.Context().Err())
						_ = request.Body.Close()
					case <-finished:
					}
				}()
				go func() {
					defer close(finished)
					err := closeAfterRequestEOF(request.Body, output)
					_ = output.CloseWithError(err)
					completed <- err
				}()
				return &http.Response{
					StatusCode: http.StatusOK,
					Proto:      map[string]string{"h2": "HTTP/2.0", "h3": "HTTP/3.0"}[protocol],
					Header:     http.Header{"Sec-Websocket-Protocol": []string{"interop"}},
					Body:       response,
				}, nil
			})
			if err := websocketRequest(options{protocol: protocol, url: "https://fixture.invalid"}, &tls.Config{}, transport); err != nil {
				t.Fatal(err)
			}
			if err := <-completed; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func closeAfterRequestEOF(body io.Reader, output io.Writer) error {
	if err := wsutil.WriteMessage(output, ws.StateServerSide, ws.OpText, []byte("hello from independent origin")); err != nil {
		return err
	}
	reader := &wsutil.Reader{Source: body, State: ws.StateServerSide, CheckUTF8: true, MaxFrameSize: maximumBody}
	for {
		operation, payload, err := message(reader)
		if err != nil {
			return err
		}
		if operation == ws.OpPing {
			operation = ws.OpPong
		}
		if operation == ws.OpClose {
			trailing, err := io.ReadAll(body)
			if err != nil || len(trailing) != 0 {
				return fmt.Errorf("request did not finish cleanly: %v", err)
			}
			return wsutil.WriteMessage(output, ws.StateServerSide, operation, payload)
		}
		if err := wsutil.WriteMessage(output, ws.StateServerSide, operation, payload); err != nil {
			return err
		}
	}
}

// A clean response must not cause the origin to reset a request whose FIN has
// arrived. Require the real handler to consume EOF before its deferred Close.
type observedBody struct {
	source          *bytes.Reader
	eof             bool
	closedBeforeEOF bool
}

func (b *observedBody) Read(p []byte) (int, error) {
	n, err := b.source.Read(p)
	if err == io.EOF {
		b.eof = true
	}
	return n, err
}

func (b *observedBody) Close() error {
	b.closedBeforeEOF = !b.eof
	return nil
}

func TestWebsocketOriginDrainsFinishedConnectRequest(t *testing.T) {
	for _, protocol := range []int{2, 3} {
		t.Run(fmt.Sprint(protocol), func(t *testing.T) {
			var wire bytes.Buffer
			if err := wsutil.WriteMessage(&wire, ws.StateClientSide, ws.OpClose, ws.NewCloseFrameBody(ws.StatusNormalClosure, "complete")); err != nil {
				t.Fatal(err)
			}
			body := &observedBody{source: bytes.NewReader(wire.Bytes())}
			request := httptest.NewRequest(http.MethodConnect, "https://fixture.invalid/ws", body)
			request.ProtoMajor = protocol
			request.Proto = "websocket"
			request.Header.Set(":protocol", "websocket")
			request.Header.Set("Sec-Websocket-Version", "13")
			request.Header.Set("Sec-Websocket-Protocol", "interop")
			websocketOrigin(httptest.NewRecorder(), request)
			if !body.eof || body.closedBeforeEOF {
				t.Fatal("origin closed CONNECT before consuming request EOF")
			}
		})
	}
}
