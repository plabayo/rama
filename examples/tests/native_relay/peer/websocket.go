// WebSocket probes use library framing on all three HTTP transports.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

// Flushing each frame keeps multiplexed CONNECT streams interactive.
type flushedWriter struct{ response http.ResponseWriter }

func (w flushedWriter) Write(p []byte) (int, error) {
	n, err := w.response.Write(p)
	if err != nil {
		return n, err
	}
	return n, http.NewResponseController(w.response).Flush()
}

func message(reader *wsutil.Reader) (ws.OpCode, []byte, error) {
	header, err := reader.NextFrame()
	if err != nil {
		return 0, nil, err
	}
	body, err := io.ReadAll(io.LimitReader(reader, maximumBody+1))
	if err != nil {
		return 0, nil, err
	}
	if len(body) > maximumBody {
		return 0, nil, fmt.Errorf("WebSocket message exceeds limit")
	}
	return header.OpCode, body, nil
}

func websocketOrigin(response http.ResponseWriter, request *http.Request) {
	var source io.Reader
	var destination io.Writer
	if request.ProtoMajor == 1 {
		upgrade := ws.HTTPUpgrader{Timeout: 5 * time.Second, Protocol: func(value string) bool { return value == "interop" }}
		connection, buffered, handshake, err := upgrade.Upgrade(request, response)
		if err != nil {
			return
		}
		defer connection.Close()
		if handshake.Protocol != "interop" {
			return
		}
		_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
		source, destination = buffered, connection
	} else {
		protocol := request.Header.Get(":protocol")
		if request.ProtoMajor == 3 {
			protocol = request.Proto
		}
		if request.Method != http.MethodConnect || protocol != "websocket" || request.Header.Get("Sec-Websocket-Version") != "13" || request.Header.Get("Sec-Websocket-Protocol") != "interop" {
			http.Error(response, "invalid WebSocket CONNECT", http.StatusBadRequest)
			return
		}
		defer request.Body.Close()
		response.Header().Set("Sec-Websocket-Protocol", "interop")
		response.WriteHeader(http.StatusOK)
		if err := http.NewResponseController(response).Flush(); err != nil {
			return
		}
		source, destination = request.Body, flushedWriter{response}
	}
	if err := echoWebsocket(source, destination); err != nil {
		// The client validates the complete exchange and reports a failed probe.
		return
	}
	if request.ProtoMajor > 1 {
		// Observe the request FIN before closing its body. Closing an unread
		// CONNECT body can reset the stream while its close reply is in flight.
		_, _ = io.Copy(io.Discard, io.LimitReader(request.Body, maximumBody+1))
	}
}

func echoWebsocket(source io.Reader, destination io.Writer) error {
	reader := &wsutil.Reader{Source: source, State: ws.StateServerSide, CheckUTF8: true, MaxFrameSize: maximumBody}
	reader.OnIntermediate = func(header ws.Header, payload io.Reader) error {
		data, err := io.ReadAll(io.LimitReader(payload, 126))
		if err != nil {
			return err
		}
		if header.OpCode != ws.OpPing {
			return fmt.Errorf("unexpected intermediate control")
		}
		return wsutil.WriteMessage(destination, ws.StateServerSide, ws.OpPong, data)
	}
	if err := wsutil.WriteMessage(destination, ws.StateServerSide, ws.OpText, []byte("hello from independent origin")); err != nil {
		return err
	}
	for {
		operation, body, err := message(reader)
		if err != nil {
			return err
		}
		switch operation {
		case ws.OpText, ws.OpBinary:
			err = wsutil.WriteMessage(destination, ws.StateServerSide, operation, body)
		case ws.OpPing:
			err = wsutil.WriteMessage(destination, ws.StateServerSide, ws.OpPong, body)
		case ws.OpClose:
			if !bytes.Equal(body, ws.NewCloseFrameBody(ws.StatusNormalClosure, "complete")) {
				return fmt.Errorf("unexpected close payload")
			}
			return wsutil.WriteMessage(destination, ws.StateServerSide, ws.OpClose, body)
		default:
			return fmt.Errorf("unexpected WebSocket operation %d", operation)
		}
		if err != nil {
			return err
		}
	}
}

func websocketRequest(args options, config *tls.Config, transport http.RoundTripper) error {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var source io.Reader
	var destination io.Writer
	var finishRequest func() error
	if args.protocol == "h1" {
		dialer := ws.Dialer{TLSConfig: config, Protocols: []string{"interop"}, Timeout: 5 * time.Second}
		connection, buffered, handshake, err := dialer.Dial(ctx, strings.Replace(args.url, "https://", "wss://", 1)+"/ws")
		if err != nil {
			return err
		}
		defer connection.Close()
		if handshake.Protocol != "interop" {
			return fmt.Errorf("missing WebSocket subprotocol")
		}
		_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
		source, destination = connection, connection
		if buffered != nil {
			source = buffered
		}
	} else {
		body, writer := io.Pipe()
		defer body.Close()
		defer writer.Close()
		request, err := http.NewRequestWithContext(ctx, http.MethodConnect, args.url+"/ws", body)
		if err != nil {
			return err
		}
		request.Host = "localhost"
		request.Header.Set("Sec-Websocket-Version", "13")
		request.Header.Set("Sec-Websocket-Protocol", "interop")
		if args.protocol == "h2" {
			request.Header.Set(":protocol", "websocket")
		} else {
			request.Proto = "websocket"
		}
		response, err := transport.RoundTrip(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		expected := map[string]string{"h2": "HTTP/2.0", "h3": "HTTP/3.0"}[args.protocol]
		if response.StatusCode != 200 || response.Proto != expected || response.Header.Get("Sec-Websocket-Protocol") != "interop" {
			return fmt.Errorf("invalid WebSocket CONNECT response: %s %d", response.Proto, response.StatusCode)
		}
		source, destination = response.Body, writer
		finishRequest = writer.Close
	}
	reader := &wsutil.Reader{Source: source, State: ws.StateClientSide, CheckUTF8: true, MaxFrameSize: maximumBody}
	expect := func(operation ws.OpCode, body []byte) error {
		received, data, err := message(reader)
		if err != nil {
			return err
		}
		if received != operation || !bytes.Equal(data, body) {
			return fmt.Errorf("WebSocket reply differs: operation=%d length=%d", received, len(data))
		}
		return nil
	}
	if err := expect(ws.OpText, []byte("hello from independent origin")); err != nil {
		return err
	}
	probes := []struct {
		operation ws.OpCode
		body      []byte
	}{
		{ws.OpText, []byte("native relay UTF-8: café 🐢")},
		{ws.OpBinary, []byte{0, 1, 127, 128, 254, 255}},
		{ws.OpPing, []byte("relay ping")},
	}
	for _, probe := range probes {
		if err := wsutil.WriteMessage(destination, ws.StateClientSide, probe.operation, probe.body); err != nil {
			return err
		}
		expected := probe.operation
		if expected == ws.OpPing {
			expected = ws.OpPong
		}
		if err := expect(expected, probe.body); err != nil {
			return err
		}
	}
	// A small writer buffer forces continuation frames without hand-coded frames.
	fragmented := []byte("fragmented UTF-8 relay message: café 🐢")
	writer := wsutil.NewWriterSize(destination, ws.StateClientSide, ws.OpText, 8)
	if _, err := writer.Write(fragmented); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if err := expect(ws.OpText, fragmented); err != nil {
		return err
	}
	closeBody := ws.NewCloseFrameBody(ws.StatusNormalClosure, "complete")
	if err := wsutil.WriteMessage(destination, ws.StateClientSide, ws.OpClose, closeBody); err != nil {
		return err
	}
	// Finish the CONNECT request before waiting for its close reply. Otherwise
	// the origin closing an unfinished request can race the response with a reset.
	if finishRequest != nil {
		if err := finishRequest(); err != nil {
			return err
		}
	}
	if err := expect(ws.OpClose, closeBody); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"flow": "websocket", "protocol": args.protocol, "text": true, "binary": true, "fragmented": true, "ping_pong": true, "close": 1000})
}
