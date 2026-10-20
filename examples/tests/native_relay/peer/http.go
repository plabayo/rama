// HTTP contracts shared by the independent client and origin. Wire verification
// remains a separate Python/tshark oracle on both sides of the Rama relay.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
)

const representation = "independent response"

type httpCase struct {
	path, method                      string
	requestBody, responseBody         string
	status                            int
	requestTrailers, responseTrailers bool
	fixedResponse                     bool
	head                              bool
}

func httpCases(payload string) []httpCase {
	return []httpCase{
		{path: "/GET", method: http.MethodGet, status: http.StatusOK, responseTrailers: true},
		{path: "/POST", method: http.MethodPost, requestBody: payload, responseBody: payload, status: http.StatusOK, requestTrailers: true, responseTrailers: true},
		{path: "/fixed", method: http.MethodPost, requestBody: payload, responseBody: payload, status: http.StatusOK, fixedResponse: true},
		{path: "/empty", method: http.MethodPost, status: http.StatusOK, fixedResponse: true},
		{path: "/empty-stream", method: http.MethodPost, status: http.StatusOK, requestTrailers: true, responseTrailers: true},
		{path: "/head", method: http.MethodHead, status: http.StatusOK, fixedResponse: true, head: true},
		{path: "/no-content", method: http.MethodGet, status: http.StatusNoContent},
		{path: "/not-modified", method: http.MethodGet, status: http.StatusNotModified},
		{path: "/stream", method: http.MethodGet, responseBody: representation, status: http.StatusOK, responseTrailers: true},
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
	for _, scenario := range httpCases(string(body)) {
		if scenario.path != r.URL.Path || scenario.method != r.Method {
			continue
		}
		if scenario.requestTrailers && r.Trailer.Get("X-Interop-Request-End") != "complete" {
			http.Error(w, "missing request trailer", http.StatusBadRequest)
			return
		}
		w.Header().Set("X-Interop-Peer", "Go")
		w.Header()["x-eXoTiC-ReSpOnSe"] = []string{"first", "second"}
		if scenario.status == http.StatusNoContent || scenario.status == http.StatusNotModified {
			w.WriteHeader(scenario.status)
			// Commit bodyless headers now: quic-go otherwise infers a zero
			// Content-Length at handler return, which is forbidden on 204.
			_ = http.NewResponseController(w).Flush()
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		if scenario.fixedResponse {
			length := len(scenario.responseBody)
			if scenario.head {
				length = len(representation)
			}
			w.Header().Set("Content-Length", strconv.Itoa(length))
		}
		if scenario.responseTrailers {
			w.Header().Set("Trailer", "X-Interop-End")
		}
		w.WriteHeader(scenario.status)
		if !scenario.head {
			// Two flushed writes exercise streaming rather than a buffered body
			// that net/http could automatically turn into Content-Length.
			middle := len(scenario.responseBody) / 2
			if _, err := io.WriteString(w, scenario.responseBody[:middle]); err != nil {
				return
			}
			if scenario.responseTrailers {
				if err := http.NewResponseController(w).Flush(); err != nil {
					return
				}
			}
			if _, err := io.WriteString(w, scenario.responseBody[middle:]); err != nil {
				return
			}
		}
		if scenario.responseTrailers {
			w.Header().Set("X-Interop-End", "complete")
		}
		return
	}
	http.NotFound(w, r)
}

func httpRequests(client *http.Client, args options) error {
	for _, scenario := range httpCases(args.body) {
		// A nil reader is an explicitly empty body on all three transports.
		// A non-nil streaming reader remains unknown-length even when empty.
		var body io.Reader
		if scenario.requestTrailers {
			body = io.NopCloser(bytes.NewBufferString(scenario.requestBody))
		} else if scenario.requestBody != "" {
			body = bytes.NewBufferString(scenario.requestBody)
		}
		req, err := http.NewRequest(scenario.method, args.url+scenario.path, body)
		if err != nil {
			return err
		}
		req.Host = "localhost"
		req.Header.Set("TE", "trailers")
		if args.protocol == "h1" {
			req.Header.Set("Connection", "TE")
		}
		req.Header.Set("X-Interop-First", "one")
		req.Header.Add("X-Interop-Repeat", "a")
		req.Header.Add("X-Interop-Repeat", "b")
		req.Header["x-eXoTiC-ReQuEsT"] = []string{"first", "second"}
		if scenario.requestTrailers {
			req.ContentLength = -1
			req.Trailer = http.Header{"X-Interop-Request-End": []string{"complete"}}
		}
		response, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("%s: %w", scenario.path, err)
		}
		result, err := io.ReadAll(io.LimitReader(response.Body, maximumBody+1))
		_ = response.Body.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", scenario.path, err)
		}
		wanted := map[string]string{"h1": "HTTP/1.1", "h2": "HTTP/2.0", "h3": "HTTP/3.0"}[args.protocol]
		if response.Proto != wanted || response.StatusCode != scenario.status || string(result) != scenario.responseBody {
			return fmt.Errorf("%s exchange failed: protocol=%s status=%d body=%q", scenario.path, response.Proto, response.StatusCode, result)
		}
		trailer := response.Trailer.Get("X-Interop-End")
		if (scenario.responseTrailers && trailer != "complete") || (!scenario.responseTrailers && len(response.Trailer) != 0) {
			return fmt.Errorf("%s response trailers differ", scenario.path)
		}
		if (scenario.status == http.StatusNoContent || scenario.status == http.StatusNotModified) && len(response.Header.Values("Content-Length")) != 0 {
			return fmt.Errorf("%s bodyless response unexpectedly carries Content-Length", scenario.path)
		}
		if scenario.fixedResponse {
			length := len(scenario.responseBody)
			if scenario.head {
				length = len(representation)
			}
			if response.ContentLength != int64(length) {
				return fmt.Errorf("%s response Content-Length differs: %d", scenario.path, response.ContentLength)
			}
		}
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"method": scenario.method, "path": scenario.path, "protocol": response.Proto, "status": response.StatusCode, "body": string(result), "trailers": response.Trailer}); err != nil {
			return err
		}
	}
	return nil
}
