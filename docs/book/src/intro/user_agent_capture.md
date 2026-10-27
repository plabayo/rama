# 🎯 Capturing your own profiles

Rama's embedded profiles cover common browsers. To emulate a browser version, device or
app of your own choice, capture its traffic and export a profile archive that
`rama send --emulate=FILE` and `UserAgentDatabase` load. There are two ways.

## With your own fingerprinting service

`rama serve fp` is the service behind <https://fp.ramaproxy.org>. Every visit stores what
the client sent: TLS over TCP, HTTP/1.1, HTTP/2, and in secure mode TLS over QUIC, QUIC
transport parameters and first flight, HTTP/3 SETTINGS and header order.

1. Give it a PostgreSQL database and a TLS certificate the client trusts (base64 PEM;
   without these two variables a self-signed certificate is generated):

   ```sh
   export DATABASE_URL='postgres://user:pass@localhost/fp'
   export RAMA_TLS_CRT="$(base64 < cert.pem)" RAMA_TLS_KEY="$(base64 < key.pem)"
   rama serve fp --bind 0.0.0.0:443 --secure
   ```

   `--http-version auto` (the default) serves HTTP/1.1 and HTTP/2 over TCP and HTTP/3 over
   QUIC on the same port. Browsers only switch to HTTP/3 after they learned it from an
   `Alt-Svc` header or an `HTTPS` DNS record with `alpn="h3"`, so reload the page once.
   An HTTP/3-only origin, as `h3.fp.ramaproxy.org`, is
   `--http-version h3 --h3-bootstrap-bind 0.0.0.0:8443`: a plain TCP page sends the browser
   on to HTTP/3. The deployments in
   [`rama-fp/infra`](https://github.com/plabayo/rama/tree/main/rama-fp/infra) are complete
   examples.
2. Open `https://your-host/` in the browser or app to profile and choose
   *Get Fingerprint Report*. The report page also runs fetch, XHR, WebSocket and form
   requests, so every kind of request is captured. Mobile devices only need to reach the
   host; [BrowserStack](https://browserstack.com) works as well, see
   [`rama-fp/browserstack`](https://github.com/plabayo/rama/tree/main/rama-fp/browserstack)
   for the automated journey we run every night.
3. Export what was stored and check it:

   ```sh
   export RAMA_FP_DATABASE_URL="$DATABASE_URL"
   rama ua export --output profiles.json   # --days N, 14 by default
   rama ua view profiles.json
   ```

4. Use it:

   ```sh
   rama send --emulate=profiles.json --http3 -H 'User-Agent: <the captured User-Agent>' https://example.com/
   ```

   [Verifying a fingerprint with Wireshark](./user_agent.md#verifying-a-fingerprint-with-wireshark)
   shows how to compare the result with the original.

## With the MITM proxy

`rama serve proxy --mitm` captures any client that can be pointed at an HTTP proxy, such
as a desktop or mobile app talking to its own API:

1. Start it in discovery mode, which records hosts without decrypting anything:

   ```sh
   rama serve proxy --bind 0.0.0.0:8080 --mitm --mitm-scope none --mitm-ca-cert rama-ca.pem
   ```

   It prints the inspector's address; `--inspect-json` prints it as JSON.
2. Trust `rama-ca.pem` on the device (it is also downloadable from the inspector), so the
   hosts you select later can be decrypted.
3. Point the device at the proxy: the system HTTP proxy setting on macOS, Windows, iOS or
   Android (Wi-Fi settings), or `HTTPS_PROXY=http://host:8080` for a single program.
4. Use the app. The inspector's **Hosts** pane lists every host it contacts. Add the ones
   you want to the **Selected** scope (or restart with `--mitm-allow api.example.com`),
   then use the app again: new connections to those hosts are decrypted and captured.
5. Export the captured requests as a profile archive from the inspector, or with
   `GET /api/profiles.json` (see the inspector's `/api/help`), and use it as above.

### Limits

- A client sends only TCP to an HTTP proxy: browsers and apps never use QUIC through one.
  This captures TLS over TCP, HTTP/1.1 and HTTP/2, not HTTP/3. For HTTP/3 profiles use your
  own fingerprinting service, or a transparent proxy that sees UDP, such as the
  [macOS transparent proxy example](https://github.com/plabayo/rama/tree/main/ffi/apple/examples/transparent_proxy).
- Apps that pin their certificates, or ignore user-installed CAs (Android apps by default
  since Android 7; Firefox uses its own store), cannot be decrypted without modifying the
  device. Their TLS ClientHello and QUIC Initial are still readable in a packet capture,
  since neither is protected by the session keys.
