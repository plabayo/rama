# ICAP

ICAP lets a proxy ask another service to inspect or adapt an HTTP message.
The proxy keeps handling clients and origin connections. The ICAP service can
focus on one concern, such as malware scanning, data-loss prevention, access
policy, or content transformation.

There are two common flows:

- `REQMOD` handles the HTTP request before it reaches the origin server;
- `RESPMOD` handles the HTTP response before it reaches the client.

An ICAP client can first use `OPTIONS` to discover what a service supports.
Preview lets the service inspect the start of a body before deciding whether
it needs the rest. A `204` response means that no adaptation is needed.

Rama provides ICAP clients and servers, plus an HTTP adaptation layer. The
[`http_icap_proxy` example][example] shows the complete flow with HTTP/1.1,
HTTP/2, and HTTPS. It runs with an embedded Rama ICAP service by default, or
can connect to an external service such as c-icap. The example adapts
responses, but the same layer can also adapt requests.

See the [`rama::icap` API documentation][api] for the protocol, streaming, and
HTTP integration APIs. See [RFC 3507][rfc] for the protocol specification.

In production, decide explicitly what the proxy should do when its ICAP
service is slow or unavailable.

[api]: https://ramaproxy.org/docs/rama/icap/index.html
[example]: https://github.com/plabayo/rama/blob/main/examples/src/http_icap_proxy.rs
[rfc]: https://www.rfc-editor.org/rfc/rfc3507
