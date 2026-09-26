
Use an ordinary client identity for the simple case:

```rust
use rama_tls::client::ClientAuth;
use rama_tls_boring::proxy::client_auth::TlsMitmClientAuthPolicy;
# fn fixed(auth: ClientAuth) -> Result<(), rama_core::error::BoxError> {
let policy = TlsMitmClientAuthPolicy::try_from(auth)?;
// Attach with relay.with_client_auth(policy), or insert into flow extensions.
# Ok(())
# }
```

For mapping, see the runnable
[`tls_mitm_relay_client_auth` example](https://github.com/plabayo/rama/blob/main/examples/src/tls_mitm_relay_client_auth.rs).
It uses separate policy and resolver service structs, verifies ingress against
its own trust store, and maps an exact leaf to a prebuilt upstream credential.
Its process-level tests cover real TCP/TLS exchanges, missing/untrusted/unmapped
clients, and independent ingress admission without an upstream request, with
both TLS 1.2 and TLS 1.3. Replace the match with your own storage service or layers;
matching alone cannot reproduce an identity without its private key or signer.

The policy runs once per connection, including with `request: None` when upstream
does not request a certificate. That permits independent ingress admission.
The plan requests no ingress certificate unless configured; `with_ingress_trust`
requires one, while `with_ingress` permits optional verification, CA-name hints,
custom asynchronous verifiers and other native per-connection settings. These
configuration calls compose in order. The resolver receives identity only after
BoringSSL completes ingress certificate verification **and** the handshake
signature/Finished checks. An empty chain means no ingress identity was provided.

A resolver error rejects the connection. With any policy, ingress trust failures,
including a client rejecting the relay certificate, are classified as `ClientAuth`.
Callers must not cache them as interception bypass hints, so pinned clients are
no longer bypassed automatically. `Some(credential)` supplies egress auth;
`None` explicitly omits it (optional upstream auth, stripping, or no upstream
request). Upstream does not indicate whether its request is optional; it may
reject an empty response. Returning a credential when upstream requested none is
an error. Both choices replace inherited credentials. TLS 1.3 upstream rejection
may arrive after local handshake completion, on the returned stream.

The callback preserves configured upstream verification and pins. The relay's
existing default remains verification disabled; configure `TlsMitmEgressServerAuth`
with `ServerVerifyMode::Auto` and suitable roots/pins when upstream authenticity
is required. A fixed identity is available to every upstream requesting it; scope
a custom policy by `input.server_name` if only selected destinations should receive
it. CertificateRequest names are selection hints, not trust anchors.
Prefer TLS 1.3 or TLS 1.2 with ephemeral key exchange when authenticating upstream
before releasing credentials.

Plans that configure ingress disable ingress session tickets/caching. Plans with
no ingress configuration (such as fixed egress identities) allow anonymous ingress
sessions to resume; both policy stages still run. Explicitly preselected egress
sessions are rejected, including without a policy, to prevent authentication from
being skipped. Acceptor caching still works; authentication settings remain local
to each SSL connection. The default 30-second relay handshake deadline includes
both policy stages, certificate issuance and any browser certificate-picker wait.
The upstream handshake timeout also applies while egress is paused. A stalled
policy can delay noticing a disconnected peer until it resolves or the deadline
expires. Use `with_handshake_timeout` to tune this or
`without_handshake_timeout` when the caller owns cancellation. Dropping the handshake drops its policy futures and
owned streams; work independently spawned by a policy must manage its own lifetime.
