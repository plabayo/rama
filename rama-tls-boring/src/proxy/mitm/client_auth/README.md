
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

For mapping, compose a policy service and a resolver service. This example
requires a trusted ingress certificate and maps one exact leaf to a prebuilt
egress identity. Replace the match with your own storage service or layers;
matching alone cannot reproduce an identity without its private key or signer.

```rust
use rama_boring::{ssl::SslCredential, x509::store::X509Store};
use rama_core::{error::BoxError, service::service_fn};
use rama_tls_boring::proxy::client_auth::{
    TlsMitmClientAuthInput, TlsMitmClientAuthPlan, TlsMitmClientAuthPolicy,
    TlsMitmClientIdentity,
};
use std::sync::Arc;

fn mapping(trust: X509Store, expected_leaf: Arc<[u8]>, egress: SslCredential)
    -> TlsMitmClientAuthPolicy
{
    TlsMitmClientAuthPolicy::new(service_fn(move |input: TlsMitmClientAuthInput| {
        let (trust, expected, egress) = (trust.clone(), expected_leaf.clone(), egress.clone());
        async move {
            let requested = input.request.is_some();
            Ok::<_, BoxError>(TlsMitmClientAuthPlan::new(service_fn(
                move |identity: TlsMitmClientIdentity| {
                    let (expected, egress) = (expected.clone(), egress.clone());
                    async move {
                        let leaf = identity.leaf().ok_or("missing client certificate")?;
                        if leaf.to_der()?.as_slice() != expected.as_ref() {
                            return Err(BoxError::from("unmapped client certificate"));
                        }
                        Ok(requested.then_some(egress))
                    }
                },
            )).with_ingress_trust(trust))
        }
    }))
}
```

The policy runs once per connection, including with `request: None` when upstream
does not request a certificate. That permits independent ingress admission.
The plan requests no ingress certificate unless configured; `with_ingress_trust`
requires one, while `with_ingress` permits optional verification, CA-name hints,
custom asynchronous verifiers and other native per-connection settings. These
configuration calls compose in order. The resolver receives identity only after
BoringSSL completes ingress certificate verification **and** the handshake
signature/Finished checks. An empty chain means no ingress identity was provided.

A resolver error rejects the connection. Ingress trust failures with a policy
are classified as `ClientAuth`, so callers must not cache them as interception
bypass hints. `Some(credential)` supplies egress auth;
`None` explicitly omits it (optional upstream auth, stripping, or no upstream
request). Upstream does not indicate whether its request is optional; it may
reject an empty response. Returning a credential when upstream requested none is
an error. Both choices replace inherited credentials. TLS 1.3 upstream rejection
may arrive after local handshake completion, on the returned stream.

The callback preserves configured upstream verification and pins. The relay's
existing default remains verification disabled; configure `TlsMitmEgressServerAuth`
with `ServerVerifyMode::Auto` and suitable roots/pins when upstream authenticity
is required. CertificateRequest names are selection hints, not trust anchors.
Prefer TLS 1.3 or TLS 1.2 with ephemeral key exchange when authenticating upstream
before releasing credentials.

Policies disable ingress session tickets/caching. Explicitly preselected egress
sessions are rejected, including without a policy, to prevent authentication from
being skipped. Acceptor caching still works; authentication settings remain local
to each SSL connection. The default 30-second relay handshake deadline includes
both policy stages and certificate issuance. A stalled policy can delay noticing
a disconnected peer until it resolves or the deadline expires. Use
`with_handshake_timeout` to tune this or `without_handshake_timeout` when the
caller owns cancellation. Dropping the handshake drops its policy futures and
owned streams; work independently spawned by a policy must manage its own lifetime.
