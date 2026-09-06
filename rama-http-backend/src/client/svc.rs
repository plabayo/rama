use rama_core::error::BoxErrorExt as _;
use rama_core::{
    Service,
    error::{BoxError, ErrorExt},
    extensions::{Egress, Extensions, ExtensionsRef},
    telemetry::tracing,
};
use rama_http::StreamingBody;
use rama_http::io::upgrade::OnUpgrade;
use rama_http::layer::version_adapter::ensure_valid_request_for_version;
use rama_http_types::body::OnIncompleteBody;
use rama_http_types::proto::h1::ext::ConnectionClose;
use rama_http_types::{Method, Request, Response, Version};
use rama_net::conn::ConnectionHealthWatcher;
use rama_utils::guard::DropGuard;
use std::fmt;
use tokio::sync::Mutex;

pub(super) enum SendRequest<Body> {
    Http1(Mutex<rama_http_core::client::conn::http1::SendRequest<Body>>),
    Http2(rama_http_core::client::conn::http2::SendRequest<Body>),
}

impl<Body: fmt::Debug> fmt::Debug for SendRequest<Body> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("SendRequest");
        match self {
            Self::Http1(send_request) => f.field(send_request).finish(),
            Self::Http2(send_request) => f.field(send_request).finish(),
        }
    }
}

/// Internal http sender used to send the actual requests.
pub struct HttpClientService<Body> {
    pub(super) sender: SendRequest<Body>,
    pub(super) extensions: Extensions,
}

impl<Body> Service<Request<Body>> for HttpClientService<Body>
where
    Body: StreamingBody<Data: Send + 'static, Error: Into<BoxError>> + Unpin + Send + 'static,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, mut req: Request<Body>) -> Result<Self::Output, Self::Error> {
        // Request-target encoding must follow the connection that survived
        // route fallback and pool selection, never the requested ProxyRoute.
        // A fresh snapshot also shadows stale markers when the connection
        // has no established route. Request-side route intent stays intact.
        // Keep this independent of EasyHttpWebClient/HttpForwardProxyLayer:
        // standalone backend callers need the same encoding guarantee.
        req.extensions().insert(Egress(self.extensions.clone()));

        // Check if this http connection can actually be used for this request version
        match (&self.sender, req.version()) {
            (SendRequest::Http1(_), Version::HTTP_10 | Version::HTTP_11)
            | (SendRequest::Http2(_), Version::HTTP_2) => (),
            (SendRequest::Http1(_), version) => Err(BoxError::from_static_str(
                "Http1 connector cannot send request with version",
            )
            .context_debug_field("version", version))?,
            (SendRequest::Http2(_), version) => Err(BoxError::from_static_str(
                "Http2 connector cannot send request with version",
            )
            .context_debug_field("version", version))?,
        }

        // CONNECT must carry an authority
        if req.method() == Method::CONNECT && req.uri().host().is_none() {
            return Err(BoxError::from_static_str("missing host in CONNECT request"));
        }

        ensure_valid_request_for_version(&mut req)?;

        let resp = match &self.sender {
            SendRequest::Http1(sender) => {
                let mut sender = sender.lock().await;
                if let Err(err) = sender.ready().await {
                    // an h1 sender only fails readiness when its connection is gone
                    mark_broken(&self.extensions);
                    tracing::debug!(
                        sender_closed = sender.is_closed(),
                        "http1 upstream sender ready failed: {err}"
                    );
                    return Err(err.into());
                }
                // Dropping an in-flight h1 request future closes the shared
                // connection, so mark it broken right here (guard) rather than on
                // the connection task, which a racing pool checkout can beat.
                let extensions = self.extensions.clone();
                let mut cancel_guard = DropGuard::new(move || mark_broken(&extensions));
                let result = sender.send_request(req).await;
                match result {
                    Ok(resp) => {
                        cancel_guard.disarm();
                        resp
                    }
                    Err(err) => {
                        // h1 has no request-level recovery: any send/receive error
                        // leaves the connection mid-message or closed.
                        cancel_guard.fire();
                        tracing::debug!(
                            sender_closed = sender.is_closed(),
                            "http1 upstream send_request failed: {err}"
                        );
                        return Err(err.into());
                    }
                }
            }
            SendRequest::Http2(sender) => {
                let mut sender = sender.clone();
                if let Err(err) = sender.ready().await {
                    mark_broken_if_closed(sender.is_closed(), &self.extensions);
                    tracing::debug!(
                        sender_closed = sender.is_closed(),
                        "http2 upstream sender ready failed: {err}"
                    );
                    return Err(err.into());
                }
                match sender.send_request(req).await {
                    Ok(resp) => resp,
                    Err(err) => {
                        mark_broken_if_closed(sender.is_closed(), &self.extensions);
                        tracing::debug!(
                            sender_closed = sender.is_closed(),
                            "http2 upstream send_request failed: {err}"
                        );
                        return Err(err.into());
                    }
                }
            }
        };

        match &self.sender {
            SendRequest::Http1(_) => {
                // Evict upgraded h1 connections before the response can release its pool lease.
                if resp.extensions().contains::<OnUpgrade>()
                    || resp.extensions().contains::<ConnectionClose>()
                {
                    mark_broken(&self.extensions);
                }
                // An h1 connection is only reusable once its response body is read
                // to end-of-stream: evict it the moment the body is abandoned or
                // errors, before the pool can hand it to the next request.
                let extensions = self.extensions.clone();
                Ok(resp.map(|body| {
                    rama_http_types::Body::new(OnIncompleteBody::new(body, move || {
                        mark_broken(&extensions)
                    }))
                }))
            }
            // h2 recovers per stream: an abandoned body resets only its stream.
            SendRequest::Http2(_) => Ok(resp.map(rama_http_types::Body::new)),
        }
    }
}

fn mark_broken_if_closed(is_closed: bool, extensions: &Extensions) {
    if is_closed {
        mark_broken(extensions);
    }
}

fn mark_broken(extensions: &Extensions) {
    extensions
        .get_ref_or_insert(ConnectionHealthWatcher::default)
        .mark_broken();
}

impl<B> ExtensionsRef for HttpClientService<B> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http_types::Body;
    use rama_http_types::body::util::BodyExt as _;
    use rama_net::conn::ConnectionHealth;

    fn is_broken(extensions: &Extensions) -> bool {
        extensions
            .get_ref::<ConnectionHealthWatcher>()
            .is_some_and(|watcher| watcher.health() == ConnectionHealth::Broken)
    }

    fn mark_broken_on_incomplete(body: Body, extensions: &Extensions) -> Body {
        let extensions = extensions.clone();
        Body::new(OnIncompleteBody::new(body, move || {
            mark_broken(&extensions)
        }))
    }

    #[tokio::test]
    async fn http1_sender_replaces_stale_connection_snapshots_before_encoding() {
        use rama_core::ServiceInput;
        use rama_net::{
            address::ProxyAddress,
            client::{EstablishedProxyRoute, ProxyRoute},
        };
        use std::time::Duration;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let proxy: ProxyAddress = "http://proxy.example:8080".parse().unwrap();
        for route in [
            None,
            Some(EstablishedProxyRoute::Direct),
            Some(EstablishedProxyRoute::Tunnel(proxy.clone())),
            Some(EstablishedProxyRoute::Tunnel(
                "socks5://proxy.example:1080".parse().unwrap(),
            )),
            Some(EstablishedProxyRoute::Forward(proxy.clone())),
        ] {
            let is_forward = route
                .as_ref()
                .is_some_and(EstablishedProxyRoute::is_http_forward);
            let (io, mut peer) = tokio::io::duplex(4096);
            let (sender, connection) =
                rama_http_core::client::conn::http1::handshake(ServiceInput::new(io))
                    .await
                    .unwrap();
            tokio::spawn(async move {
                drop(connection.await);
            });
            let extensions = Extensions::new();
            if let Some(route) = route.clone() {
                extensions.insert(route);
            }
            let service = HttpClientService {
                sender: SendRequest::Http1(Mutex::new(sender)),
                extensions,
            };
            let request = Request::builder()
                .uri("http://origin.example/resource")
                .body(Body::empty())
                .unwrap();
            request
                .extensions()
                .insert(ProxyRoute::Proxy(proxy.clone()));
            let stale_route = if is_forward {
                EstablishedProxyRoute::Direct
            } else {
                EstablishedProxyRoute::Forward(proxy.clone())
            };
            request.extensions().insert(stale_route.clone());
            let stale_egress = Extensions::new();
            stale_egress.insert(stale_route);
            request.extensions().insert(Egress(stale_egress));

            let (response, head) = tokio::time::timeout(Duration::from_secs(2), async {
                tokio::join!(service.serve(request), async {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        peer.read_exact(&mut byte).await.unwrap();
                        head.push(byte[0]);
                    }
                    peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .unwrap();
                    head
                })
            })
            .await
            .expect("HTTP exchange timed out");
            response.unwrap();
            let expected = if is_forward {
                b"GET http://origin.example/resource HTTP/1.1\r\n".as_slice()
            } else {
                b"GET /resource HTTP/1.1\r\n".as_slice()
            };
            assert!(
                head.starts_with(expected),
                "route: {route:?}, head: {head:?}"
            );
        }
    }

    #[test]
    fn incomplete_body_marks_broken_on_early_drop() {
        let extensions = Extensions::new();
        drop(mark_broken_on_incomplete(Body::from("hello"), &extensions));
        assert!(is_broken(&extensions));
    }

    #[tokio::test]
    async fn consumed_body_does_not_mark_broken() {
        let extensions = Extensions::new();
        mark_broken_on_incomplete(Body::from("hello"), &extensions)
            .collect()
            .await
            .unwrap();
        assert!(!is_broken(&extensions));
    }

    #[test]
    fn empty_body_does_not_mark_broken_when_never_polled() {
        let extensions = Extensions::new();
        drop(mark_broken_on_incomplete(Body::empty(), &extensions));
        assert!(!is_broken(&extensions));
    }

    // Regression: a forwarded request received over a terminated TLS connection
    // (e.g. a MITM proxy upstream hop) arrives in origin-form with no scheme in
    // the URI. Its protocol MUST resolve to HTTPS via the `SecureTransport`
    // extension so the auto TLS connector secures the upstream hop. This
    // silently regressed to HTTP whenever `rama-http-types/tls` was not enabled
    // alongside `rama-tls`: `input_ext` then matched against a dummy
    // `SecureTransport` type instead of the real one inserted by the TLS
    // acceptor, so the connector went plaintext to a TLS upstream and the
    // upstream's TLS alert surfaced as `Parse(Version)` (http_mitm_proxy_boring).
    #[cfg(feature = "tls")]
    #[test]
    fn origin_form_request_over_terminated_tls_resolves_https() {
        use super::*;
        use rama_http::header::HOST;
        use rama_net::{Protocol, ProtocolInputExt};
        use rama_tls::SecureTransport;

        let req = Request::builder()
            .uri("/ping")
            .header(HOST, "example.com:8443")
            .body(())
            .unwrap();
        req.extensions().insert(SecureTransport::default());

        assert_eq!(req.protocol(), Some(&Protocol::HTTPS));
    }
}
