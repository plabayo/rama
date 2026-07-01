use rama_core::error::BoxErrorExt as _;
use rama_core::{
    Service,
    error::{BoxError, ErrorExt},
    extensions::{Extensions, ExtensionsRef},
    telemetry::tracing,
};
use rama_http::StreamingBody;
use rama_http::layer::version_adapter::ensure_valid_request_for_version;
use rama_http_types::{Method, Request, Response, Version};
use rama_net::conn::ConnectionHealthWatcher;
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
                    mark_broken_if_closed(sender.is_closed(), &self.extensions);
                    tracing::debug!(
                        sender_closed = sender.is_closed(),
                        "http1 upstream sender ready failed: {err}"
                    );
                    return Err(err.into());
                }
                match sender.send_request(req).await {
                    Ok(resp) => resp,
                    Err(err) => {
                        mark_broken_if_closed(sender.is_closed(), &self.extensions);
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

        Ok(resp.map(rama_http_types::Body::new))
    }
}

fn mark_broken_if_closed(is_closed: bool, extensions: &Extensions) {
    if is_closed {
        extensions
            .get_ref_or_insert(ConnectionHealthWatcher::default)
            .mark_broken();
    }
}

impl<B> ExtensionsRef for HttpClientService<B> {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

#[cfg(test)]
mod tests {
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
