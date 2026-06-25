use rama_core::error::BoxErrorExt as _;
use rama_core::{
    Service,
    error::{BoxError, ErrorContext, ErrorExt},
    extensions::{Extensions, ExtensionsRef},
    telemetry::tracing,
};
use rama_http::{StreamingBody, header::SEC_WEBSOCKET_KEY};
use rama_http_headers::{HeaderMapExt, Host};
use rama_http_types::{
    Method, Request, Response, Version,
    header::{CONNECTION, HOST, KEEP_ALIVE, PROXY_CONNECTION, TRANSFER_ENCODING, UPGRADE},
};
use rama_net::{
    AuthorityInputExt, Protocol, ProtocolInputExt, address::ProxyAddress,
    conn::ConnectionHealthWatcher,
};
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

    async fn serve(&self, req: Request<Body>) -> Result<Self::Output, Self::Error> {
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

        // sanitize subject line request uri
        // because Hyper (http) writes the URI as-is
        //
        // Originally reported in and fixed for:
        // <https://github.com/plabayo/rama/issues/250>
        //
        // TODO: fix this in hyper fork (embedded in rama http core)
        // directly instead of here...
        let req = sanitize_client_req_header(req)?;

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

fn sanitize_client_req_header<B>(req: Request<B>) -> Result<Request<B>, BoxError> {
    // logic specific to this method
    if req.method() == Method::CONNECT && req.uri().host().is_none() {
        return Err(BoxError::from_static_str("missing host in CONNECT request"));
    }

    let uses_http_proxy = req
        .extensions()
        .get_ref::<ProxyAddress>()
        .and_then(|proxy| proxy.protocol.as_ref())
        .map(|protocol| protocol.is_http())
        .unwrap_or_default();

    let authority = req.authority().context("fetch request authority")?;
    let protocol = req.protocol().cloned();

    let is_insecure_request_over_http_proxy =
        !protocol.as_ref().map(|p| p.is_secure()).unwrap_or_default() && uses_http_proxy;

    // logic specific to http versions
    Ok(match req.version() {
        Version::HTTP_09 | Version::HTTP_10 | Version::HTTP_11 => {
            // remove authority and scheme for non-connect requests
            // cfr: <https://github.com/plabayo/rama/blob/main/rama-http-core/specifications/rfc9110.txt#section-7.1>
            // Unless we are sending an insecure request over a http(s) proxy
            if req.method() != Method::CONNECT
                && !is_insecure_request_over_http_proxy
                && req.uri().host().is_some()
            {
                tracing::trace!(
                    "remove authority and scheme from non-connect direct http(~1) request"
                );
                let (mut parts, body) = req.into_parts();
                // strip scheme + authority down to origin-form (`/path?query`),
                // preserving path + query + fragment exactly as received.
                parts.uri.unset_scheme();
                parts.uri.unset_authority();

                // We just selected origin-form for a direct h1 hop. The h1
                // core writer still serializes the stored URI as-is, so an
                // empty effective root has to be made explicit here.
                parts.uri.ensure_path_or_root();

                // add required host header if not defined
                if !parts.headers.contains_key(HOST) {
                    let authority = authority.without_default_port_for(protocol.as_ref());
                    tracing::trace!("add missing authority {authority} as host header");
                    parts.headers.typed_insert(Host::from(authority));
                }

                Request::from_parts(parts, body)
            } else if !req.headers().contains_key(HOST) {
                let mut req = req;
                let authority = authority.without_default_port_for(protocol.as_ref());
                tracing::trace!(
                    url.full = %req.request_uri(),
                    server.address = %authority,
                    "add host from authority as HOST header to req (was missing it)",
                );
                req.headers_mut().typed_insert(Host::from(authority));
                req
            } else {
                req
            }
        }
        Version::HTTP_2 => {
            // set scheme/host if not defined as otherwise pseudo
            // headers won't be possible to be set in the h2 crate
            let mut req = if req.uri().host().is_none() {
                let authority = req
                    .authority()
                    .context("[h2+] add scheme/host: missing authority")?;
                let protocol = req.protocol().cloned();

                tracing::trace!(
                    network.protocol.name = "http",
                    network.protocol.version = ?req.version(),
                    "defining authority and scheme to non-connect direct http request"
                );

                // Default port is stripped in browsers. It's important that we also do this
                // as some reverse proxies such as nginx respond 404 if authority is not an exact match
                let authority = authority.without_default_port_for(protocol.as_ref());
                let (mut parts, body) = req.into_parts();
                parts.uri.set_scheme(protocol.unwrap_or(Protocol::HTTP));
                parts.uri.set_host(authority.host);
                parts.uri.set_port(authority.port);

                Request::from_parts(parts, body)
            } else {
                req
            };

            // remove illegal headers
            for illegal_h2_header in [
                &CONNECTION,
                &TRANSFER_ENCODING,
                &PROXY_CONNECTION,
                &UPGRADE,
                &SEC_WEBSOCKET_KEY,
                &KEEP_ALIVE,
                &HOST,
            ] {
                if let Some(header) = req.headers_mut().remove(illegal_h2_header) {
                    tracing::trace!(
                        http.header.name = ?header,
                        "removed illegal (~http1) header from h2 request",
                    );
                }
            }

            req
        }
        Version::HTTP_3 => {
            tracing::debug!(
                url.full = %req.request_uri(),
                "h3 request detected, but sanitize_client_req_header does not yet support this",
            );
            req
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http::Uri;
    use rama_net::Protocol;

    #[test]
    fn should_sanitize_http1_except_connect() {
        for method in [
            Method::DELETE,
            Method::GET,
            Method::HEAD,
            Method::OPTIONS,
            Method::PATCH,
            Method::POST,
            Method::PUT,
            Method::QUERY,
            Method::TRACE,
        ]
        .into_iter()
        {
            let uri = Uri::from_static("https://example.com/test");

            let req = Request::builder().uri(uri).method(method).body(()).unwrap();
            let req = sanitize_client_req_header(req).unwrap();

            let (parts, _) = req.into_parts();

            assert_eq!(parts.uri.scheme(), None);
            assert_eq!(parts.uri.authority(), None);
            assert_eq!(parts.uri, "/test");
        }
    }

    #[test]
    fn should_sanitize_http1_absolute_root_to_origin_form_root() {
        let req = Request::builder()
            .uri(Uri::from_static("https://example.com"))
            .method(Method::GET)
            .body(())
            .unwrap();
        let req = sanitize_client_req_header(req).unwrap();

        let (parts, _) = req.into_parts();

        assert_eq!(parts.uri.scheme(), None);
        assert_eq!(parts.uri.authority(), None);
        assert_eq!(parts.uri, "/");
    }

    #[test]
    fn should_not_sanitize_http1_connect() {
        let uri = Uri::from_static("https://example.com/test");

        let req = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .body(())
            .unwrap();
        let req = sanitize_client_req_header(req).unwrap();

        let (parts, _) = req.into_parts();

        assert_eq!(parts.uri.scheme(), Some(&Protocol::HTTPS));
        assert_eq!(parts.uri.host_str().as_deref(), Some("example.com"));
    }

    #[test]
    fn should_not_sanitize_insecure_http1_request_over_http_proxy() {
        let uri = Uri::from_static("http://example.com/test");

        let req = Request::builder().uri(uri).body(()).unwrap();

        req.extensions().insert(ProxyAddress {
            address: rama_net::address::HostWithPort::example_domain_http(),
            credential: None,
            protocol: Some(Protocol::HTTP),
        });

        let req = sanitize_client_req_header(req).unwrap();

        let (parts, _) = req.into_parts();

        assert_eq!(parts.uri.scheme(), Some(&Protocol::HTTP));
        assert_eq!(parts.uri.host_str().as_deref(), Some("example.com"));
    }

    #[test]
    fn should_sanitize_secure_http1_request_over_http_proxy() {
        let uri = Uri::from_static("https://example.com/test");

        let req = Request::builder().uri(uri).body(()).unwrap();

        req.extensions().insert(ProxyAddress {
            address: rama_net::address::HostWithPort::example_domain_http(),
            credential: None,
            protocol: Some(Protocol::HTTP),
        });

        let req = sanitize_client_req_header(req).unwrap();

        let (parts, _) = req.into_parts();

        assert_eq!(parts.uri.scheme(), None);
        assert_eq!(parts.uri.authority(), None);
        assert_eq!(parts.uri, "/test");
    }

    #[test]
    fn should_sanitize_insecure_http1_request_over_socks_proxy() {
        let uri = Uri::from_static("http://example.com/test");

        let req = Request::builder().uri(uri).body(()).unwrap();

        req.extensions().insert(ProxyAddress {
            address: rama_net::address::HostWithPort::example_domain_http(),
            credential: None,
            protocol: Some(Protocol::SOCKS5),
        });

        let req = sanitize_client_req_header(req).unwrap();

        let (parts, _) = req.into_parts();

        assert_eq!(parts.uri.scheme(), None);
        assert_eq!(parts.uri.authority(), None);
        assert_eq!(parts.uri, "/test");
    }

    // Regression: a forwarded request received over a terminated TLS connection
    // (e.g. a MITM proxy upstream hop) arrives in origin-form with no scheme in
    // the URI. Its protocol MUST resolve to HTTPS via the `SecureTransport`
    // extension so the auto TLS connector secures the upstream hop. This
    // silently regressed to HTTP whenever `rama-http-types/tls` was not enabled
    // alongside `rama-net/tls`: `input_ext` then matched against a dummy
    // `SecureTransport` type instead of the real one inserted by the TLS
    // acceptor, so the connector went plaintext to a TLS upstream and the
    // upstream's TLS alert surfaced as `Parse(Version)` (http_mitm_proxy_boring).
    #[cfg(feature = "tls")]
    #[test]
    fn origin_form_request_over_terminated_tls_resolves_https() {
        use rama_net::tls::SecureTransport;

        let req = Request::builder()
            .uri("/ping")
            .header(HOST, "example.com:8443")
            .body(())
            .unwrap();
        req.extensions().insert(SecureTransport::default());

        assert_eq!(req.protocol(), Some(&Protocol::HTTPS));
    }
}
