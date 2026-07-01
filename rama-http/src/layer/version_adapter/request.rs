use rama_core::Layer;
use rama_core::Service;
use rama_core::bytes::BytesMut;
use rama_core::error::BoxError;
use rama_core::error::ErrorContext;
use rama_core::extensions::ExtensionsRef;
use rama_core::telemetry::tracing;
use rama_http_headers::Connection;
use rama_http_headers::HeaderMapExt;
use rama_http_headers::Host;
use rama_http_headers::SecWebSocketKey;
use rama_http_headers::SecWebSocketVersion;
use rama_http_headers::Upgrade;
use rama_http_types::HeaderValue;
use rama_http_types::Method;
use rama_http_types::Request;
use rama_http_types::Version;
use rama_http_types::conn::TargetHttpVersion;
use rama_http_types::header::COOKIE;
use rama_http_types::header::Entry;
use rama_http_types::header::HOST;
use rama_http_types::header::{SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_VERSION};
use rama_http_types::proto::h2::ext::Protocol;
use rama_net::client::{ConnectorService, EstablishedClientConnection};
use rama_net::{AuthorityInputExt, Protocol as Scheme, ProtocolInputExt};

use crate::layer::remove_header::remove_illegal_h2_request_headers;
use rama_utils::macros::generate_set_and_with;

#[derive(Clone, Debug)]
/// [`ConnectorService`] which will adapt the request version if needed.
///
/// It will adapt the request version to [`TargetHttpVersion`], or the configured
/// default version
pub struct RequestVersionAdapter<S> {
    inner: S,
    default_http_version: Option<Version>,
}

impl<S> RequestVersionAdapter<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            default_http_version: None,
        }
    }

    generate_set_and_with! {
        /// Set default request [`Version`] which will be used if [`TargetHttpVersion`] is
        /// is not present in extensions
        pub fn default_version(mut self, version: Option<Version>) -> Self {
            self.default_http_version = version;
            self
        }
    }
}

impl<S, Body> Service<Request<Body>> for RequestVersionAdapter<S>
where
    S: ConnectorService<Request<Body>, Error: Into<BoxError>>,
    Body: Send + 'static,
{
    type Output = EstablishedClientConnection<S::Connection, Request<Body>>;
    type Error = BoxError;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Output, Self::Error> {
        let EstablishedClientConnection {
            conn,
            input: mut req,
        } = self.inner.connect(req).await.into_box_error()?;

        let version = req
            .extensions()
            .clone_to_if_absent::<TargetHttpVersion>(conn.extensions())
            .map(|version| version.0);

        match (version, self.default_http_version) {
            (Some(version), _) => {
                tracing::trace!(
                    "setting request version to {:?} based on configured TargetHttpVersion (was: {:?})",
                    version,
                    req.version(),
                );
                adapt_request_version(&mut req, version)?;
            }
            (_, Some(version)) => {
                tracing::trace!(
                    "setting request version to {:?} based on configured default http version (was: {:?})",
                    version,
                    req.version(),
                );
                adapt_request_version(&mut req, version)?;

                // Since this default is now the actual target, also store this on the connection so other components
                // can see this. This is needed in case this adapter is used twice e.g. with connection pooling
                conn.extensions().insert(TargetHttpVersion(version));
            }
            (None, None) => {
                tracing::trace!(
                    "no TargetHttpVersion or default http version configured, leaving request version {:?}",
                    req.version(),
                );
            }
        }

        Ok(EstablishedClientConnection { input: req, conn })
    }
}

#[derive(Clone, Debug, Default)]
/// [`ConnectorService`] layer which will adapt the request version if needed.
///
/// It will adapt the request version to [`TargetHttpVersion`], or the configured
/// default version
pub struct RequestVersionAdapterLayer {
    default_http_version: Option<Version>,
}

impl RequestVersionAdapterLayer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            default_http_version: None,
        }
    }

    generate_set_and_with! {
        /// Set default request [`Version`] which will be used if [`TargetHttpVersion`] is
        /// is not present in extensions
        pub fn default_version(mut self, version: Option<Version>) -> Self {
            self.default_http_version = version;
            self
        }
    }
}

impl<S> Layer<S> for RequestVersionAdapterLayer {
    type Service = RequestVersionAdapter<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestVersionAdapter {
            inner,
            default_http_version: self.default_http_version,
        }
    }
}

/// Adapt request to match the provided [`Version`]
pub fn adapt_request_version<Body>(
    request: &mut Request<Body>,
    target_version: Version,
) -> Result<(), BoxError> {
    let request_version = request.version();
    if request_version == target_version {
        tracing::trace!(
            ?target_version,
            "request version already satisfied, skipping it"
        );
        return Ok(());
    }
    tracing::trace!(
        ?request_version,
        ?target_version,
        "changing request version"
    );

    let request_is_h1 = request_version <= Version::HTTP_11;
    let target_is_h1 = target_version <= Version::HTTP_11;

    // Translate the handshake (WebSocket method / `:protocol` form) when
    // crossing the HTTP/1 <-> HTTP/2/3 boundary. Within a class it is already correct.
    match (request_is_h1, target_is_h1) {
        (true, false) => translate_request_upgrade(request)?,
        (false, true) => translate_request_downgrade(request)?,
        (true, true) | (false, false) => {}
    }

    // Normalize the request so it is valid for the target version (runs regardless of
    // whether the version actually changed).
    *request.version_mut() = target_version;
    ensure_valid_request_for_version(request)?;

    Ok(())
}

/// Normalize `request` so it is valid for it's configured `version`
pub fn ensure_valid_request_for_version<Body>(request: &mut Request<Body>) -> Result<(), BoxError> {
    if request.version() <= Version::HTTP_11 {
        ensure_valid_h1_request(request)
    } else {
        ensure_valid_h2_or_h3_request(request)
    }
}

/// Normalize a request so it is a valid HTTP/1.x request: ensure a `Host` header and
/// collapse multiple `Cookie` headers into one (RFC 6265 §5.4).
pub fn ensure_valid_h1_request<Body>(request: &mut Request<Body>) -> Result<(), BoxError> {
    ensure_h1_host_header(request)?;
    merge_cookie_headers_for_http1(request)?;
    Ok(())
}

/// Normalize a request so it is a valid HTTP/2 or HTTP/3 request: ensure the
/// authority/scheme live in the URI (for the `:authority`/`:scheme` pseudo-headers) and
/// strip the connection-specific headers those versions forbid (RFC 9113 §8.2.2).
pub fn ensure_valid_h2_or_h3_request<Body>(request: &mut Request<Body>) -> Result<(), BoxError> {
    ensure_h2_or_h3_uri_authority(request)?;
    remove_illegal_h2_request_headers(request.headers_mut());
    Ok(())
}

/// Whether a [`Protocol`] is the WebSocket Extended CONNECT / `Upgrade` protocol.
pub(crate) fn is_websocket_protocol(protocol: &Protocol) -> bool {
    protocol.as_str().eq_ignore_ascii_case("websocket")
}

/// The Extended CONNECT / `Upgrade` application protocol a request is *genuinely*
/// switching to (e.g. `websocket`), if any.
///
/// HTTP/2 and HTTP/3 carry it in the `:protocol` pseudo-header (the [`Protocol`]
/// extension on a `CONNECT`). HTTP/1 carries it in the `Upgrade` header, but only
/// counts as a genuine switch when accompanied by `Connection: Upgrade` — otherwise
/// it is a mere protocol advertisement, which is ignored (not an error).
pub(crate) fn request_connect_protocol<Body>(request: &Request<Body>) -> Option<Protocol> {
    if request.method() == Method::CONNECT
        && let Some(protocol) = request.extensions().get_ref::<Protocol>()
    {
        return Some(protocol.clone());
    }

    let is_genuine_upgrade = request
        .headers()
        .typed_get::<Connection>()
        .is_some_and(|connection| connection.contains_upgrade());
    if !is_genuine_upgrade {
        return None;
    }
    let upgrade = request.headers().typed_get::<Upgrade>()?;
    let token = std::str::from_utf8(upgrade.as_bytes()).ok()?.trim();
    (!token.is_empty()).then(|| Protocol::from(token))
}

/// Translate the handshake envelope of an HTTP/1.x request up to HTTP/2 or HTTP/3.
///
/// Converts a WebSocket `Upgrade` handshake into an Extended CONNECT (RFC 8441 for
/// HTTP/2, RFC 9220 for HTTP/3 — same `:protocol` pseudo-header). WebSocket is the only
/// Extended CONNECT protocol whose cross-version translation is supported; any other
/// genuine upgrade is rejected rather than silently dropped. Header validity (authority,
/// stripping illegal headers) is handled separately by [`ensure_valid_h2_or_h3_request`].
fn translate_request_upgrade<Body>(request: &mut Request<Body>) -> Result<(), BoxError> {
    match request_connect_protocol(request) {
        Some(protocol) if is_websocket_protocol(&protocol) => {
            // `GET` + `Upgrade: websocket` -> `CONNECT` + `:protocol: websocket`.
            tracing::trace!("translating h1 websocket upgrade into h2/h3 extended CONNECT");
            *request.method_mut() = Method::CONNECT;
            request
                .extensions()
                .insert(Protocol::from_static("websocket"));
        }
        Some(protocol) => {
            return Err(BoxError::from(format!(
                "cannot translate HTTP/1 `Upgrade: {}` into an HTTP/2+ Extended CONNECT: only websocket is supported",
                protocol.as_str(),
            )));
        }
        None => {}
    }
    Ok(())
}

/// Translate the handshake envelope of an HTTP/2 or HTTP/3 request down to HTTP/1.x.
///
/// Converts an Extended CONNECT WebSocket request back into an HTTP/1.x `Upgrade`
/// handshake. A non-WebSocket Extended CONNECT is rejected, a plain `CONNECT` tunnel
/// (no `:protocol`) is left untouched. The `Host` header is added separately by
/// [`ensure_valid_h1_request`].
fn translate_request_downgrade<Body>(request: &mut Request<Body>) -> Result<(), BoxError> {
    match request_connect_protocol(request) {
        Some(protocol) if is_websocket_protocol(&protocol) => {
            // `CONNECT` + `:protocol: websocket` -> `GET` + `Upgrade: websocket`.
            tracing::trace!("translating h2/h3 extended CONNECT websocket into h1 upgrade");
            *request.method_mut() = Method::GET;

            let headers = request.headers_mut();
            headers.typed_insert(Upgrade::websocket());
            headers.typed_insert(Connection::upgrade());
            if !headers.contains_key(SEC_WEBSOCKET_KEY) {
                headers.typed_insert(SecWebSocketKey::random());
            }
            if !headers.contains_key(SEC_WEBSOCKET_VERSION) {
                headers.typed_insert(SecWebSocketVersion::V13);
            }

            // NOTE: the `:protocol` pseudo-header is carried via the `Protocol`
            // extension, which is only emitted on HTTP/2 CONNECT requests. It is inert
            // for HTTP/1 and `Extensions` has no removal API, so we leave it in place.
        }
        Some(protocol) => {
            return Err(BoxError::from(format!(
                "cannot translate an HTTP/2+ Extended CONNECT `:protocol: {}` request to HTTP/1: only websocket is supported",
                protocol.as_str(),
            )));
        }
        None => {}
    }
    Ok(())
}

/// Ensure an HTTP/1.x request carries a `Host` header.
///
/// HTTP/1 carries the routing authority in the `Host` header, whereas HTTP/2 and
/// HTTP/3 carry it in the `:authority` pseudo-header (the URI). The `Host` header is
/// derived from the request authority when missing. Used both when downgrading a
/// request to HTTP/1 and as a general send-time backstop.
pub fn ensure_h1_host_header<Body>(request: &mut Request<Body>) -> Result<(), BoxError> {
    if request.headers().contains_key(HOST) {
        return Ok(());
    }
    let authority = request
        .authority()
        .context("ensure h1 Host header: request has no resolvable authority")?;
    let protocol = request.protocol().cloned();
    // Strip the default port (browsers do this, and some reverse proxies 404 on a
    // non-exact authority match).
    let authority = authority.without_default_port_for(protocol.as_ref());
    tracing::trace!("adding Host header {authority} derived from request authority");
    request.headers_mut().typed_insert(Host::from(authority));
    Ok(())
}

/// Ensure an HTTP/2 or HTTP/3 request carries its authority and scheme in the URI.
///
/// HTTP/2 and HTTP/3 require the `:authority`/`:scheme` pseudo-headers, which the
/// underlying crates derive from the URI. When converting up from HTTP/1 (where the
/// authority lives in the `Host` header) the URI authority and scheme are materialized
/// from the request authority if the URI lacks a host. Used both when upgrading a
/// request to HTTP/2+ and as a general send-time backstop.
pub fn ensure_h2_or_h3_uri_authority<Body>(request: &mut Request<Body>) -> Result<(), BoxError> {
    if request.uri().host().is_some() {
        return Ok(());
    }
    let authority = request
        .authority()
        .context("ensure h2 URI authority: request has no resolvable authority")?;
    let protocol = request.protocol().cloned();
    let authority = authority.without_default_port_for(protocol.as_ref());
    tracing::trace!("materializing authority {authority} and scheme into request URI");
    let uri = request.uri_mut();
    uri.set_scheme(protocol.unwrap_or(Scheme::HTTP));
    uri.set_host(authority.host);
    uri.set_port(authority.port);
    Ok(())
}

/// Merge multiple cookie headers into a single Cookie header for HTTP/1.x compliance
/// per RFC 6265 §5.4: "the user agent MUST NOT attach more than one Cookie header field"
fn merge_cookie_headers_for_http1<Body>(request: &mut Request<Body>) -> Result<(), BoxError> {
    if let Entry::Occupied(cookie_headers) = request.headers_mut().entry(COOKIE) {
        let Some((bytes_count, header_count)) = cookie_headers
            .iter()
            .map(|v| (v.as_bytes().len(), 1usize))
            .reduce(|a, b| (a.0 + b.0, a.1 + b.1))
        else {
            return Ok(());
        };
        if header_count <= 1 {
            return Ok(());
        }

        let (header_name, mut header_values) = cookie_headers.remove_entry_mult();

        let mut buffer = BytesMut::with_capacity(bytes_count + ((header_count - 1) * 2));
        if let Some(header_value) = header_values.next() {
            buffer.extend_from_slice(header_value.as_bytes());
        }
        for header_value in header_values {
            buffer.extend_from_slice(b"; ");
            buffer.extend_from_slice(header_value.as_bytes());
        }

        let new_header_value = HeaderValue::from_maybe_shared(buffer)
            .context("create new cookie header value from combined multiple values")?;

        request.headers_mut().insert(header_name, new_header_value);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http_types::header::{CONNECTION, COOKIE, HOST, TRANSFER_ENCODING, UPGRADE};

    #[test]
    fn test_h1_to_h2_strips_connection_specific_headers() {
        let mut req = Request::builder()
            .version(Version::HTTP_11)
            .uri("https://example.com")
            .header(HOST, "example.com")
            .header(CONNECTION, "keep-alive, x-custom")
            .header("keep-alive", "timeout=5")
            .header(TRANSFER_ENCODING, "chunked")
            .header("x-custom", "1")
            .header("x-keep", "yes")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_2).unwrap();

        assert_eq!(req.version(), Version::HTTP_2);
        for illegal in [&HOST, &CONNECTION, &TRANSFER_ENCODING] {
            assert!(
                !req.headers().contains_key(illegal),
                "expected {illegal:?} to be removed"
            );
        }
        // header named by the Connection header must also be gone
        assert!(!req.headers().contains_key("x-custom"));
        assert!(!req.headers().contains_key("keep-alive"));
        // unrelated headers are preserved
        assert_eq!(req.headers().get("x-keep").unwrap(), "yes");
    }

    #[test]
    fn test_h1_to_h2_websocket_upgrade_becomes_extended_connect() {
        let mut req = Request::builder()
            .version(Version::HTTP_11)
            .method(Method::GET)
            .uri("https://example.com/chat")
            .header(UPGRADE, "websocket")
            .header(CONNECTION, "Upgrade")
            .header(SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
            .header(SEC_WEBSOCKET_VERSION, "13")
            .header("sec-websocket-protocol", "chat")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_2).unwrap();

        assert_eq!(req.method(), Method::CONNECT);
        assert_eq!(
            req.extensions().get_ref::<Protocol>().map(|p| p.as_str()),
            Some("websocket"),
        );
        // h1 handshake headers are removed for h2 (RFC 8441 §5.1)
        assert!(!req.headers().contains_key(UPGRADE));
        assert!(!req.headers().contains_key(CONNECTION));
        assert!(!req.headers().contains_key(SEC_WEBSOCKET_KEY));
        // Sec-WebSocket-Version is kept in h2, as is the requested subprotocol
        assert_eq!(req.headers().get(SEC_WEBSOCKET_VERSION).unwrap(), "13");
        assert_eq!(req.headers().get("sec-websocket-protocol").unwrap(), "chat");
    }

    #[test]
    fn test_h2_to_h1_websocket_connect_becomes_upgrade() {
        let mut req = Request::builder()
            .version(Version::HTTP_2)
            .method(Method::CONNECT)
            .uri("https://example.com/chat")
            .header(SEC_WEBSOCKET_VERSION, "13")
            .body(())
            .unwrap();
        req.extensions().insert(Protocol::from_static("websocket"));

        adapt_request_version(&mut req, Version::HTTP_11).unwrap();

        assert_eq!(req.method(), Method::GET);
        assert_eq!(req.version(), Version::HTTP_11);
        assert!(
            req.headers()
                .typed_get::<Upgrade>()
                .is_some_and(|u| u.is_websocket())
        );
        assert!(
            req.headers()
                .typed_get::<Connection>()
                .is_some_and(|c| c.contains_upgrade())
        );
        // a fresh key is generated and the version is retained
        assert!(req.headers().contains_key(SEC_WEBSOCKET_KEY));
        assert_eq!(req.headers().get(SEC_WEBSOCKET_VERSION).unwrap(), "13");
    }

    #[test]
    fn test_h2_to_h1_non_websocket_connect_untouched() {
        let mut req = Request::builder()
            .version(Version::HTTP_2)
            .method(Method::CONNECT)
            .uri("example.com:443")
            .header(HOST, "example.com:443")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_11).unwrap();

        // plain CONNECT (no :protocol) must not gain websocket headers
        assert_eq!(req.method(), Method::CONNECT);
        assert!(!req.headers().contains_key(UPGRADE));
        assert!(!req.headers().contains_key(SEC_WEBSOCKET_KEY));
    }

    #[test]
    fn test_h2_to_h1_adds_host_from_authority() {
        let mut req = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://example.com/path")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_11).unwrap();

        // HTTP/1 carries the authority in the Host header, derived from the URI
        assert_eq!(req.version(), Version::HTTP_11);
        assert_eq!(req.headers().get(HOST).unwrap(), "example.com");
    }

    #[test]
    fn test_h1_to_h2_materializes_uri_authority_and_strips_host() {
        let mut req = Request::builder()
            .version(Version::HTTP_11)
            .uri("/path")
            .header(HOST, "example.com")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_2).unwrap();

        assert_eq!(req.version(), Version::HTTP_2);
        // authority now lives in the URI (for :authority/:scheme); Host header is gone
        assert_eq!(req.uri().host_str().as_deref(), Some("example.com"));
        assert!(!req.headers().contains_key(HOST));
    }

    #[test]
    fn test_h1_to_h3_websocket_upgrade_becomes_extended_connect() {
        let mut req = Request::builder()
            .version(Version::HTTP_11)
            .method(Method::GET)
            .uri("https://example.com/chat")
            .header(UPGRADE, "websocket")
            .header(CONNECTION, "Upgrade")
            .header(SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_3).unwrap();

        // HTTP/3 reuses HTTP/2's Extended CONNECT model (RFC 9220), so the conversion
        // is identical — proving the class-based translation handles h3 for free.
        assert_eq!(req.version(), Version::HTTP_3);
        assert_eq!(req.method(), Method::CONNECT);
        assert_eq!(
            req.extensions().get_ref::<Protocol>().map(|p| p.as_str()),
            Some("websocket"),
        );
        assert!(!req.headers().contains_key(UPGRADE));
        assert!(!req.headers().contains_key(SEC_WEBSOCKET_KEY));
    }

    #[test]
    fn test_h2_to_h3_only_changes_version() {
        let mut req = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://example.com/path")
            .header(COOKIE, "a=1")
            .header(COOKIE, "b=2")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_3).unwrap();

        // same semantic class (h2<->h3): only the version field changes, no cookie
        // merge, nothing stripped
        assert_eq!(req.version(), Version::HTTP_3);
        assert_eq!(req.headers().get_all(COOKIE).iter().count(), 2);
    }

    #[test]
    fn test_h1_to_h2_unsupported_upgrade_errors() {
        let mut req = Request::builder()
            .version(Version::HTTP_11)
            .method(Method::GET)
            .uri("https://example.com/")
            .header(UPGRADE, "myproto")
            .header(CONNECTION, "Upgrade")
            .body(())
            .unwrap();

        // a genuine non-websocket upgrade switch we can't translate -> explicit error,
        // not a silent strip.
        let err = adapt_request_version(&mut req, Version::HTTP_2).unwrap_err();
        assert!(
            err.to_string().contains("only websocket is supported"),
            "{err}"
        );
    }

    #[test]
    fn test_h1_to_h2_upgrade_advertisement_is_not_a_switch() {
        let mut req = Request::builder()
            .version(Version::HTTP_11)
            .method(Method::GET)
            .uri("https://example.com/")
            // `Upgrade` without `Connection: Upgrade` is a mere advertisement, not a
            // protocol switch -> no error, just stripped on the way to h2.
            .header(UPGRADE, "h2c")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_2).unwrap();

        assert_eq!(req.version(), Version::HTTP_2);
        assert!(!req.headers().contains_key(UPGRADE));
    }

    #[test]
    fn test_h2_to_h1_unsupported_extended_connect_errors() {
        let mut req = Request::builder()
            .version(Version::HTTP_2)
            .method(Method::CONNECT)
            .uri("https://example.com/")
            .body(())
            .unwrap();
        req.extensions()
            .insert(Protocol::from_static("connect-udp"));

        let err = adapt_request_version(&mut req, Version::HTTP_11).unwrap_err();
        assert!(
            err.to_string().contains("only websocket is supported"),
            "{err}"
        );
    }

    #[test]
    fn test_merge_multiple_cookies_http2_to_http1() {
        let mut req = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://example.com")
            .header(COOKIE, "a=1")
            .header(COOKIE, "b=2")
            .header(COOKIE, "c=3")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_11).unwrap();

        // Should now have exactly one Cookie header
        let cookie_values: Vec<_> = req.headers().get_all(COOKIE).iter().collect();
        assert_eq!(
            cookie_values.len(),
            1,
            "Should have exactly one Cookie header"
        );

        // The merged value should contain all cookies joined by "; "
        assert_eq!(cookie_values[0].as_bytes(), b"a=1; b=2; c=3");

        // Version should be changed
        assert_eq!(req.version(), Version::HTTP_11);
    }

    #[test]
    fn test_merge_multiple_cookies_http3_to_http1() {
        let mut req = Request::builder()
            .version(Version::HTTP_3)
            .uri("https://example.com")
            .header(COOKIE, "session=abc123")
            .header(COOKIE, "token=xyz789")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_11).unwrap();

        let cookie_values: Vec<_> = req.headers().get_all(COOKIE).iter().collect();
        assert_eq!(
            cookie_values.len(),
            1,
            "Should have exactly one Cookie header"
        );
        assert_eq!(cookie_values[0].as_bytes(), b"session=abc123; token=xyz789");
    }

    #[test]
    fn test_single_cookie_http2_to_http1_unchanged() {
        let mut req = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://example.com")
            .header(COOKIE, "single=cookie")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_11).unwrap();

        // Should still have one Cookie header, unchanged
        let cookie_values: Vec<_> = req.headers().get_all(COOKIE).iter().collect();
        assert_eq!(cookie_values.len(), 1);
        assert_eq!(cookie_values[0].as_bytes(), b"single=cookie");
    }

    #[test]
    fn test_no_merge_http1_to_http2() {
        let mut req = Request::builder()
            .version(Version::HTTP_11)
            .uri("https://example.com")
            .header(COOKIE, "a=1")
            .header(COOKIE, "b=2")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_2).unwrap();

        // When going from HTTP/1 to HTTP/2, don't merge (keep as-is)
        let cookie_values: Vec<_> = req.headers().get_all(COOKIE).iter().collect();
        assert_eq!(
            cookie_values.len(),
            2,
            "Should preserve multiple headers when converting to HTTP/2"
        );
    }

    #[test]
    fn test_no_cookies_http2_to_http1() {
        let mut req = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://example.com")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_11).unwrap();

        // Should have no Cookie headers
        let cookie_values: Vec<_> = req.headers().get_all(COOKIE).iter().collect();
        assert_eq!(cookie_values.len(), 0);
    }

    #[test]
    fn test_merge_preserves_order() {
        let mut req = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://example.com")
            .header(COOKIE, "first=1")
            .header(COOKIE, "second=2")
            .header(COOKIE, "third=3")
            .header(COOKIE, "fourth=4")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_11).unwrap();

        // Should have only one cookie header and the order should be preserved
        let cookie_values: Vec<_> = req.headers().get_all(COOKIE).iter().collect();
        assert_eq!(cookie_values.len(), 1);
        assert_eq!(
            cookie_values[0].as_bytes(),
            b"first=1; second=2; third=3; fourth=4",
            "Cookie order should be preserved"
        );
    }

    #[test]
    fn test_complex_cookie_values() {
        let mut req = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://example.com")
            .header(COOKIE, "uaid=abc123def456")
            .header(COOKIE, "MSCC=NR")
            .header(COOKIE, "MUID=1234567890ABCDEF")
            .header(COOKIE, "VAL1=ASD=DSA&HASH=41&LV=41&V=4&LU=41")
            .header(COOKIE, "empty=")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_11).unwrap();

        // also should have only one cookie header with complex values preserved
        let cookie_values: Vec<_> = req.headers().get_all(COOKIE).iter().collect();
        assert_eq!(cookie_values.len(), 1);
        assert_eq!(
            cookie_values[0].as_bytes(),
            b"uaid=abc123def456; MSCC=NR; MUID=1234567890ABCDEF; VAL1=ASD=DSA&HASH=41&LV=41&V=4&LU=41; empty=",
        );
    }

    #[test]
    fn test_same_version_http2_keeps_multiple_cookies() {
        let mut req = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://example.com")
            .header(COOKIE, "a=1")
            .header(COOKIE, "b=2")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_2).unwrap();

        // multiple Cookie headers are legal in HTTP/2, so normalizing must not merge them
        let cookie_values: Vec<_> = req.headers().get_all(COOKIE).iter().collect();
        assert_eq!(cookie_values.len(), 2);
    }

    #[test]
    fn test_same_version_http1_is_noop() {
        let mut req = Request::builder()
            .version(Version::HTTP_11)
            .uri("https://example.com")
            .header(COOKIE, "a=1")
            .header(COOKIE, "b=2")
            .body(())
            .unwrap();

        // adapting to the same version is a no-op (it only translates across versions)
        adapt_request_version(&mut req, Version::HTTP_11).unwrap();

        let cookie_values: Vec<_> = req.headers().get_all(COOKIE).iter().collect();
        assert_eq!(cookie_values.len(), 2);
    }

    #[test]
    fn test_ensure_valid_h1_request_normalizes() {
        let mut req = Request::builder()
            .version(Version::HTTP_11)
            .uri("https://example.com")
            .header(COOKIE, "a=1")
            .header(COOKIE, "b=2")
            .body(())
            .unwrap();

        // the standalone normalizer makes the request valid for HTTP/1: multiple Cookie
        // headers are merged into one (RFC 6265 §5.4) and a Host header is ensured.
        ensure_valid_request_for_version(&mut req).unwrap();

        let cookie_values: Vec<_> = req.headers().get_all(COOKIE).iter().collect();
        assert_eq!(cookie_values.len(), 1);
        assert_eq!(cookie_values[0].as_bytes(), b"a=1; b=2");
        assert!(req.headers().contains_key(HOST));
    }
}
