use rama_core::Layer;
use rama_core::Service;
use rama_core::bytes::BytesMut;
use rama_core::extensions::ChainableExtensions;
use rama_core::extensions::ExtensionsMut;
use rama_core::telemetry::tracing;
use rama_error::BoxError;
use rama_error::ErrorContext;
use rama_error::OpaqueError;
use rama_http_headers::HeaderMapExt;
use rama_http_headers::Upgrade;
use rama_http_types::HeaderValue;
use rama_http_types::Method;
use rama_http_types::Request;
use rama_http_types::Version;
use rama_http_types::conn::TargetHttpVersion;
use rama_http_types::header::COOKIE;
use rama_http_types::header::Entry;
use rama_net::client::{ConnectorService, EstablishedClientConnection};
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
            mut conn,
            input: mut req,
        } = self.inner.connect(req).await.map_err(Into::into)?;

        let ext_chain = (&conn, &req);
        let version = ext_chain
            .get::<TargetHttpVersion>()
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
                conn.extensions_mut().insert(TargetHttpVersion(version));
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
) -> Result<(), OpaqueError> {
    let request_version = request.version();
    if request_version == target_version {
        tracing::trace!(
            "request version is already {target_version:?}, no version switching needed",
        );
        return Ok(());
    }

    tracing::trace!(
        "changing request version from {:?} to {:?}",
        request_version,
        target_version,
    );

    // TODO full implementation: https://github.com/plabayo/rama/issues/624

    if (request_version == Version::HTTP_10 || request_version == Version::HTTP_11)
        && target_version == Version::HTTP_2
        && request.headers().typed_get::<Upgrade>().is_some()
    {
        *request.method_mut() = Method::CONNECT;
    }

    // RFC 6265 §5.4: When converting to HTTP/1.x, merge multiple cookie headers into one
    // In HTTP/2 and HTTP/3, multiple cookie headers are allowed, but HTTP/1.x must have
    // at most one Cookie header field with values joined by "; "
    if target_version <= Version::HTTP_11 && request_version >= Version::HTTP_2 {
        merge_cookie_headers_for_http1(request)?;
    }

    *request.version_mut() = target_version;
    Ok(())
}

/// Merge multiple cookie headers into a single Cookie header for HTTP/1.x compliance
/// per RFC 6265 §5.4: "the user agent MUST NOT attach more than one Cookie header field"
fn merge_cookie_headers_for_http1<Body>(request: &mut Request<Body>) -> Result<(), OpaqueError> {
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
    use rama_http_types::header::COOKIE;

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
    fn test_same_version_http2_to_http2_no_processing() {
        let mut req = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://example.com")
            .header(COOKIE, "a=1")
            .header(COOKIE, "b=2")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_2).unwrap();

        // Should not merge when version is already the same
        let cookie_values: Vec<_> = req.headers().get_all(COOKIE).iter().collect();
        assert_eq!(
            cookie_values.len(),
            2,
            "Should not merge when version stays the same"
        );
    }

    #[test]
    fn test_same_version_http1_to_http1_no_processing() {
        let mut req = Request::builder()
            .version(Version::HTTP_11)
            .uri("https://example.com")
            .header(COOKIE, "a=1")
            .header(COOKIE, "b=2")
            .body(())
            .unwrap();

        adapt_request_version(&mut req, Version::HTTP_11).unwrap();

        // Should not merge when version is already the same
        let cookie_values: Vec<_> = req.headers().get_all(COOKIE).iter().collect();
        assert_eq!(
            cookie_values.len(),
            2,
            "Should not merge when version stays the same"
        );
    }
}
