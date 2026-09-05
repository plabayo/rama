use rama::{
    Layer, Service,
    http::{
        HeaderName, HeaderValue, Request,
        headers::{HeaderEncode, TypedHeader},
    },
    telemetry::tracing,
};

/// Private, harness-only header used to attribute a stress request to the
/// provider process that actually intercepted it.
///
/// This header is deliberately consumed at the HTTP relay boundary. It must
/// never be forwarded to an origin server: besides weakening the evidence,
/// forwarding it would unnecessarily disclose a local run identifier.
pub const STRESS_RUN_HEADER_NAME: &str = "x-rama-tproxy-stress-run";

/// Stable public os_log message prefix consumed by `stress_evidence.py`.
///
/// Keep the message free of request URLs, headers, application identity, or
/// other user-controlled data. The only suffix accepted by the parser is a
/// canonical random run UUID and privacy-safe per-request identifier generated
/// by the stress harness.
pub const STRESS_ATTRIBUTION_EVENT_PREFIX: &str = "rama stress request attributed: run_uuid=";

#[derive(Debug, Clone, Default)]
pub struct StressRequestAttributionLayer;

impl<S> Layer<S> for StressRequestAttributionLayer {
    type Service = StressRequestAttributionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        StressRequestAttributionService(inner)
    }
}

#[derive(Debug, Clone)]
pub struct StressRequestAttributionService<S>(S);

impl<S, ReqBody> Service<Request<ReqBody>> for StressRequestAttributionService<S>
where
    S: Service<Request<ReqBody>>,
    ReqBody: Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, mut request: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        // `remove` strips every occurrence, including malformed or duplicated
        // values. Only one exact UUID/request-ID pair earns an attribution record.
        // Thus hostile/mistaken callers cannot smuggle the private marker to
        // egress or inflate the harness count with ambiguous input.
        let marker = take_stress_run_marker(request.headers_mut());
        if let Some((run_uuid, request_id)) = marker {
            tracing::info!(
                target: "rama_tproxy_example::stress_attribution",
                "{STRESS_ATTRIBUTION_EVENT_PREFIX}{run_uuid} request_id={request_id}",
            );
        }
        self.0.serve(request).await
    }
}

fn take_stress_run_marker(headers: &mut rama::http::HeaderMap) -> Option<(String, String)> {
    let values = headers.get_all(STRESS_RUN_HEADER_NAME);
    let mut iter = values.iter();
    let first = iter.next().and_then(|value| value.to_str().ok());
    let unique = iter.next().is_none();
    let marker = first.and_then(|value| {
        let (run_uuid, request_id) = value.split_once(':')?;
        (unique && is_canonical_uuid(run_uuid) && is_lower_hex_sha256(request_id))
            .then(|| (run_uuid.to_owned(), request_id.to_owned()))
    });
    headers.remove(STRESS_RUN_HEADER_NAME);
    marker
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_canonical_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    value.bytes().enumerate().all(|(index, byte)| match index {
        8 | 13 | 18 | 23 => byte == b'-',
        _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
    })
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct XRamaTransparentProxyObservedHeader;

impl XRamaTransparentProxyObservedHeader {
    #[inline(always)]
    pub fn new() -> Self {
        Self
    }
}

impl TypedHeader for XRamaTransparentProxyObservedHeader {
    fn name() -> &'static HeaderName {
        static NAME: HeaderName = HeaderName::from_static("x-rama-tproxy-observed");
        &NAME
    }
}

impl HeaderEncode for XRamaTransparentProxyObservedHeader {
    fn encode<E: Extend<rama::http::HeaderValue>>(&self, values: &mut E) {
        values.extend([
            HeaderValue::try_from(format!("seen-by-{}", std::process::id())).unwrap_or_else(
                |err| {
                    tracing::warn!(error = %err, "failed to create proxy observed header");
                    HeaderValue::from_static("seen")
                },
            ),
        ]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{http::Response, service::service_fn};
    use std::convert::Infallible;

    #[test]
    fn marker_parser_accepts_only_canonical_lowercase_uuid() {
        assert!(is_canonical_uuid("12345678-1234-4234-8234-123456789abc"));
        assert!(!is_canonical_uuid("12345678-1234-4234-8234-123456789ABC"));
        assert!(!is_canonical_uuid("12345678123442348234123456789abc"));
        assert!(!is_canonical_uuid("12345678-1234-4234-8234-private-data"));
        assert!(is_lower_hex_sha256(&"a".repeat(64)));
        assert!(!is_lower_hex_sha256(&"A".repeat(64)));
    }

    #[tokio::test]
    async fn marker_is_removed_before_egress() {
        let service =
            StressRequestAttributionLayer.layer(service_fn(async |request: Request<()>| {
                assert!(!request.headers().contains_key(STRESS_RUN_HEADER_NAME));
                Ok::<_, Infallible>(Response::new(()))
            }));
        let request = Request::builder()
            .header(
                STRESS_RUN_HEADER_NAME,
                concat!(
                    "12345678-1234-4234-8234-123456789abc:",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
            )
            .body(())
            .unwrap();
        service.serve(request).await.unwrap();
    }

    #[tokio::test]
    async fn duplicate_markers_are_all_removed() {
        let service =
            StressRequestAttributionLayer.layer(service_fn(async |request: Request<()>| {
                assert!(!request.headers().contains_key(STRESS_RUN_HEADER_NAME));
                Ok::<_, Infallible>(Response::new(()))
            }));
        let request = Request::builder()
            .header(
                STRESS_RUN_HEADER_NAME,
                concat!(
                    "12345678-1234-4234-8234-123456789abc:",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
            )
            .header(
                STRESS_RUN_HEADER_NAME,
                concat!(
                    "12345678-1234-4234-8234-123456789abc:",
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ),
            )
            .body(())
            .unwrap();
        service.serve(request).await.unwrap();
    }
}
