use rama::{
    Layer, Service,
    bytes::Bytes,
    error::BoxError,
    extensions::ExtensionsRef as _,
    futures::async_stream::stream_fn,
    http::{
        Body, Method, Request, Response, StreamingBody,
        header::CONTENT_ENCODING,
        headers::{ContentType, HeaderMapExt},
        layer::remove_header::{
            remove_cache_validation_response_headers, remove_payload_metadata_headers,
        },
        mime,
    },
    matcher::service::{ServiceMatch, ServiceMatcher},
    net::{address::Domain, http::RequestContext, proxy::ProxyTarget},
    telemetry::tracing,
    utils::{
        octets::kib,
        str::{contains_ignore_ascii_case, submatch_ignore_ascii_case},
    },
};
use std::{borrow::Cow, convert::Infallible};

use crate::policy::DomainExclusionList;

const BADGE_MARKER: &[u8] = b"id=\"rama-proxy-badge\"";
const BODY_OPEN: &[u8] = b"<body";
/// Hard cap on how many bytes we'll buffer once we've seen `<body`
/// while waiting for the closing `>` of the opening tag. A real opening
/// tag (`<body class="…" data-…>`) is tens of bytes; 4 KiB is comfortably
/// above the worst real-world value and below any size that matters for
/// streaming latency.
const MAX_OPEN_TAG_SCAN: usize = kib(4);

#[derive(Debug, Clone)]
pub struct HtmlBadgeLayer {
    enabled: bool,
    badge_html: Vec<u8>,
    excluded_domains: DomainExclusionList,
}

impl HtmlBadgeLayer {
    #[inline(always)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            enabled: true,
            badge_html: badge_html("proxied by rama"),
            excluded_domains: DomainExclusionList::default(),
        }
    }

    pub fn with_badge_label(mut self, badge_label: impl AsRef<str>) -> Self {
        self.badge_html = badge_html(badge_label.as_ref());
        self
    }

    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn with_excluded_domains(mut self, excluded_domains: DomainExclusionList) -> Self {
        self.excluded_domains = excluded_domains;
        self
    }

    pub fn decompression_matcher(&self) -> HtmlBadgeDecompressionMatcher {
        HtmlBadgeDecompressionMatcher {
            enabled: self.enabled,
            excluded_domains: self.excluded_domains.clone(),
        }
    }
}

impl<S> Layer<S> for HtmlBadgeLayer {
    type Service = HtmlBadgeService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        let Self {
            enabled,
            badge_html,
            excluded_domains,
        } = self;

        HtmlBadgeService {
            inner,
            enabled: *enabled,
            badge_html: badge_html.clone(),
            excluded_domains: excluded_domains.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        let Self {
            enabled,
            badge_html,
            excluded_domains,
        } = self;

        HtmlBadgeService {
            inner,
            enabled,
            badge_html,
            excluded_domains,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HtmlBadgeService<S> {
    inner: S,
    enabled: bool,
    badge_html: Vec<u8>,
    excluded_domains: DomainExclusionList,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for HtmlBadgeService<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error = BoxError>,
    ReqBody: Send + 'static,
    ResBody: rama::http::StreamingBody<Data = Bytes, Error: Into<BoxError> + Send>
        + Send
        + Sync
        + 'static,
{
    type Output = Response<Body>;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let req_method = req.method().clone();
        let req_domain = RequestContext::try_from(&req)
            .ok()
            .and_then(|rc| rc.authority.host.try_into_domain().ok());
        let req_uri = req.uri().clone();

        let response = self.inner.serve(req).await?;

        if !self.enabled {
            return Ok(response.map(Body::new));
        }

        if req_method == Method::HEAD {
            tracing::debug!(
                "skip HTML (domain = {req_domain:?}; method = {req_method:?}; uri = {req_uri}; ) \
                modification: request method = HEAD",
            );
            return Ok(response.map(Body::new));
        }

        if req_domain
            .as_ref()
            .map(|d| self.excluded_domains.is_excluded(d))
            .unwrap_or_default()
        {
            tracing::debug!(
                "skip HTML (domain = {req_domain:?}; method = {req_method:?}; uri = {req_uri}; ) \
                modification: request's domain is excluded",
            );
            return Ok(response.map(Body::new));
        }

        if !should_rewrite(&response) {
            tracing::debug!(
                "skip HTML (domain = {req_domain:?}; method = {req_method:?}; uri = {req_uri}; ) \
                modification: response detected as not to be rewritten",
            );
            return Ok(response.map(Body::new));
        }

        let (mut parts, body) = response.into_parts();
        // Drop length / cache-validation headers up front: streaming
        // injection may rewrite chunks, so the inbound Content-Length
        // and ETag no longer match what we'll emit. Going chunked is
        // safe regardless of whether the scan actually finds a `<body>`
        // and injects.
        remove_payload_metadata_headers(&mut parts.headers);
        remove_cache_validation_response_headers(&mut parts.headers);
        let new_body = Body::from_stream(badge_inject_stream(body, self.badge_html.clone()));
        Ok(Response::from_parts(parts, new_body))
    }
}

/// Wrap `body` in a streaming injector that emits the badge bytes right
/// after the `<body…>` opening tag and passes the rest through
/// unchanged. Buffered state is bounded — at most
/// `MAX_OPEN_TAG_SCAN` bytes while waiting for the tag's closing `>`,
/// otherwise just a small carry-over to catch `<body` / BADGE_MARKER
/// straddling a chunk boundary.
fn badge_inject_stream<B>(
    body: B,
    badge: Vec<u8>,
) -> impl rama::futures::Stream<Item = Result<Bytes, BoxError>> + Send + 'static
where
    B: StreamingBody<Data = Bytes, Error: Into<BoxError> + Send> + Send + 'static,
{
    stream_fn(async move |mut yielder| {
        let mut state = BadgeScanState::new();
        let mut body = std::pin::pin!(body);
        loop {
            let frame = match std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
                Some(Ok(f)) => f,
                Some(Err(e)) => {
                    yielder.yield_item(Err(e.into())).await;
                    return;
                }
                None => break,
            };
            let Ok(data) = frame.into_data() else {
                continue;
            };
            for chunk in state.process(data, &badge) {
                yielder.yield_item(Ok(chunk)).await;
            }
        }
        if let Some(tail) = state.flush() {
            yielder.yield_item(Ok(tail)).await;
        }
    })
}

fn should_rewrite<B>(response: &Response<B>) -> bool {
    if response.headers().contains_key(CONTENT_ENCODING) {
        return false;
    }

    is_html_rewrite_candidate(response)
}

fn is_request_eligible_for_html_rewrite(
    enabled: bool,
    method: &Method,
    domain: Option<&Domain>,
    excluded_domains: &DomainExclusionList,
) -> bool {
    enabled && *method != Method::HEAD && !domain.is_some_and(|d| excluded_domains.is_excluded(d))
}

fn is_html_rewrite_candidate<B>(response: &Response<B>) -> bool {
    let Some(content_type) = response.headers().typed_get::<ContentType>() else {
        return false;
    };
    let mime = content_type.into_mime();
    (mime.type_() == mime::TEXT && mime.subtype() == mime::HTML)
        || (mime.type_() == mime::APPLICATION && mime.subtype().as_str() == "xhtml+xml")
}

#[derive(Debug, Clone)]
pub struct HtmlBadgeDecompressionMatcher {
    enabled: bool,
    excluded_domains: DomainExclusionList,
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct HtmlBadgeResponseDecompressionMatcher;

impl<ReqBody> ServiceMatcher<Request<ReqBody>> for HtmlBadgeDecompressionMatcher
where
    ReqBody: Send + 'static,
{
    type Service = HtmlBadgeResponseDecompressionMatcher;
    type Error = Infallible;
    type ModifiedInput = Request<ReqBody>;

    async fn match_service(
        &self,
        req: Request<ReqBody>,
    ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error> {
        let req_domain = try_get_domain_for_req(&req);

        let enabled = is_request_eligible_for_html_rewrite(
            self.enabled,
            req.method(),
            req_domain.as_deref(),
            &self.excluded_domains,
        );

        Ok(ServiceMatch {
            input: req,
            service: enabled.then_some(HtmlBadgeResponseDecompressionMatcher),
        })
    }
}

impl<ResBody> ServiceMatcher<Response<ResBody>> for HtmlBadgeResponseDecompressionMatcher
where
    ResBody: Send + 'static,
{
    type Service = ();
    type Error = Infallible;
    type ModifiedInput = Response<ResBody>;

    async fn match_service(
        &self,
        input: Response<ResBody>,
    ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error> {
        Ok(ServiceMatch {
            service: is_html_rewrite_candidate(&input).then_some(()),
            input,
        })
    }
}

/// Streaming scanner that emits the badge right after the `<body…>`
/// opening tag of an HTML stream and passes everything else through.
///
/// Bounded memory: the only state held is a short carry-over while
/// scanning (at most `max(BODY_OPEN.len(), BADGE_MARKER.len()) - 1`
/// bytes) plus, once `<body` is found, the partial opening tag up to
/// `MAX_OPEN_TAG_SCAN`. Past either of those exits the scanner enters
/// `PassThrough` and forwards every subsequent chunk unchanged.
///
/// Trade-offs vs. the previous buffer-everything implementation:
/// * No `</body>` / end-of-doc fallback injection — those need the
///   full body. A response with no `<body>` opening tag now gets no
///   badge. Acceptable for the proxy-badge use case; the demo target
///   is full HTML pages.
/// * On EOF mid-scan the held-back carry / partial open-tag is flushed
///   as-is, so we never truncate output.
#[derive(Debug)]
enum BadgeScanState {
    /// Scanning input for `<body` or for an already-present
    /// `BADGE_MARKER`. `carry` holds a few bytes at the boundary of
    /// the previous chunk that might be the start of a match.
    Scanning { carry: Vec<u8> },
    /// Found `<body`; buffering until the opening tag's closing `>`.
    InOpenTag { buf: Vec<u8> },
    /// Injection done — or aborted because BADGE_MARKER was already
    /// in the body, or the open tag exceeded `MAX_OPEN_TAG_SCAN`.
    /// Subsequent chunks are emitted unchanged.
    PassThrough,
}

impl BadgeScanState {
    fn new() -> Self {
        Self::Scanning { carry: Vec::new() }
    }

    fn process(&mut self, chunk: Bytes, badge: &[u8]) -> Vec<Bytes> {
        let mut out = Vec::new();
        let mut input = chunk;
        loop {
            match self {
                Self::PassThrough => {
                    if !input.is_empty() {
                        out.push(input);
                    }
                    return out;
                }
                Self::Scanning { carry } => {
                    if input.is_empty() && carry.is_empty() {
                        return out;
                    }
                    let combined: Vec<u8> = if carry.is_empty() {
                        input.to_vec()
                    } else {
                        let mut v = std::mem::take(carry);
                        v.extend_from_slice(&input);
                        v
                    };

                    // Pre-existing badge → bail; forward and stop scanning.
                    if submatch_ignore_ascii_case(&combined, BADGE_MARKER) {
                        out.push(Bytes::from(combined));
                        *self = Self::PassThrough;
                        return out;
                    }

                    // Found `<body` → flush prefix, switch to InOpenTag.
                    if let Some(idx) = contains_ignore_ascii_case(&combined, BODY_OPEN) {
                        if idx > 0 {
                            out.push(Bytes::copy_from_slice(&combined[..idx]));
                        }
                        let buf = combined[idx..].to_vec();
                        *self = Self::InOpenTag { buf };
                        input = Bytes::new();
                        continue;
                    }

                    // No match yet — keep a tail large enough to catch a
                    // pattern straddling the next chunk boundary.
                    let max_tail = BADGE_MARKER.len().max(BODY_OPEN.len()) - 1;
                    if combined.len() <= max_tail {
                        *carry = combined;
                    } else {
                        let split = combined.len() - max_tail;
                        out.push(Bytes::copy_from_slice(&combined[..split]));
                        *carry = combined[split..].to_vec();
                    }
                    return out;
                }
                Self::InOpenTag { buf } => {
                    if !input.is_empty() {
                        buf.extend_from_slice(&input);
                    }
                    if let Some(close) = buf.iter().position(|&b| b == b'>') {
                        let insert_at = close + 1;
                        let mut output = Vec::with_capacity(buf.len() + badge.len());
                        output.extend_from_slice(&buf[..insert_at]);
                        output.extend_from_slice(badge);
                        output.extend_from_slice(&buf[insert_at..]);
                        out.push(Bytes::from(output));
                        *self = Self::PassThrough;
                        return out;
                    }
                    if buf.len() > MAX_OPEN_TAG_SCAN {
                        // Malformed / hostile: give up and flush.
                        out.push(Bytes::from(std::mem::take(buf)));
                        *self = Self::PassThrough;
                    }
                    return out;
                }
            }
        }
    }

    fn flush(&mut self) -> Option<Bytes> {
        match std::mem::replace(self, Self::PassThrough) {
            Self::Scanning { carry } if !carry.is_empty() => Some(Bytes::from(carry)),
            Self::InOpenTag { buf } if !buf.is_empty() => Some(Bytes::from(buf)),
            _ => None,
        }
    }
}

fn badge_html(label: &str) -> Vec<u8> {
    format!(
        r#"<div id="rama-proxy-badge" style="position:fixed;top:16px;right:16px;z-index:2147483647;padding:10px 14px;background:rgba(17,17,17,0.92);color:#fff;font:700 12px/1.2 ui-monospace,SFMono-Regular,Menlo,monospace;border-radius:999px;box-shadow:0 4px 18px rgba(0,0,0,0.25);pointer-events:none">{label}</div>"#,
    )
    .into_bytes()
}

fn try_get_domain_for_req<Body>(req: &Request<Body>) -> Option<Cow<'_, Domain>> {
    if let Some(ProxyTarget(target)) = req.extensions().get_ref()
        && let Ok(domain) = target.host.try_as_domain()
    {
        Some(domain)
    } else {
        RequestContext::try_from(req)
            .ok()
            .map(|ctx| ctx.host_with_port())
            .and_then(|v| v.host.try_into_domain().ok())
            .map(Cow::Owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{
        bytes::Bytes,
        futures::async_stream::stream_fn,
        http::{
            body::util::BodyExt,
            header::{CONTENT_ENCODING, ETAG},
            headers::ContentLength,
            layer::{
                compression::{predicate::Always, stream::StreamCompressionLayer},
                decompression::DecompressionLayer,
            },
        },
        service::service_fn,
    };
    use std::{convert::Infallible, time::Duration};

    fn default_badge_html() -> Vec<u8> {
        badge_html("proxied by rama")
    }

    /// Single-chunk happy path: badge lands right after the opening
    /// `<body class="…">` tag, suffix is preserved.
    #[test]
    fn scanner_injects_after_body_open_tag_single_chunk() {
        let badge = default_badge_html();
        let mut state = BadgeScanState::new();
        let out = state.process(
            Bytes::from_static(b"<html><body class=\"demo\">Hello</body></html>"),
            &badge,
        );
        let joined: Vec<u8> = out.into_iter().flatten().collect();
        let expected_prefix = b"<html><body class=\"demo\">";
        assert!(joined.starts_with(expected_prefix));
        let after_tag = &joined[expected_prefix.len()..];
        assert!(after_tag.starts_with(badge.as_slice()));
        assert!(joined.ends_with(b"Hello</body></html>"));
    }

    /// Pre-existing badge → scanner bails into PassThrough; body
    /// emerges byte-identical.
    #[test]
    fn scanner_is_idempotent_when_badge_already_present() {
        let badge = default_badge_html();
        let html = format!(
            "<html><body>{}hello</body></html>",
            String::from_utf8_lossy(&badge),
        );
        let mut state = BadgeScanState::new();
        let out = state.process(Bytes::from(html.clone().into_bytes()), &badge);
        let joined: Vec<u8> = out.into_iter().flatten().collect();
        assert_eq!(joined, html.as_bytes());
    }

    /// `<body` straddles a chunk boundary: scanner must still find it
    /// via the carry-over and inject correctly.
    #[test]
    fn scanner_handles_body_open_tag_across_chunk_boundary() {
        let badge = default_badge_html();
        let mut state = BadgeScanState::new();
        // Split mid-tag: `<bo` ends chunk 1, `dy>rest</body>` starts chunk 2.
        let mut joined = Vec::new();
        for chunk in [&b"<html><bo"[..], &b"dy>rest</body></html>"[..]] {
            for emitted in state.process(Bytes::copy_from_slice(chunk), &badge) {
                joined.extend_from_slice(&emitted);
            }
        }
        if let Some(tail) = state.flush() {
            joined.extend_from_slice(&tail);
        }
        let expected_prefix = b"<html><body>";
        assert!(joined.starts_with(expected_prefix));
        let after_tag = &joined[expected_prefix.len()..];
        assert!(after_tag.starts_with(badge.as_slice()));
        assert!(joined.ends_with(b"rest</body></html>"));
    }

    /// Opening tag with `>` arriving in a later chunk: scanner buffers
    /// `<body…` until the `>` shows up, then injects + passes through.
    #[test]
    fn scanner_handles_open_tag_closing_bracket_in_later_chunk() {
        let badge = default_badge_html();
        let mut state = BadgeScanState::new();
        let chunks: [&[u8]; 3] = [
            b"<html><body class=\"foo",
            b"\" data-x=\"y",
            b"\">tail</body>",
        ];
        let mut joined = Vec::new();
        for chunk in chunks {
            for emitted in state.process(Bytes::copy_from_slice(chunk), &badge) {
                joined.extend_from_slice(&emitted);
            }
        }
        if let Some(tail) = state.flush() {
            joined.extend_from_slice(&tail);
        }
        let expected_prefix = b"<html><body class=\"foo\" data-x=\"y\">";
        assert!(joined.starts_with(expected_prefix));
        assert!(joined[expected_prefix.len()..].starts_with(badge.as_slice()));
        assert!(joined.ends_with(b"tail</body>"));
    }

    /// HTML with no `<body>` at all: scanner forwards everything
    /// unchanged (no fallback append).
    #[test]
    fn scanner_passes_through_html_without_body_tag() {
        let badge = default_badge_html();
        let mut state = BadgeScanState::new();
        let input = b"<div>just a fragment</div>";
        let mut joined = Vec::new();
        for emitted in state.process(Bytes::from_static(input), &badge) {
            joined.extend_from_slice(&emitted);
        }
        if let Some(tail) = state.flush() {
            joined.extend_from_slice(&tail);
        }
        assert_eq!(joined.as_slice(), input);
    }

    #[tokio::test]
    async fn html_badge_layer_rewrites_plain_html_and_updates_headers() {
        let svc =
            HtmlBadgeLayer::new().into_layer(service_fn(move |_req: Request<Body>| async move {
                const CONTENT: &str = "<html><body>Hello</body></html>";
                let mut response = Response::new(Body::from(CONTENT));
                response
                    .headers_mut()
                    .typed_insert(ContentType::html_utf8());
                response
                    .headers_mut()
                    .typed_insert(ContentLength(CONTENT.len() as u64));
                response
                    .headers_mut()
                    .insert(ETAG, "\"abc\"".try_into().unwrap());
                Ok::<_, BoxError>(response)
            }));

        let response: Response<Body> = svc.serve(Request::new(Body::empty())).await.unwrap();
        // Streaming-injection path strips both Content-Length (output is
        // chunked) and ETag (body diverges from the original).
        assert!(response.headers().typed_get::<ContentLength>().is_none());
        assert!(response.headers().get(ETAG).is_none());

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let badge_html = default_badge_html();
        assert!(body.windows(badge_html.len()).any(|w| w == badge_html));
    }

    #[tokio::test]
    async fn html_badge_layer_skips_content_encoded_responses() {
        let body = Bytes::from_static(b"not really gzip, but encoded");
        let expected_body = body.clone();
        let svc = HtmlBadgeLayer::new().into_layer(service_fn(move |_req: Request<Body>| {
            let body = body.clone();
            async move {
                let mut response = Response::new(Body::from(body));
                response
                    .headers_mut()
                    .typed_insert(ContentType::html_utf8());
                response
                    .headers_mut()
                    .insert(CONTENT_ENCODING, "gzip".try_into().unwrap());
                Ok::<_, BoxError>(response)
            }
        }));

        let response: Response<Body> = svc.serve(Request::new(Body::empty())).await.unwrap();
        let body_bytes = response.into_body().collect().await.unwrap().to_bytes();

        assert_eq!(body_bytes.as_ref(), expected_body.as_ref());
    }

    #[tokio::test]
    async fn html_badge_layer_rewrites_after_decompression_and_recompresses() {
        let html = format!("<html><body>{}</body></html>", "Hello ".repeat(16));
        let svc = (
            StreamCompressionLayer::new().with_compress_predicate(Always::new()),
            HtmlBadgeLayer::new(),
            DecompressionLayer::new().with_insert_accept_encoding_header(false),
        )
            .into_layer(service_fn(move |_req: Request<Body>| {
                let html = html.clone();
                async move {
                    let mut response = Response::new(Body::from(html));
                    response
                        .headers_mut()
                        .typed_insert(ContentType::html_utf8());
                    Ok::<_, BoxError>(response)
                }
            }));

        let request = Request::builder()
            .header(rama::http::header::ACCEPT_ENCODING, "gzip")
            .body(Body::empty())
            .unwrap();
        let response = svc.serve(request).await.unwrap();

        assert_eq!(response.headers().get(CONTENT_ENCODING).unwrap(), "gzip");

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let decompressed = rama::http::layer::decompression::DecompressionLayer::new()
            .into_layer(service_fn(move |_req: Request<Body>| {
                let body = body.clone();
                async move {
                    let mut response = Response::new(Body::from(body));
                    response
                        .headers_mut()
                        .typed_insert(ContentType::html_utf8());
                    response
                        .headers_mut()
                        .insert(CONTENT_ENCODING, "gzip".try_into().unwrap());
                    Ok::<_, BoxError>(response)
                }
            }))
            .serve(Request::new(Body::empty()))
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let badge_html = default_badge_html();

        assert!(
            decompressed
                .windows(badge_html.len())
                .any(|w| w == badge_html.as_slice()),
            "output: {:?}",
            String::from_utf8_lossy(&decompressed)
        );
    }

    /// Streaming HTML responses (no `Content-Length`, chunks arriving
    /// over time) must (a) get the badge injected after the opening
    /// `<body>` tag and (b) deliver subsequent chunks to the client
    /// without buffering the whole upstream.
    ///
    /// Test shape: upstream yields three chunks separated by sleeps.
    /// We measure the elapsed time to first byte of the rewritten
    /// stream. If the layer buffered, it would wait for the upstream
    /// to finish (~60ms+ in this test); streaming should deliver the
    /// first byte essentially immediately after the first upstream
    /// chunk arrives.
    #[tokio::test]
    async fn html_badge_layer_streams_chunks_without_buffering() {
        let svc =
            HtmlBadgeLayer::new().into_layer(service_fn(move |_req: Request<Body>| async move {
                let upstream = stream_fn(async |mut y| {
                    y.yield_item(Ok::<_, Infallible>(Bytes::from_static(
                        b"<html><body>chunk-0",
                    )))
                    .await;
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    y.yield_item(Ok(Bytes::from_static(b"<p>chunk-1</p>")))
                        .await;
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    y.yield_item(Ok(Bytes::from_static(b"<p>chunk-2</p></body></html>")))
                        .await;
                });
                let mut response = Response::new(Body::from_stream(upstream));
                response
                    .headers_mut()
                    .typed_insert(ContentType::html_utf8());
                Ok::<_, BoxError>(response)
            }));

        let response: Response<Body> = svc.serve(Request::new(Body::empty())).await.unwrap();
        let start = std::time::Instant::now();
        let mut body = response.into_body();
        let first_frame = body
            .frame()
            .await
            .expect("at least one frame")
            .expect("frame ok");
        let first_at = start.elapsed();
        // First chunk should arrive well before the upstream's 80 ms
        // total. Generous bound to avoid flakes on slow CI.
        assert!(
            first_at < Duration::from_millis(30),
            "first chunk should stream without waiting for upstream EOF: \
             {first_at:?}",
        );
        // Drain the rest and verify the badge made it in.
        let mut joined = Vec::new();
        if let Ok(data) = first_frame.into_data() {
            joined.extend_from_slice(&data);
        }
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame.expect("frame ok").into_data() {
                joined.extend_from_slice(&data);
            }
        }
        let badge_html = default_badge_html();
        assert!(
            joined.windows(badge_html.len()).any(|w| w == badge_html),
            "badge must be present in joined output: {:?}",
            String::from_utf8_lossy(&joined),
        );
        assert!(joined.windows(7).any(|w| w == b"chunk-0"));
        assert!(joined.windows(7).any(|w| w == b"chunk-1"));
        assert!(joined.windows(7).any(|w| w == b"chunk-2"));
    }
}
