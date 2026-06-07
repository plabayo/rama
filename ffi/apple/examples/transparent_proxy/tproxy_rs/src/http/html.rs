use rama::{
    Layer, Service,
    bytes::Bytes,
    error::BoxError,
    extensions::ExtensionsRef as _,
    http::{
        Body, Method, Request, Response, StreamingBody,
        header::CONTENT_ENCODING,
        headers::{ContentType, HeaderMapExt},
        layer::{
            html_rewrite::HtmlRewriteLayer,
            remove_header::{
                remove_cache_validation_response_headers, remove_payload_metadata_headers,
            },
        },
        protocols::html::{
            IntoHtml, div,
            rewrite::{Element, ElementContentHandler, HandlerResult},
            selector::Selector,
        },
    },
    matcher::service::{ServiceMatch, ServiceMatcher},
    net::{address::Domain, http::RequestContext, proxy::ProxyTarget},
    telemetry::tracing,
};
use std::{borrow::Cow, convert::Infallible};

use crate::policy::DomainExclusionList;

const BADGE_ID: &str = "rama-proxy-badge";
const BADGE_STYLE: &str = concat!(
    "position:fixed;",
    "top:16px;",
    "right:16px;",
    "z-index:2147483647;",
    "padding:10px 14px;",
    "background:rgba(17,17,17,0.92);",
    "color:#fff;",
    "font:700 12px/1.2 ui-monospace,SFMono-Regular,Menlo,monospace;",
    "border-radius:999px;",
    "box-shadow:0 4px 18px rgba(0,0,0,0.25);",
    "pointer-events:none",
);

#[derive(Debug, Clone)]
pub struct HtmlBadgeLayer {
    enabled: bool,
    excluded_domains: DomainExclusionList,
    rewrite: HtmlRewriteLayer<BadgeHandler>,
}

impl HtmlBadgeLayer {
    #[inline(always)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            enabled: true,
            excluded_domains: DomainExclusionList::default(),
            rewrite: badge_rewrite_layer("proxied by rama"),
        }
    }

    rama::utils::macros::generate_set_and_with! {
        pub fn badge_label(mut self, badge_label: impl AsRef<str>) -> Self {
            self.rewrite = badge_rewrite_layer(badge_label.as_ref());
            self
        }
    }

    rama::utils::macros::generate_set_and_with! {
        pub fn enabled(mut self, enabled: bool) -> Self {
            self.enabled = enabled;
            self
        }
    }

    rama::utils::macros::generate_set_and_with! {
        pub fn excluded_domains(mut self, excluded_domains: DomainExclusionList) -> Self {
            self.excluded_domains = excluded_domains;
            self
        }
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
            excluded_domains,
            rewrite,
        } = self;

        HtmlBadgeService {
            inner,
            enabled: *enabled,
            excluded_domains: excluded_domains.clone(),
            rewrite: rewrite.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        let Self {
            enabled,
            excluded_domains,
            rewrite,
        } = self;

        HtmlBadgeService {
            inner,
            enabled,
            excluded_domains,
            rewrite,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HtmlBadgeService<S> {
    inner: S,
    enabled: bool,
    excluded_domains: DomainExclusionList,
    rewrite: HtmlRewriteLayer<BadgeHandler>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for HtmlBadgeService<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error = BoxError>,
    ReqBody: Send + 'static,
    ResBody: StreamingBody<Data = Bytes, Error: Into<BoxError> + Send> + Send + Sync + 'static,
{
    type Output = Response<Body>;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let req_method = req.method().clone();
        let req_domain = try_get_domain_for_req(&req).map(Cow::into_owned);
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
        let new_body = self.rewrite.rewrite_body(body);
        let new_body = Body::new(new_body);
        Ok(Response::from_parts(parts, new_body))
    }
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
    content_type.into_mime().essence_str() == "text/html"
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

#[derive(Debug, Clone)]
struct BadgeHandler {
    label: String,
}

impl ElementContentHandler for BadgeHandler {
    fn handle_element(&mut self, _selector: usize, element: &mut Element<'_>) -> HandlerResult {
        element.prepend(ProxyBadge {
            label: self.label.clone(),
        });
        Ok(())
    }
}

struct ProxyBadge {
    label: String,
}

impl IntoHtml for ProxyBadge {
    fn into_html(self) -> impl IntoHtml {
        div!(id = BADGE_ID, style = BADGE_STYLE, self.label)
    }

    fn size_hint(&self) -> usize {
        BADGE_STYLE.len() + BADGE_ID.len() + self.label.len() + 32
    }
}

fn badge_rewrite_layer(label: &str) -> HtmlRewriteLayer<BadgeHandler> {
    HtmlRewriteLayer::new(
        [Selector::tag("body")],
        BadgeHandler {
            label: label.to_owned(),
        },
    )
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

    fn badge_html(label: &str) -> Vec<u8> {
        ProxyBadge {
            label: label.to_owned(),
        }
        .into_string()
        .into_bytes()
    }

    fn default_badge_html() -> Vec<u8> {
        badge_html("proxied by rama")
    }

    #[tokio::test]
    async fn html_badge_layer_injects_after_body_open_tag_single_chunk() {
        let svc =
            HtmlBadgeLayer::new().into_layer(service_fn(move |_req: Request<Body>| async move {
                let mut response =
                    Response::new(Body::from("<html><body class=\"demo\">Hello</body></html>"));
                response
                    .headers_mut()
                    .typed_insert(ContentType::html_utf8());
                Ok::<_, BoxError>(response)
            }));

        let response: Response<Body> = svc.serve(Request::new(Body::empty())).await.unwrap();
        let joined = response.into_body().collect().await.unwrap().to_bytes();
        let badge = default_badge_html();
        let expected_prefix = b"<html><body class=\"demo\">";
        assert!(joined.starts_with(expected_prefix));
        let after_tag = &joined[expected_prefix.len()..];
        assert!(after_tag.starts_with(badge.as_slice()));
        assert!(joined.ends_with(b"Hello</body></html>"));
    }

    #[tokio::test]
    async fn html_badge_layer_handles_body_open_tag_across_chunk_boundary() {
        let svc =
            HtmlBadgeLayer::new().into_layer(service_fn(move |_req: Request<Body>| async move {
                let upstream = stream_fn(async |mut y| {
                    y.yield_item(Ok::<_, Infallible>(Bytes::from_static(b"<html><bo")))
                        .await;
                    y.yield_item(Ok(Bytes::from_static(b"dy>rest</body></html>")))
                        .await;
                });
                let mut response = Response::new(Body::from_stream(upstream));
                response
                    .headers_mut()
                    .typed_insert(ContentType::html_utf8());
                Ok::<_, BoxError>(response)
            }));

        let response: Response<Body> = svc.serve(Request::new(Body::empty())).await.unwrap();
        let joined = response.into_body().collect().await.unwrap().to_bytes();
        let badge = default_badge_html();
        let expected_prefix = b"<html><body>";
        assert!(joined.starts_with(expected_prefix));
        let after_tag = &joined[expected_prefix.len()..];
        assert!(after_tag.starts_with(badge.as_slice()));
        assert!(joined.ends_with(b"rest</body></html>"));
    }

    #[tokio::test]
    async fn html_badge_layer_handles_open_tag_closing_bracket_in_later_chunk() {
        let svc =
            HtmlBadgeLayer::new().into_layer(service_fn(move |_req: Request<Body>| async move {
                let upstream = stream_fn(async |mut y| {
                    y.yield_item(Ok::<_, Infallible>(Bytes::from_static(
                        b"<html><body class=\"foo",
                    )))
                    .await;
                    y.yield_item(Ok(Bytes::from_static(b"\" data-x=\"y")))
                        .await;
                    y.yield_item(Ok(Bytes::from_static(b"\">tail</body>")))
                        .await;
                });
                let mut response = Response::new(Body::from_stream(upstream));
                response
                    .headers_mut()
                    .typed_insert(ContentType::html_utf8());
                Ok::<_, BoxError>(response)
            }));

        let response: Response<Body> = svc.serve(Request::new(Body::empty())).await.unwrap();
        let joined = response.into_body().collect().await.unwrap().to_bytes();
        let badge = default_badge_html();
        let expected_prefix = b"<html><body class=\"foo\" data-x=\"y\">";
        assert!(joined.starts_with(expected_prefix));
        assert!(joined[expected_prefix.len()..].starts_with(badge.as_slice()));
        assert!(joined.ends_with(b"tail</body>"));
    }

    #[tokio::test]
    async fn html_badge_layer_passes_through_html_without_body_tag() {
        let svc =
            HtmlBadgeLayer::new().into_layer(service_fn(move |_req: Request<Body>| async move {
                let mut response = Response::new(Body::from("<div>just a fragment</div>"));
                response
                    .headers_mut()
                    .typed_insert(ContentType::html_utf8());
                Ok::<_, BoxError>(response)
            }));

        let response: Response<Body> = svc.serve(Request::new(Body::empty())).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"<div>just a fragment</div>");
    }

    #[tokio::test]
    async fn html_badge_layer_skips_excluded_domains() {
        let svc = HtmlBadgeLayer::new()
            .with_excluded_domains(DomainExclusionList::new(["example.com"]))
            .into_layer(service_fn(move |_req: Request<Body>| async move {
                let mut response = Response::new(Body::from("<html><body>Hello</body></html>"));
                response
                    .headers_mut()
                    .typed_insert(ContentType::html_utf8());
                Ok::<_, BoxError>(response)
            }));

        let request = Request::builder()
            .uri("https://example.com/")
            .body(Body::empty())
            .unwrap();
        let response: Response<Body> = svc.serve(request).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"<html><body>Hello</body></html>");
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
        if first_frame.is_data() {
            let data: Bytes = first_frame.into_data().expect("data");
            joined.extend_from_slice(data.as_ref());
        }
        while let Some(frame) = body.frame().await {
            let frame = frame.expect("frame ok");
            if frame.is_data() {
                let data: Bytes = frame.into_data().expect("data");
                joined.extend_from_slice(data.as_ref());
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
