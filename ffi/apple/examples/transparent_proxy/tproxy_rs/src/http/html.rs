use rama::{
    Layer, Service,
    bytes::Bytes,
    error::{BoxError, ErrorContext as _},
    http::{
        Body, Method, Request, Response,
        body::util::BodyExt,
        header::CONTENT_ENCODING,
        headers::{ContentLength, ContentType, HeaderMapExt},
        layer::remove_header::{
            remove_cache_validation_response_headers, remove_payload_metadata_headers,
        },
        mime,
    },
    net::http::RequestContext,
    telemetry::tracing,
    utils::str::{contains_ignore_ascii_case, submatch_ignore_ascii_case},
};

use crate::policy::DomainExclusionList;

const BADGE_MARKER: &[u8] = b"id=\"rama-proxy-badge\"";
const BODY_OPEN: &[u8] = b"<body";
const BODY_CLOSE: &[u8] = b"</body>";
const MAX_CONTENT_LENGTH_BYTES: usize = 1024 * 1024;

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
    ResBody: rama::http::StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Output = Response<Body>;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let req_method = req.method().clone();
        let req_domain = RequestContext::try_from(&req)
            .ok()
            .and_then(|rc| rc.authority.host.into_domain());
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
        let html = body
            .collect()
            .await
            .context("collect HTML response body for badge injection")?
            .to_bytes();

        let updated_html = inject_badge(html.as_ref(), &self.badge_html);

        if updated_html.is_none() {
            return Ok(Response::from_parts(parts, Body::from(html)));
        }

        let updated_html = updated_html.expect("updated_html is_some above");
        remove_payload_metadata_headers(&mut parts.headers);
        remove_cache_validation_response_headers(&mut parts.headers);
        let updated_html_len = u64::try_from(updated_html.len())
            .context("convert updated HTML response length to u64")?;
        parts.headers.typed_insert(ContentLength(updated_html_len));

        Ok(Response::from_parts(parts, Body::from(updated_html)))
    }
}

fn should_rewrite<B>(response: &Response<B>) -> bool {
    let headers = response.headers();

    if headers.contains_key(CONTENT_ENCODING) {
        return false;
    }

    let Some(content_type) = headers.typed_get::<ContentType>() else {
        return false;
    };

    let mime = content_type.into_mime();
    let is_html = (mime.type_() == mime::TEXT && mime.subtype() == mime::HTML)
        || (mime.type_() == mime::APPLICATION && mime.subtype().as_str() == "xhtml+xml");
    if !is_html {
        return false;
    }

    let Some(content_length) = headers.typed_get::<ContentLength>() else {
        return true;
    };

    content_length.0 <= MAX_CONTENT_LENGTH_BYTES as u64
}

fn inject_badge(html: &[u8], badge_html: &[u8]) -> Option<Vec<u8>> {
    if submatch_ignore_ascii_case(html, BADGE_MARKER) {
        return None;
    }

    if let Some(body_start) = contains_ignore_ascii_case(html, BODY_OPEN)
        && let Some(body_end) = html[body_start..].iter().position(|byte| *byte == b'>')
    {
        let insert_at = body_start + body_end + 1;
        return Some(insert_bytes(html, insert_at, badge_html));
    }

    if let Some(body_end) = contains_ignore_ascii_case(html, BODY_CLOSE) {
        return Some(insert_bytes(html, body_end, badge_html));
    }

    Some(insert_bytes(html, html.len(), badge_html))
}

fn insert_bytes(html: &[u8], index: usize, insertion: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(html.len() + insertion.len());
    output.extend_from_slice(&html[..index]);
    output.extend_from_slice(insertion);
    output.extend_from_slice(&html[index..]);
    output
}

fn badge_html(label: &str) -> Vec<u8> {
    format!(
        r#"<div id="rama-proxy-badge" style="position:fixed;top:16px;right:16px;z-index:2147483647;padding:10px 14px;background:rgba(17,17,17,0.92);color:#fff;font:700 12px/1.2 ui-monospace,SFMono-Regular,Menlo,monospace;border-radius:999px;box-shadow:0 4px 18px rgba(0,0,0,0.25);pointer-events:none">{label}</div>"#,
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{
        http::{
            header::{CONTENT_ENCODING, ETAG},
            layer::{
                compression::{predicate::Always, stream::StreamCompressionLayer},
                decompression::DecompressionLayer,
            },
        },
        service::service_fn,
    };

    fn default_badge_html() -> Vec<u8> {
        badge_html("proxied by rama")
    }

    #[test]
    fn inject_badge_after_body_open_tag() {
        let html = b"<html><body class=\"demo\">\xffHello</body></html>";
        let badge_html = default_badge_html();
        let updated = inject_badge(html, &badge_html).expect("badge should be injected");

        assert!(updated.starts_with(b"<html><body class=\"demo\">"));
        assert!(updated.ends_with(b"\xffHello</body></html>"));
        assert!(updated.windows(badge_html.len()).any(|w| w == badge_html));
    }

    #[test]
    fn inject_badge_is_idempotent() {
        let html = format!(
            "<html><body>{}hello</body></html>",
            String::from_utf8_lossy(&default_badge_html())
        );

        assert!(inject_badge(html.as_bytes(), &default_badge_html()).is_none());
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
        let content_length = response
            .headers()
            .typed_get::<ContentLength>()
            .expect("content-length should be set");
        assert!(response.headers().get(ETAG).is_none());

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let badge_html = default_badge_html();
        assert!(body.windows(badge_html.len()).any(|w| w == badge_html));
        assert_eq!(content_length.0, body.len() as u64);
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
            DecompressionLayer::new(),
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
}
