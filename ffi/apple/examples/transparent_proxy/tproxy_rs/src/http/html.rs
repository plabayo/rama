use rama::{
    Layer, Service,
    bytes::Bytes,
    error::{BoxError, ErrorContext as _},
    http::{
        Body, Request, Response,
        body::util::BodyExt,
        header::CONTENT_ENCODING,
        headers::{ContentLength, ContentType, HeaderMapExt},
        layer::remove_header::remove_payload_metadata_headers,
        mime,
    },
    utils::str::{contains_ignore_ascii_case, submatch_ignore_ascii_case},
};

const BADGE_HTML: &str = r#"<div id="rama-proxy-badge" style="position:fixed;top:16px;right:16px;z-index:2147483647;padding:10px 14px;background:rgba(17,17,17,0.92);color:#fff;font:700 12px/1.2 ui-monospace,SFMono-Regular,Menlo,monospace;border-radius:999px;box-shadow:0 4px 18px rgba(0,0,0,0.25);pointer-events:none">proxied by rama</div>"#;
const BADGE_HTML_BYTES: &[u8] = BADGE_HTML.as_bytes();
const BADGE_MARKER: &[u8] = b"id=\"rama-proxy-badge\"";
const BODY_OPEN: &[u8] = b"<body";
const BODY_CLOSE: &[u8] = b"</body>";
const MAX_CONTENT_LENGTH_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct HtmlBadgeLayer;

impl<S> Layer<S> for HtmlBadgeLayer {
    type Service = HtmlBadgeService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        HtmlBadgeService { inner }
    }
}

#[derive(Debug, Clone)]
pub struct HtmlBadgeService<S> {
    inner: S,
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
        let is_head_request = req.method() == rama::http::Method::HEAD;
        let response = self.inner.serve(req).await?;

        if is_head_request || !should_rewrite(&response) {
            return Ok(response.map(Body::new));
        }

        let (mut parts, body) = response.into_parts();
        let html = body
            .collect()
            .await
            .context("collect HTML response body for badge injection")?
            .to_bytes();

        let updated_html = inject_badge(html.as_ref());

        if updated_html.is_none() {
            return Ok(Response::from_parts(parts, Body::from(html)));
        }

        let updated_html = updated_html.expect("updated_html is_some above");
        remove_payload_metadata_headers(&mut parts.headers);
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

fn inject_badge(html: &[u8]) -> Option<Vec<u8>> {
    if submatch_ignore_ascii_case(html, BADGE_MARKER) {
        return None;
    }

    if let Some(body_start) = contains_ignore_ascii_case(html, BODY_OPEN)
        && let Some(body_end) = html[body_start..].iter().position(|byte| *byte == b'>')
    {
        let insert_at = body_start + body_end + 1;
        return Some(insert_bytes(html, insert_at, BADGE_HTML_BYTES));
    }

    if let Some(body_end) = contains_ignore_ascii_case(html, BODY_CLOSE) {
        return Some(insert_bytes(html, body_end, BADGE_HTML_BYTES));
    }

    Some(insert_bytes(html, html.len(), BADGE_HTML_BYTES))
}

fn insert_bytes(html: &[u8], index: usize, insertion: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(html.len() + insertion.len());
    output.extend_from_slice(&html[..index]);
    output.extend_from_slice(insertion);
    output.extend_from_slice(&html[index..]);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::{
        http::header::{CONTENT_ENCODING, ETAG},
        http::layer::{
            compression::stream::StreamCompressionLayer, decompression::DecompressionLayer,
        },
        service::service_fn,
    };

    #[test]
    fn inject_badge_after_body_open_tag() {
        let html = b"<html><body class=\"demo\">\xffHello</body></html>";
        let updated = inject_badge(html).expect("badge should be injected");

        assert!(updated.starts_with(b"<html><body class=\"demo\">"));
        assert!(updated.ends_with(b"\xffHello</body></html>"));
        assert!(
            updated
                .windows(BADGE_HTML_BYTES.len())
                .any(|w| w == BADGE_HTML_BYTES)
        );
    }

    #[test]
    fn inject_badge_is_idempotent() {
        let html = format!("<html><body>{BADGE_HTML}hello</body></html>");

        assert!(inject_badge(html.as_bytes()).is_none());
    }

    #[tokio::test]
    async fn html_badge_layer_rewrites_plain_html_and_updates_headers() {
        let svc = HtmlBadgeLayer.into_layer(service_fn(move |_req: Request<Body>| async move {
            let mut response = Response::new(Body::from("<html><body>Hello</body></html>"));
            response
                .headers_mut()
                .typed_insert(ContentType::html_utf8());
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
        assert!(
            body.windows(BADGE_HTML_BYTES.len())
                .any(|w| w == BADGE_HTML_BYTES)
        );
        assert_eq!(content_length.0, body.len() as u64);
    }

    #[tokio::test]
    async fn html_badge_layer_skips_content_encoded_responses() {
        let body = Bytes::from_static(b"not really gzip, but encoded");
        let expected_body = body.clone();
        let svc = HtmlBadgeLayer.into_layer(service_fn(move |_req: Request<Body>| {
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
            HtmlBadgeLayer,
            DecompressionLayer::new(),
            StreamCompressionLayer::new(),
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
        let response: Response<Body> = svc.serve(request).await.unwrap();

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

        assert!(
            decompressed
                .windows(BADGE_HTML_BYTES.len())
                .any(|w| w == BADGE_HTML_BYTES)
        );
    }
}
