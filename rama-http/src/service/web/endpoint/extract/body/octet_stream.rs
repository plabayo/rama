use super::BytesRejection;
use crate::Request;
use crate::body::util::BodyExt;
use crate::service::web::extract::{FromRequest, OptionalFromRequest};
use crate::utils::macros::{composite_http_rejection, define_http_rejection};
use rama_core::bytes::Bytes;
use rama_http_types::{HeaderMap, header};
use rama_utils::macros::impl_deref;

/// Wrapper used to extract `application/octet-stream` payloads from request bodies.
///
/// The request `Content-Type` must be `application/octet-stream`, or absent —
/// per RFC 9110 §8.3 a receiver MAY treat a missing `Content-Type` as
/// `application/octet-stream`. Any other content type is rejected with
/// `415 Unsupported Media Type`. The full body is collected into [`Bytes`].
///
/// # Performance
///
/// `OctetStream` collects the entire body into a single contiguous buffer
/// before the handler runs — convenient for small uploads, but unsuitable for
/// large or streaming payloads. For those, use the [`Body`](super::Body)
/// extractor and consume frame-by-frame; cap the request body size with the
/// existing body-limit machinery to bound memory use.
///
/// For producing octet-stream responses, see
/// [`response::OctetStream`](crate::service::web::endpoint::response::OctetStream).
#[derive(Debug, Clone)]
pub struct OctetStream(pub Bytes);

impl_deref!(OctetStream: Bytes);

impl From<Bytes> for OctetStream {
    fn from(value: Bytes) -> Self {
        Self(value)
    }
}

impl From<OctetStream> for Bytes {
    fn from(value: OctetStream) -> Self {
        value.0
    }
}

define_http_rejection! {
    #[status = UNSUPPORTED_MEDIA_TYPE]
    #[body = "OctetStream requests must have `Content-Type: application/octet-stream` (or no Content-Type)"]
    /// Rejection type for [`OctetStream`]
    /// used if the `Content-Type` header is present and its value is not
    /// `application/octet-stream`.
    pub struct InvalidOctetStreamContentType;
}

composite_http_rejection! {
    /// Rejection used for [`OctetStream`]
    ///
    /// Contains one variant for each way the [`OctetStream`] extractor
    /// can fail.
    pub enum OctetStreamRejection {
        InvalidOctetStreamContentType,
        BytesRejection,
    }
}

impl FromRequest for OctetStream {
    type Rejection = OctetStreamRejection;

    async fn from_request(req: Request) -> Result<Self, Self::Rejection> {
        match content_type_match(req.headers()) {
            ContentTypeMatch::Match | ContentTypeMatch::Absent => {}
            ContentTypeMatch::Mismatch => return Err(InvalidOctetStreamContentType.into()),
        }

        match req.into_body().collect().await {
            Ok(c) => Ok(Self(c.to_bytes())),
            Err(err) => Err(BytesRejection::from_err(err).into()),
        }
    }
}

impl OptionalFromRequest for OctetStream {
    type Rejection = OctetStreamRejection;

    /// Mirrors the non-optional [`FromRequest`] acceptance policy: any
    /// indication of a body (`Content-Type`, `Content-Length > 0`, or
    /// `Transfer-Encoding`) delegates to `FromRequest`. Only when the
    /// request clearly carries no body do we return `None`.
    ///
    /// This avoids the pitfall of silently dropping a body the
    /// non-optional extractor would happily parse — important now that the
    /// non-optional path treats a missing `Content-Type` as
    /// `application/octet-stream` per RFC 9110 §8.3.
    async fn from_request(req: Request) -> Result<Option<Self>, Self::Rejection> {
        if request_has_body(req.headers()) {
            let v = <Self as FromRequest>::from_request(req).await?;
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }
}

fn request_has_body(headers: &HeaderMap) -> bool {
    if headers.get(header::CONTENT_TYPE).is_some() {
        return true;
    }
    if headers.get(header::TRANSFER_ENCODING).is_some() {
        return true;
    }
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|n| n > 0)
}

enum ContentTypeMatch {
    Match,
    Absent,
    Mismatch,
}

fn content_type_match(headers: &HeaderMap) -> ContentTypeMatch {
    let Some(value) = headers.get(header::CONTENT_TYPE) else {
        return ContentTypeMatch::Absent;
    };
    let parsed = value
        .to_str()
        .ok()
        .and_then(|s| s.parse::<crate::mime::Mime>().ok());
    match parsed {
        Some(mime)
            if mime.type_() == crate::mime::APPLICATION
                && mime.subtype() == crate::mime::OCTET_STREAM =>
        {
            ContentTypeMatch::Match
        }
        _ => ContentTypeMatch::Mismatch,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::StatusCode;
    use crate::service::web::WebService;
    use rama_core::Service;

    #[tokio::test]
    async fn test_octet_stream() {
        let service =
            WebService::default().with_post("/", async |OctetStream(body): OctetStream| {
                assert_eq!(body.as_ref(), b"\x00\x01\x02\x03");
            });

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(
                rama_http_types::header::CONTENT_TYPE,
                "application/octet-stream",
            )
            .body(vec![0u8, 1, 2, 3].into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_octet_stream_missing_content_type() {
        let service = WebService::default()
            .with_post("/", async |OctetStream(_): OctetStream| StatusCode::OK);

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_TYPE, "text/plain")
            .body(vec![0u8, 1, 2, 3].into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn test_octet_stream_optional_present() {
        let service = WebService::default().with_post("/", async |body: Option<OctetStream>| {
            let OctetStream(b) = body.expect("body present");
            assert_eq!(b.as_ref(), b"data");
        });

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(
                rama_http_types::header::CONTENT_TYPE,
                "application/octet-stream",
            )
            .body("data".into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_octet_stream_accepts_absent_content_type() {
        // Per RFC 9110 §8.3 a receiver MAY treat a missing Content-Type as
        // application/octet-stream. We do.
        let service =
            WebService::default().with_post("/", async |OctetStream(body): OctetStream| {
                assert_eq!(body.as_ref(), b"raw");
            });

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .body("raw".into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_octet_stream_optional_no_content_type_with_body() {
        // Regression: `Option<OctetStream>` previously returned `None` when
        // no Content-Type was set, even though the non-optional extractor
        // would happily parse the same request. Now the optional variant
        // mirrors the acceptance policy and treats a body indicated by
        // Content-Length as present.
        let service = WebService::default().with_post("/", async |body: Option<OctetStream>| {
            let OctetStream(b) = body.expect("body present");
            assert_eq!(b.as_ref(), b"data");
        });

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .header(rama_http_types::header::CONTENT_LENGTH, "4")
            .body("data".into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_octet_stream_optional_absent() {
        let service = WebService::default().with_post("/", async |body: Option<OctetStream>| {
            assert!(body.is_none());
            StatusCode::OK
        });

        let req = rama_http_types::Request::builder()
            .method(rama_http_types::Method::POST)
            .body(rama_http_types::Body::empty())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
