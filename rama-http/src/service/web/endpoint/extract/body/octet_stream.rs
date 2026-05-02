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
/// The request `Content-Type` must be `application/octet-stream`. The full body is
/// collected into [`Bytes`].
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
    #[body = "OctetStream requests must have `Content-Type: application/octet-stream`"]
    /// Rejection type for [`OctetStream`]
    /// used if the `Content-Type` header is missing
    /// or its value is not `application/octet-stream`.
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
        if !octet_stream_content_type(req.headers()) {
            return Err(InvalidOctetStreamContentType.into());
        }

        match req.into_body().collect().await {
            Ok(c) => Ok(Self(c.to_bytes())),
            Err(err) => Err(BytesRejection::from_err(err).into()),
        }
    }
}

impl OptionalFromRequest for OctetStream {
    type Rejection = OctetStreamRejection;

    async fn from_request(req: Request) -> Result<Option<Self>, Self::Rejection> {
        if req.headers().get(header::CONTENT_TYPE).is_some() {
            let v = <Self as FromRequest>::from_request(req).await?;
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }
}

fn octet_stream_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|content_type| content_type.to_str().ok())
        .and_then(|content_type| content_type.parse::<crate::mime::Mime>().ok())
        .is_some_and(|mime| {
            mime.type_() == crate::mime::APPLICATION && mime.subtype() == crate::mime::OCTET_STREAM
        })
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
