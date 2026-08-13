use crate::Request;
use crate::body::util::BodyExt;
use crate::service::web::extract::{FromRequest, FromRequestBody};
use crate::utils::macros::define_http_rejection;
use rama_utils::macros::impl_deref;

/// Extractor to get the response body, collected as [`Bytes`].
///
/// [`Bytes`]: https://docs.rs/bytes/latest/bytes/struct.Bytes.html
#[derive(Debug, Clone)]
pub struct Bytes(pub rama_core::bytes::Bytes);

impl_deref!(Bytes: rama_core::bytes::Bytes);

define_http_rejection! {
    #[status = BAD_REQUEST]
    #[body = "Request Body failed to be collected as Bytes"]
    /// Rejection type used when the [`Bytes`] extractor fails to collect the request body.
    pub struct BytesRejection(Error);
}

impl FromRequest for Bytes {
    type Rejection = BytesRejection;

    async fn from_request(req: Request) -> Result<Self, Self::Rejection> {
        let (parts, body) = req.into_parts();
        let future = Self::from_request_body(&parts, body);
        future.await
    }
}

impl FromRequestBody for Bytes {
    fn from_request_body(
        _parts: &crate::request::Parts,
        body: crate::Body,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send + 'static {
        collect_body(body)
    }
}

async fn collect_body(body: crate::Body) -> Result<Bytes, BytesRejection> {
    body.collect()
        .await
        .map_err(BytesRejection::from_err)
        .map(|body| Bytes(body.to_bytes()))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::service::web::WebService;
    use crate::{Method, Request, StatusCode};
    use rama_core::{Service, extensions::Extension};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    #[tokio::test]
    async fn test_bytes() {
        let service = WebService::default().with_get("/", async |Bytes(body): Bytes| {
            assert_eq!(body, "test");
        });

        let req = Request::builder()
            .method(Method::GET)
            .body("test".into())
            .unwrap();
        let resp = service.serve(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn terminal_extractor_keeps_request_parts_alive_while_reading_body() {
        #[derive(Debug)]
        struct PartsGuard(Arc<AtomicBool>);

        impl Extension for PartsGuard {}

        impl Drop for PartsGuard {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }

        let parts_are_alive = Arc::new(AtomicBool::new(true));
        let body_observer = Arc::clone(&parts_are_alive);
        let body = crate::Body::from_stream(rama_core::futures::stream::once(async move {
            assert!(body_observer.load(Ordering::SeqCst));
            Ok::<_, std::convert::Infallible>(rama_core::bytes::Bytes::from_static(b"payload"))
        }));
        let request = Request::builder()
            .extension(PartsGuard(Arc::clone(&parts_are_alive)))
            .body(body)
            .unwrap();

        let Bytes(body) = Bytes::from_request(request).await.unwrap();

        assert_eq!(body, "payload");
        assert!(!parts_are_alive.load(Ordering::SeqCst));
    }
}
