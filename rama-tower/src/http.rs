//! HTTP tower interop.
//!
//! [`TowerHttpServiceAdapter`] adapts a [`tower::Service`] that speaks the
//! hyperium `http::Request`/`http::Response` into a rama [`Service`], converting
//! the head via [`rama-http-hyperium`](rama_http_hyperium) and wrapping the bodies
//! (rama [`Body`] ↔ [`http_body::Body`]) so neither side is copied.
//!
//! [`tower::Service`]: tower_service::Service
//! [`Service`]: rama_core::Service
//! [`Body`]: rama_http_types::body::http_body::Body

use std::fmt;

use rama_core::error::BoxError;
use rama_http_hyperium::{HyperiumBody, RamaBody, TryIntoHyperiumHttp as _, TryIntoRamaHttp as _};
use rama_http_types::body::http_body::Body;
use rama_http_types::{Request, Response};

use crate::core::Service as TowerService;
use crate::service_ready::Ready;

/// Adapter to use a tower HTTP [`tower::Service`] — operating on
/// `http::Request`/`http::Response` — as a rama [`Service`].
///
/// The request head is converted to its hyperium form and the rama body wrapped
/// as an [`http_body::Body`] ([`HyperiumBody`]); the response head is converted
/// back and its body wrapped as a rama [`Body`] ([`RamaBody`]). Conversion
/// errors (head or trailers) surface as [`BoxError`].
///
/// Like [`ServiceAdapter`](crate::ServiceAdapter), this clones the inner service
/// per call and drives it to readiness before calling it.
///
/// [`tower::Service`]: tower_service::Service
/// [`Service`]: rama_core::Service
#[derive(Clone)]
pub struct TowerHttpServiceAdapter<T>(T);

impl<T: Clone + Send + Sync + 'static> TowerHttpServiceAdapter<T> {
    /// Adapt a tower HTTP service into a rama [`Service`](rama_core::Service).
    pub const fn new(svc: T) -> Self {
        Self(svc)
    }

    /// Consume itself to return the inner [`tower::Service`](tower_service::Service).
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: fmt::Debug> fmt::Debug for TowerHttpServiceAdapter<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TowerHttpServiceAdapter")
            .field(&self.0)
            .finish()
    }
}

impl<T, ReqBody, ResBody> rama_core::Service<Request<ReqBody>> for TowerHttpServiceAdapter<T>
where
    T: TowerService<
            http::Request<HyperiumBody<ReqBody>>,
            Response = http::Response<ResBody>,
            Error: std::error::Error + Send + Sync + 'static,
            Future: Send,
        > + Clone
        + Send
        + Sync
        + 'static,
    ReqBody: Body + Send + 'static,
    ResBody: http_body::Body + Send + 'static,
{
    type Output = Response<RamaBody<ResBody>>;
    type Error = BoxError;

    fn serve(
        &self,
        input: Request<ReqBody>,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        let svc = self.0.clone();
        async move {
            // rama request -> hyperium request (head converted, body wrapped)
            let (parts, body) = input.into_parts();
            let http_parts = parts.try_into_hyperium_http()?;
            let http_req = http::Request::from_parts(http_parts, HyperiumBody::new(body));

            // drive the tower service to readiness, then call it
            let mut svc = svc;
            let ready_svc = Ready::new(&mut svc).await?;
            let http_res = ready_svc.call(http_req).await?;

            // hyperium response -> rama response (head converted, body wrapped)
            let (res_parts, res_body) = http_res.into_parts();
            let rama_parts = res_parts.try_into_rama_http()?;
            Ok(Response::from_parts(rama_parts, RamaBody::new(res_body)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::Service as _;
    use rama_core::bytes::Bytes;
    use std::convert::Infallible;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// Minimal external `http_body::Body` yielding one data frame.
    struct OnceBody(Option<Bytes>);

    impl http_body::Body for OnceBody {
        type Data = Bytes;
        type Error = Infallible;
        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Bytes>, Infallible>>> {
            Poll::Ready(
                self.get_mut()
                    .0
                    .take()
                    .map(|b| Ok(http_body::Frame::data(b))),
            )
        }
    }

    /// Trivial tower http service: echoes a fixed 201 response.
    #[derive(Clone)]
    struct StatusEcho;

    impl<B> TowerService<http::Request<B>> for StatusEcho {
        type Response = http::Response<OnceBody>;
        type Error = Infallible;
        type Future = std::future::Ready<Result<Self::Response, Infallible>>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, _req: http::Request<B>) -> Self::Future {
            let res = http::Response::builder()
                .status(201)
                .body(OnceBody(Some(Bytes::from_static(b"pong"))))
                .unwrap();
            std::future::ready(Ok(res))
        }
    }

    #[tokio::test]
    async fn adapts_a_tower_http_service() {
        let adapter = TowerHttpServiceAdapter::new(StatusEcho);
        let req = Request::builder()
            .uri("http://example.com/")
            .body("ping".to_owned())
            .unwrap();
        let res = adapter.serve(req).await.unwrap();
        assert_eq!(res.status().as_u16(), 201);
    }
}
