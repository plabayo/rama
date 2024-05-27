// //! Middleware to get [`SocketInfo`] from a header such as `x-forwarded-for`.

// use crate::http::{Request, Response, StatusCode};
// use crate::service::{Context, Layer, Service};
// use crate::stream::SocketInfo;

// /// Layer that extracts [`SocketInfo`] from a header.
// #[derive(Debug, Clone)]
// pub struct HeaderIpsLayer {
//     header: HeaderName,
//     required: bool,
// }

// impl HeaderIpsLayer {
//     /// Create a new [`HeaderIpsLayer`] using the `x-forwarded-for` header.
//     pub fn x_forwarded_for() -> Self {
//         Self {
//             header: HeaderName::from_static("x-forwarded-for"),
//             required: false,
//         }
//     }
// }

// impl<S> Layer<S> for SetStatusLayer {
//     type Service = SetStatus<S>;

//     fn layer(&self, inner: S) -> Self::Service {
//         SetStatus::new(inner, self.status)
//     }
// }

// /// Middleware to override status codes.
// ///
// /// See the [module docs](self) for more details.
// #[derive(Debug, Clone, Copy)]
// pub struct SetStatus<S> {
//     inner: S,
//     status: StatusCode,
// }

// impl<S> SetStatus<S> {
//     /// Create a new [`SetStatus`].
//     ///
//     /// The response status code will be `status` regardless of what the inner service returns.
//     pub fn new(inner: S, status: StatusCode) -> Self {
//         Self { status, inner }
//     }

//     define_inner_service_accessors!();

//     /// Returns a new [`Layer`] that wraps services with a `SetStatus` middleware.
//     ///
//     /// [`Layer`]: crate::service::Layer
//     pub fn layer(status: StatusCode) -> SetStatusLayer {
//         SetStatusLayer::new(status)
//     }
// }

// impl<State, S, ReqBody, ResBody> Service<State, Request<ReqBody>> for SetStatus<S>
// where
//     State: Send + Sync + 'static,
//     S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
//     ReqBody: Send + 'static,
//     ResBody: Send + 'static,
// {
//     type Response = S::Response;
//     type Error = S::Error;

//     async fn serve(
//         &self,
//         ctx: Context<State>,
//         req: Request<ReqBody>,
//     ) -> Result<Self::Response, Self::Error> {
//         let mut response = self.inner.serve(ctx, req).await?;
//         *response.status_mut() = self.status;
//         Ok(response)
//     }
// }
