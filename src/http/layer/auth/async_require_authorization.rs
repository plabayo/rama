//! Authorize requests using the [`Authorization`] header asynchronously.
//!
//! [`Authorization`]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
//!
//! # Example
//!
//! ```
//! use bytes::Bytes;
//!
//! use rama::http::layer::auth::{AsyncRequireAuthorizationLayer, AsyncAuthorizeRequest};
//! use rama::http::{Body, Request, Response, StatusCode, header::AUTHORIZATION};
//! use rama::service::{Context, Service, ServiceBuilder, service_fn};
//! use rama::error::BoxError;
//!
//! #[derive(Clone, Copy)]
//! struct MyAuth;
//!
//! impl<S, B> AsyncAuthorizeRequest<S, B> for MyAuth
//! where
//!     S: Send + Sync + 'static,
//!     B: Send + Sync + 'static,
//! {
//!     type RequestBody = B;
//!     type ResponseBody = Body;
//!
//!     async fn authorize(&self, mut ctx: Context<S>, request: Request<B>) -> Result<(Context<S>, Request<B>), Response<Self::ResponseBody>> {
//!         if let Some(user_id) = check_auth(&request).await {
//!             // Set `user_id` as a request extension so it can be accessed by other
//!             // services down the stack.
//!             ctx.insert(user_id);
//!
//!             Ok((ctx, request))
//!         } else {
//!             let unauthorized_response = Response::builder()
//!                 .status(StatusCode::UNAUTHORIZED)
//!                 .body(Body::default())
//!                 .unwrap();
//!
//!             Err(unauthorized_response)
//!         }
//!     }
//! }
//!
//! async fn check_auth<B>(request: &Request<B>) -> Option<UserId> {
//!     // ...
//!     # None
//! }
//!
//! #[derive(Clone, Debug)]
//! struct UserId(String);
//!
//! async fn handle<S>(ctx: Context<S>, _request: Request) -> Result<Response, BoxError> {
//!     // Access the `UserId` that was set in `on_authorized`. If `handle` gets called the
//!     // request was authorized and `UserId` will be present.
//!     let user_id = ctx
//!         .get::<UserId>()
//!         .expect("UserId will be there if request was authorized");
//!
//!     println!("request from {:?}", user_id);
//!
//!     Ok(Response::new(Body::default()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! let service = ServiceBuilder::new()
//!     // Authorize requests using `MyAuth`
//!     .layer(AsyncRequireAuthorizationLayer::new(MyAuth))
//!     .service_fn(handle::<()>);
//! # Ok(())
//! # }
//! ```
//!
//! Or using a closure:
//!
//! ```
//! use bytes::Bytes;
//!
//! use rama::http::layer::auth::{AsyncRequireAuthorizationLayer, AsyncAuthorizeRequest};
//! use rama::http::{Body, Request, Response, StatusCode};
//! use rama::service::{Service, ServiceBuilder};
//! use rama::error::BoxError;
//!
//! async fn check_auth<B>(request: &Request<B>) -> Option<UserId> {
//!     // ...
//!     # None
//! }
//!
//! #[derive(Debug)]
//! struct UserId(String);
//!
//! async fn handle(request: Request) -> Result<Response, BoxError> {
//!     # todo!();
//!     // ...
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! let service = ServiceBuilder::new()
//!     .layer(AsyncRequireAuthorizationLayer::new(|request: Request| async move {
//!         if let Some(user_id) = check_auth(&request).await {
//!             Ok(request)
//!         } else {
//!             let unauthorized_response = Response::builder()
//!                 .status(StatusCode::UNAUTHORIZED)
//!                 .body(Body::default())
//!                 .unwrap();
//!
//!             Err(unauthorized_response)
//!         }
//!     }))
//!     .service_fn(handle);
//! # Ok(())
//! # }
//! ```

use std::future::Future;

use crate::http::{Request, Response};
use crate::service::{Context, Layer, Service};

/// Layer that applies [`AsyncRequireAuthorization`] which authorizes all requests using the
/// [`Authorization`] header.
///
/// See the [module docs](crate::http::layer::auth::async_require_authorization) for an example.
///
/// [`Authorization`]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
#[derive(Debug, Clone)]
pub struct AsyncRequireAuthorizationLayer<T> {
    auth: T,
}

impl<T> AsyncRequireAuthorizationLayer<T> {
    /// Authorize requests using a custom scheme.
    pub fn new(auth: T) -> AsyncRequireAuthorizationLayer<T> {
        Self { auth }
    }
}

impl<S, T> Layer<S> for AsyncRequireAuthorizationLayer<T>
where
    T: Clone,
{
    type Service = AsyncRequireAuthorization<S, T>;

    fn layer(&self, inner: S) -> Self::Service {
        AsyncRequireAuthorization::new(inner, self.auth.clone())
    }
}

/// Middleware that authorizes all requests using the [`Authorization`] header.
///
/// See the [module docs](crate::http::layer::auth::async_require_authorization) for an example.
///
/// [`Authorization`]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
#[derive(Clone, Debug)]
pub struct AsyncRequireAuthorization<S, T> {
    inner: S,
    auth: T,
}

impl<S, T> AsyncRequireAuthorization<S, T> {
    /// Authorize requests using a custom scheme.
    ///
    /// The `Authorization` header is required to have the value provided.
    pub fn new(inner: S, auth: T) -> AsyncRequireAuthorization<S, T> {
        Self { inner, auth }
    }

    define_inner_service_accessors!();
}

impl<ReqBody, ResBody, S, State, Auth> Service<State, Request<ReqBody>>
    for AsyncRequireAuthorization<S, Auth>
where
    Auth: AsyncAuthorizeRequest<State, ReqBody, ResponseBody = ResBody> + Send + Sync + 'static,
    S: Service<State, Request<Auth::RequestBody>, Response = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    State: Send + Sync + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let (ctx, req) = match self.auth.authorize(ctx, req).await {
            Ok(req) => req,
            Err(res) => return Ok(res),
        };
        self.inner.serve(ctx, req).await
    }
}

/// Trait for authorizing requests.
pub trait AsyncAuthorizeRequest<S, B> {
    /// The type of request body returned by `authorize`.
    ///
    /// Set this to `B` unless you need to change the request body type.
    type RequestBody;

    /// The body type used for responses to unauthorized requests.
    type ResponseBody;

    /// Authorize the request.
    ///
    /// If the future resolves to `Ok(request)` then the request is allowed through, otherwise not.
    fn authorize(
        &self,
        ctx: Context<S>,
        request: Request<B>,
    ) -> impl std::future::Future<
        Output = Result<(Context<S>, Request<Self::RequestBody>), Response<Self::ResponseBody>>,
    > + Send
           + '_;
}

impl<S, B, F, Fut, ReqBody, ResBody> AsyncAuthorizeRequest<S, B> for F
where
    F: Fn(Context<S>, Request<B>) -> Fut + Send + Sync + 'static,
    Fut:
        Future<Output = Result<(Context<S>, Request<ReqBody>), Response<ResBody>>> + Send + 'static,
    B: Send + 'static,
    S: Send + Sync + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type RequestBody = ReqBody;
    type ResponseBody = ResBody;

    async fn authorize(
        &self,
        ctx: Context<S>,
        request: Request<B>,
    ) -> Result<(Context<S>, Request<Self::RequestBody>), Response<Self::ResponseBody>> {
        self(ctx, request).await
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    use crate::error::BoxError;
    use crate::http::{header, Body, StatusCode};
    use crate::service::ServiceBuilder;

    #[derive(Clone, Copy)]
    struct MyAuth;

    impl<S, B> AsyncAuthorizeRequest<S, B> for MyAuth
    where
        S: Send + Sync + 'static,
        B: Send + 'static,
    {
        type RequestBody = B;
        type ResponseBody = Body;

        async fn authorize(
            &self,
            mut ctx: Context<S>,
            request: Request<B>,
        ) -> Result<(Context<S>, Request<Self::RequestBody>), Response<Self::ResponseBody>>
        {
            let authorized = request
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|it: &http::HeaderValue| it.to_str().ok())
                .and_then(|it| it.strip_prefix("Bearer "))
                .map(|it| it == "69420")
                .unwrap_or(false);

            if authorized {
                let user_id = UserId("6969".to_owned());
                ctx.insert(user_id);
                Ok((ctx, request))
            } else {
                Err(Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::empty())
                    .unwrap())
            }
        }
    }

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    struct UserId(String);

    #[tokio::test]
    async fn require_async_auth_works() {
        let service = ServiceBuilder::new()
            .layer(AsyncRequireAuthorizationLayer::new(MyAuth))
            .service_fn(echo);

        let request = Request::get("/")
            .header(header::AUTHORIZATION, "Bearer 69420")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn require_async_auth_401() {
        let service = ServiceBuilder::new()
            .layer(AsyncRequireAuthorizationLayer::new(MyAuth))
            .service_fn(echo);

        let request = Request::get("/")
            .header(header::AUTHORIZATION, "Bearer deez")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    async fn echo<Body>(req: Request<Body>) -> Result<Response<Body>, BoxError> {
        Ok(Response::new(req.into_body()))
    }
}
