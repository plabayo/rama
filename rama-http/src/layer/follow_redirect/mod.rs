//! Middleware for following redirections.
//!
//! # Overview
//!
//! The [`FollowRedirect`] middleware retries requests with the inner [`Service`] to follow HTTP
//! redirections.
//!
//! The middleware tries to clone the original [`Request`] when making a redirected request.
//! However, since [`Extensions`][http::Extensions] are `!Clone`, any extensions set by outer
//! middleware will be discarded. Also, the request body cannot always be cloned. When the
//! original body is known to be empty by [`Body::size_hint`], the middleware uses `Default`
//! implementation of the body type to create a new request body. If you know that the body can be
//! cloned in some way, you can tell the middleware to clone it by configuring a [`policy`].
//!
//! # Examples
//!
//! ## Basic usage
//!
//! ```
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Service, Layer};
//! use rama_http::{Body, Request, Response, StatusCode, header};
//! use rama_http::layer::follow_redirect::{FollowRedirectLayer, RequestUri};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), std::convert::Infallible> {
//! # let http_client = service_fn(|req: Request| async move {
//! #     let dest = "https://www.rust-lang.org/";
//! #     let mut res = Response::builder();
//! #     if req.uri() != dest {
//! #         res = res
//! #             .status(StatusCode::MOVED_PERMANENTLY)
//! #             .header(header::LOCATION, dest);
//! #     }
//! #     Ok::<_, std::convert::Infallible>(res.body(Body::empty()).unwrap())
//! # });
//! let mut client = FollowRedirectLayer::new().layer(http_client);
//!
//! let request = Request::builder()
//!     .uri("https://rust-lang.org/")
//!     .body(Body::empty())
//!     .unwrap();
//!
//! let response = client.serve(Context::default(), request).await?;
//! // Get the final request URI.
//! assert_eq!(response.extensions().get::<RequestUri>().unwrap().0, "https://www.rust-lang.org/");
//! # Ok(())
//! # }
//! ```
//!
//! ## Customizing the `Policy`
//!
//! You can use a [`Policy`] value to customize how the middleware handles redirections.
//!
//! ```
//! # #![allow(unused)]
//!
//! # use std::convert::Infallible;
//! use rama_core::service::service_fn;
//! use rama_core::layer::MapErrLayer;
//! use rama_core::{Context, Service, Layer};
//! use rama_http::{Body, Request, Response};
//! use rama_http::layer::follow_redirect::{
//!     policy::{self, PolicyExt},
//!     FollowRedirectLayer,
//! };
//! use rama_core::error::OpaqueError;
//!
//! #[derive(Debug)]
//! enum MyError {
//!     TooManyRedirects,
//!     Other(OpaqueError),
//! }
//!
//! impl MyError {
//!     fn from_std(err: impl std::error::Error + Send + Sync + 'static) -> Self {
//!         Self::Other(OpaqueError::from_std(err))
//!     }
//!
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), MyError> {
//! # let http_client = service_fn(|_: Request| async { Ok::<_, Infallible>(Response::new(Body::empty())) });
//! let policy = policy::Limited::new(10) // Set the maximum number of redirections to 10.
//!     // Return an error when the limit was reached.
//!     .or::<(), _, (), _>(policy::redirect_fn(|_| Err(MyError::TooManyRedirects)))
//!     // Do not follow cross-origin redirections, and return the redirection responses as-is.
//!     .and::<(), _, (), _>(policy::SameOrigin::new());
//!
//! let client = (
//!     FollowRedirectLayer::with_policy(policy),
//!     MapErrLayer::new(MyError::from_std),
//! ).layer(http_client);
//!
//! // ...
//! let _ = client.serve(Context::default(), Request::default()).await?;
//! # Ok(())
//! # }
//! ```

pub mod policy;

use crate::{dep::http_body::Body, header::LOCATION, Method, Request, Response, StatusCode, Uri};
use iri_string::types::{UriAbsoluteString, UriReferenceStr};
use rama_core::{context::StateTransformer, error::BoxError, Context, Layer, Service};
use rama_utils::macros::define_inner_service_accessors;
use std::{fmt, future::Future};

use self::policy::{Action, Attempt, Policy, Standard};

/// [`Layer`] for retrying requests with a [`Service`] to follow redirection responses.
///
/// See the [module docs](self) for more details.
#[derive(Clone)]
pub struct FollowRedirectLayer<P = Standard, T = ()> {
    policy: P,
    state_transformer: T,
}

impl FollowRedirectLayer {
    /// Create a new [`FollowRedirectLayer`] with a [`Standard`] redirection policy.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for FollowRedirectLayer {
    fn default() -> Self {
        FollowRedirectLayer {
            policy: Standard::default(),
            state_transformer: (),
        }
    }
}

impl<P: fmt::Debug, T: fmt::Debug> fmt::Debug for FollowRedirectLayer<P, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FollowRedirectLayer")
            .field("policy", &self.policy)
            .field("state_transformer", &self.state_transformer)
            .finish()
    }
}

impl<P> FollowRedirectLayer<P> {
    /// Create a new [`FollowRedirectLayer`] with the given redirection [`Policy`].
    pub fn with_policy(policy: P) -> Self {
        FollowRedirectLayer {
            policy,
            state_transformer: (),
        }
    }
}

impl<P> FollowRedirectLayer<P> {
    /// Add a [`StateTransformer`] to the [`FollowRedirectLayer`]
    /// to customise how the state is to be created for each call.
    pub fn with_state_transformer<T>(self, transformer: T) -> FollowRedirectLayer<P, T> {
        FollowRedirectLayer {
            policy: self.policy,
            state_transformer: transformer,
        }
    }
}

impl<S, P, T> Layer<S> for FollowRedirectLayer<P, T>
where
    S: Clone,
    P: Clone,
    T: Clone,
{
    type Service = FollowRedirect<S, P, T>;

    fn layer(&self, inner: S) -> Self::Service {
        FollowRedirect {
            inner,
            policy: self.policy.clone(),
            state_transformer: self.state_transformer.clone(),
        }
    }
}

/// Middleware that retries requests with a [`Service`] to follow redirection responses.
///
/// See the [module docs](self) for more details.
pub struct FollowRedirect<S, P = Standard, T = ()> {
    inner: S,
    policy: P,
    state_transformer: T,
}

impl<S> FollowRedirect<S> {
    /// Create a new [`FollowRedirect`] with a [`Standard`] redirection policy.
    pub fn new(inner: S) -> Self {
        Self::with_policy(inner, Standard::default())
    }
}

impl<S, P, T> fmt::Debug for FollowRedirect<S, P, T>
where
    S: fmt::Debug,
    P: fmt::Debug,
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FollowRedirect")
            .field("inner", &self.inner)
            .field("policy", &self.policy)
            .field("state_transformer", &self.state_transformer)
            .finish()
    }
}

impl<S, P, T> Clone for FollowRedirect<S, P, T>
where
    S: Clone,
    P: Clone,
    T: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            policy: self.policy.clone(),
            state_transformer: self.state_transformer.clone(),
        }
    }
}

impl<S, P> FollowRedirect<S, P> {
    /// Create a new [`FollowRedirect`] with the given redirection [`Policy`].
    pub fn with_policy(inner: S, policy: P) -> Self {
        FollowRedirect {
            inner,
            policy,
            state_transformer: (),
        }
    }

    /// Add a [`StateTransformer`] to the [`FollowRedirect`]
    /// to customise how the state is to be created for each call.
    pub fn with_state_transformer<T>(self, transformer: T) -> FollowRedirect<S, P, T> {
        FollowRedirect {
            inner: self.inner,
            policy: self.policy,
            state_transformer: transformer,
        }
    }

    define_inner_service_accessors!();
}

impl<State, ReqBody, ResBody, S, P, T> Service<State, Request<ReqBody>> for FollowRedirect<S, P, T>
where
    State: Send + Sync + 'static,
    S: Service<T::Output, Request<ReqBody>, Response = Response<ResBody>, Error: Into<BoxError>>,
    ReqBody: Body + Default + Send + 'static,
    ResBody: Send + 'static,
    P: Policy<State, ReqBody, S::Error> + Clone,
    T: StateTransformer<
            State,
            Output: Send + Sync + 'static,
            Error: Into<BoxError> + Send + Sync + 'static,
        > + Send
        + Sync
        + 'static,
{
    type Response = Response<ResBody>;
    type Error = BoxError;

    fn serve(
        &self,
        mut ctx: Context<State>,
        mut req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> {
        let mut method = req.method().clone();
        let mut uri = req.uri().clone();
        let version = req.version();
        let headers = req.headers().clone();

        let mut policy = self.policy.clone();

        let mut body = BodyRepr::None;
        body.try_clone_from(&ctx, &mut policy, req.body());
        policy.on_request(&mut ctx, &mut req);

        let service = &self.inner;
        let state_transformer = &self.state_transformer;

        async move {
            loop {
                let state = state_transformer
                    .transform_state(&ctx)
                    .map_err(Into::into)?;
                let mut res = service
                    .serve(ctx.clone_with_state(state), req)
                    .await
                    .map_err(Into::into)?;
                res.extensions_mut().insert(RequestUri(uri.clone()));

                match res.status() {
                    StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND => {
                        // User agents MAY change the request method from POST to GET
                        // (RFC 7231 section 6.4.2. and 6.4.3.).
                        if method == Method::POST {
                            method = Method::GET;
                            body = BodyRepr::Empty;
                        }
                    }
                    StatusCode::SEE_OTHER => {
                        // A user agent can perform a GET or HEAD request (RFC 7231 section 6.4.4.).
                        if method != Method::HEAD {
                            method = Method::GET;
                        }
                        body = BodyRepr::Empty;
                    }
                    StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT => {}
                    _ => return Ok(res),
                };

                let taken_body = if let Some(body) = body.take() {
                    body
                } else {
                    return Ok(res);
                };

                let location = res
                    .headers()
                    .get(&LOCATION)
                    .and_then(|loc| resolve_uri(std::str::from_utf8(loc.as_bytes()).ok()?, &uri));
                let location = if let Some(loc) = location {
                    loc
                } else {
                    return Ok(res);
                };

                let attempt = Attempt {
                    status: res.status(),
                    location: &location,
                    previous: &uri,
                };
                match policy.redirect(&ctx, &attempt).map_err(Into::into)? {
                    Action::Follow => {
                        uri = location;
                        body.try_clone_from(&ctx, &mut policy, &taken_body);

                        req = Request::new(taken_body);
                        *req.uri_mut() = uri.clone();
                        *req.method_mut() = method.clone();
                        *req.version_mut() = version;
                        *req.headers_mut() = headers.clone();
                        policy.on_request(&mut ctx, &mut req);
                        continue;
                    }
                    Action::Stop => return Ok(res),
                }
            }
        }
    }
}

/// Response [`Extensions`][http::Extensions] value that represents the effective request URI of
/// a response returned by a [`FollowRedirect`] middleware.
///
/// The value differs from the original request's effective URI if the middleware has followed
/// redirections.
#[derive(Debug, Clone)]
pub struct RequestUri(pub Uri);

#[derive(Debug)]
enum BodyRepr<B> {
    Some(B),
    Empty,
    None,
}

impl<B> BodyRepr<B>
where
    B: Body + Default,
{
    fn take(&mut self) -> Option<B> {
        match std::mem::replace(self, BodyRepr::None) {
            BodyRepr::Some(body) => Some(body),
            BodyRepr::Empty => {
                *self = BodyRepr::Empty;
                Some(B::default())
            }
            BodyRepr::None => None,
        }
    }

    fn try_clone_from<S, P, E>(&mut self, ctx: &Context<S>, policy: &mut P, body: &B)
    where
        P: Policy<S, B, E>,
    {
        match self {
            BodyRepr::Some(_) | BodyRepr::Empty => {}
            BodyRepr::None => {
                if let Some(body) = clone_body(ctx, policy, body) {
                    *self = BodyRepr::Some(body);
                }
            }
        }
    }
}

fn clone_body<S, P, B, E>(ctx: &Context<S>, policy: &mut P, body: &B) -> Option<B>
where
    P: Policy<S, B, E>,
    B: Body + Default,
{
    if body.size_hint().exact() == Some(0) {
        Some(B::default())
    } else {
        policy.clone_body(ctx, body)
    }
}

/// Try to resolve a URI reference `relative` against a base URI `base`.
fn resolve_uri(relative: &str, base: &Uri) -> Option<Uri> {
    let relative = UriReferenceStr::new(relative).ok()?;
    let base = UriAbsoluteString::try_from(base.to_string()).ok()?;
    let uri = relative.resolve_against(&base).to_string();
    Uri::try_from(uri).ok()
}

#[cfg(test)]
mod tests {
    use super::{policy::*, *};
    use crate::{header::LOCATION, Body};
    use rama_core::service::service_fn;
    use rama_core::Layer;
    use std::convert::Infallible;

    #[tokio::test]
    async fn follows() {
        let svc = FollowRedirectLayer::with_policy(Action::Follow).layer(service_fn(handle));
        let req = Request::builder()
            .uri("http://example.com/42")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(Context::default(), req).await.unwrap();
        assert_eq!(*res.body(), 0);
        assert_eq!(
            res.extensions().get::<RequestUri>().unwrap().0,
            "http://example.com/0"
        );
    }

    #[tokio::test]
    async fn stops() {
        let svc = FollowRedirectLayer::with_policy(Action::Stop).layer(service_fn(handle));
        let req = Request::builder()
            .uri("http://example.com/42")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(Context::default(), req).await.unwrap();
        assert_eq!(*res.body(), 42);
        assert_eq!(
            res.extensions().get::<RequestUri>().unwrap().0,
            "http://example.com/42"
        );
    }

    #[tokio::test]
    async fn limited() {
        let svc = FollowRedirectLayer::with_policy(Limited::new(10)).layer(service_fn(handle));
        let req = Request::builder()
            .uri("http://example.com/42")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(Context::default(), req).await.unwrap();
        assert_eq!(*res.body(), 42 - 10);
        assert_eq!(
            res.extensions().get::<RequestUri>().unwrap().0,
            "http://example.com/32"
        );
    }

    /// A server with an endpoint `GET /{n}` which redirects to `/{n-1}` unless `n` equals zero,
    /// returning `n` as the response body.
    async fn handle<S, B>(_ctx: Context<S>, req: Request<B>) -> Result<Response<u64>, Infallible> {
        let n: u64 = req.uri().path()[1..].parse().unwrap();
        let mut res = Response::builder();
        if n > 0 {
            res = res
                .status(StatusCode::MOVED_PERMANENTLY)
                .header(LOCATION, format!("/{}", n - 1));
        }
        Ok::<_, Infallible>(res.body(n).unwrap())
    }
}
