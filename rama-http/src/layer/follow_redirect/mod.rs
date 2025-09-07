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
//! # let http_client = service_fn(async |req: Request| {
//! #     let dest = "https://www.rust-lang.org/";
//! #     let mut res = Response::builder();
//! #     if req.uri() != dest {
//! #         res = res
//! #             .status(StatusCode::MOVED_PERMANENTLY)
//! #             .header(header::LOCATION, dest);
//! #     }
//! #     Ok::<_, std::convert::Infallible>(res.body(Body::empty()).unwrap())
//! # });
//! let mut client = FollowRedirectLayer::new().into_layer(http_client);
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
//! # let http_client = service_fn(async |_: Request| Ok::<_, Infallible>(Response::new(Body::empty())));
//! let policy = policy::Limited::new(10) // Set the maximum number of redirections to 10.
//!     // Return an error when the limit was reached.
//!     .or::<_, (), _>(policy::redirect_fn(|_| Err(MyError::TooManyRedirects)))
//!     // Do not follow cross-origin redirections, and return the redirection responses as-is.
//!     .and::<_, (), _>(policy::SameOrigin::new());
//!
//! let client = (
//!     FollowRedirectLayer::with_policy(policy),
//!     MapErrLayer::new(MyError::from_std),
//! ).into_layer(http_client);
//!
//! // ...
//! let _ = client.serve(Context::default(), Request::default()).await?;
//! # Ok(())
//! # }
//! ```

pub mod policy;

use crate::{Method, Request, Response, StatusCode, Uri, dep::http_body::Body, header::LOCATION};
use iri_string::types::{UriAbsoluteString, UriReferenceStr};
use rama_core::{Context, Layer, Service};
use rama_http_types::{
    HeaderMap,
    header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING},
};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

use self::policy::{Action, Attempt, Policy, Standard};

/// [`Layer`] for retrying requests with a [`Service`] to follow redirection responses.
///
/// See the [module docs](self) for more details.
#[derive(Clone)]
pub struct FollowRedirectLayer<P = Standard> {
    policy: P,
}

impl FollowRedirectLayer {
    /// Create a new [`FollowRedirectLayer`] with a [`Standard`] redirection policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for FollowRedirectLayer {
    fn default() -> Self {
        Self {
            policy: Standard::default(),
        }
    }
}

impl<P: fmt::Debug> fmt::Debug for FollowRedirectLayer<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FollowRedirectLayer")
            .field("policy", &self.policy)
            .finish()
    }
}

impl<P> FollowRedirectLayer<P> {
    /// Create a new [`FollowRedirectLayer`] with the given redirection [`Policy`].
    pub fn with_policy(policy: P) -> Self {
        Self { policy }
    }
}

impl<S, P> Layer<S> for FollowRedirectLayer<P>
where
    S: Clone,
    P: Clone,
{
    type Service = FollowRedirect<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        FollowRedirect {
            inner,
            policy: self.policy.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        FollowRedirect {
            inner,
            policy: self.policy,
        }
    }
}

/// Middleware that retries requests with a [`Service`] to follow redirection responses.
///
/// See the [module docs](self) for more details.
pub struct FollowRedirect<S, P = Standard> {
    inner: S,
    policy: P,
}

impl<S> FollowRedirect<S> {
    /// Create a new [`FollowRedirect`] with a [`Standard`] redirection policy.
    pub fn new(inner: S) -> Self {
        Self::with_policy(inner, Standard::default())
    }
}

impl<S, P> fmt::Debug for FollowRedirect<S, P>
where
    S: fmt::Debug,
    P: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FollowRedirect")
            .field("inner", &self.inner)
            .field("policy", &self.policy)
            .finish()
    }
}

impl<S, P> Clone for FollowRedirect<S, P>
where
    S: Clone,
    P: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            policy: self.policy.clone(),
        }
    }
}

impl<S, P> FollowRedirect<S, P> {
    /// Create a new [`FollowRedirect`] with the given redirection [`Policy`].
    pub fn with_policy(inner: S, policy: P) -> Self {
        Self { inner, policy }
    }

    define_inner_service_accessors!();
}

impl<ReqBody, ResBody, S, P> Service<Request<ReqBody>> for FollowRedirect<S, P>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Body + Default + Send + 'static,
    ResBody: Send + 'static,
    P: Policy<ReqBody, S::Error> + Clone,
{
    type Response = Response<ResBody>;
    type Error = S::Error;

    fn serve(
        &self,
        mut ctx: Context,
        mut req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> {
        let mut method = req.method().clone();
        let mut uri = req.uri().clone();
        let version = req.version();
        let mut headers = req.headers().clone();

        let mut policy = self.policy.clone();

        let mut body = BodyRepr::None;
        body.try_clone_from(&ctx, &mut policy, req.body());
        policy.on_request(&mut ctx, &mut req);

        let service = &self.inner;

        async move {
            loop {
                let mut res = service.serve(ctx.clone(), req).await?;
                res.extensions_mut().insert(RequestUri(uri.clone()));

                let drop_payload_headers = |headers: &mut HeaderMap| {
                    for header in &[
                        CONTENT_TYPE,
                        CONTENT_LENGTH,
                        CONTENT_ENCODING,
                        TRANSFER_ENCODING,
                    ] {
                        headers.remove(header);
                    }
                };

                match res.status() {
                    StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND => {
                        // User agents MAY change the request method from POST to GET
                        // (RFC 7231 section 6.4.2. and 6.4.3.).
                        if method == Method::POST {
                            method = Method::GET;
                            body = BodyRepr::Empty;
                            drop_payload_headers(&mut headers);
                        }
                    }
                    StatusCode::SEE_OTHER => {
                        // A user agent can perform a GET or HEAD request (RFC 7231 section 6.4.4.).
                        if method != Method::HEAD {
                            method = Method::GET;
                        }
                        body = BodyRepr::Empty;
                        drop_payload_headers(&mut headers);
                    }
                    StatusCode::TEMPORARY_REDIRECT | StatusCode::PERMANENT_REDIRECT => {}
                    _ => return Ok(res),
                };

                let Some(taken_body) = body.take() else {
                    return Ok(res);
                };

                let location = res
                    .headers()
                    .get(&LOCATION)
                    .and_then(|loc| resolve_uri(std::str::from_utf8(loc.as_bytes()).ok()?, &uri));
                let Some(location) = location else {
                    return Ok(res);
                };

                let attempt = Attempt {
                    status: res.status(),
                    location: &location,
                    previous: &uri,
                };
                match policy.redirect(&ctx, &attempt)? {
                    Action::Follow => {
                        uri = location;
                        body.try_clone_from(&ctx, &mut policy, &taken_body);

                        req = Request::new(taken_body);
                        *req.uri_mut() = uri.clone();
                        *req.method_mut() = method.clone();
                        *req.version_mut() = version;
                        *req.headers_mut() = headers.clone();
                        policy.on_request(&mut ctx, &mut req);
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
        match std::mem::replace(self, Self::None) {
            Self::Some(body) => Some(body),
            Self::Empty => {
                *self = Self::Empty;
                Some(B::default())
            }
            Self::None => None,
        }
    }

    fn try_clone_from<P, E>(&mut self, ctx: &Context, policy: &mut P, body: &B)
    where
        P: Policy<B, E>,
    {
        match self {
            Self::Some(_) | Self::Empty => {}
            Self::None => {
                if let Some(body) = clone_body(ctx, policy, body) {
                    *self = Self::Some(body);
                }
            }
        }
    }
}

fn clone_body<P, B, E>(ctx: &Context, policy: &mut P, body: &B) -> Option<B>
where
    P: Policy<B, E>,
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
    use crate::{Body, header::LOCATION};
    use rama_core::Layer;
    use rama_core::service::service_fn;
    use std::convert::Infallible;

    #[tokio::test]
    async fn follows() {
        let svc = FollowRedirectLayer::with_policy(Action::Follow).into_layer(service_fn(handle));
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
        let svc = FollowRedirectLayer::with_policy(Action::Stop).into_layer(service_fn(handle));
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
        let svc = FollowRedirectLayer::with_policy(Limited::new(10)).into_layer(service_fn(handle));
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
    async fn handle<B>(_ctx: Context, req: Request<B>) -> Result<Response<u64>, Infallible> {
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
