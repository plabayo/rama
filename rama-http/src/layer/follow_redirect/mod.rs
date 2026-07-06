//! Middleware for following redirections.
//!
//! # Overview
//!
//! The [`FollowRedirect`] middleware retries requests with the inner [`Service`] to follow HTTP
//! redirections.
//!
//! The middleware tries to clone the original [`Request`] when making a redirected request.
//! Request [`Extensions`] are carried over to redirected
//! requests according to the configured [`RedirectExtensionsBehaviour`] (preserved — i.e. the
//! same store is shared — by default). The request body cannot always be cloned. When the original body is
//! known to be empty by [`StreamingBody::size_hint`], the middleware uses the `Default`
//! implementation of the body type to create a new request body. If you know that the body can be
//! cloned in some way, you can tell the middleware to clone it by configuring a [`policy`].
//!
//! # Examples
//!
//! ## Basic usage
//!
//! ```
//! use rama_core::service::service_fn;
//! use rama_core::{extensions::ExtensionsRef, Service, Layer};
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
//! let response = client.serve(request).await?;
//! // Get the final request URI.
//! assert_eq!(response.extensions().get_ref::<RequestUri>().unwrap().0, "https://www.rust-lang.org/");
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
//! use rama_core::{Service, Layer};
//! use rama_http::{Body, Request, Response};
//! use rama_http::layer::follow_redirect::{
//!     policy::{self, PolicyExt},
//!     FollowRedirectLayer,
//! };
//! use rama_core::error::BoxError;
//!
//! #[derive(Debug)]
//! enum MyError {
//!     TooManyRedirects,
//!     Other(BoxError),
//! }
//!
//! impl MyError {
//!     fn from_std(err: impl std::error::Error + Send + Sync + 'static) -> Self {
//!         Self::Other(BoxError::from(err))
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
//! _ = client.serve(Request::default()).await?;
//! # Ok(())
//! # }
//! ```

pub mod policy;

use crate::{Method, Request, Response, StatusCode, StreamingBody, header::LOCATION};
use iri_string::types::{UriAbsoluteString, UriReferenceStr};
use rama_core::{
    Layer, Service,
    extensions::{Extension, Extensions, ExtensionsRef},
};
use rama_http_types::{
    HeaderMap,
    header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING},
};
use rama_net::uri::Uri;
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};
use std::fmt;

use self::policy::{Action, Attempt, Policy, Standard};

/// Controls how request [`Extensions`] are carried over to redirected requests.
///
/// rama's [`Extensions`] are an append-only, parent-chained store, so this mirrors the way
/// retries and forks are modelled elsewhere in rama rather than the boolean toggle used by
/// upstream `tower-http`.
///
/// Note that, regardless of the variant, a forwarded extension can be _read_ by the redirect
/// target (including cross-origin ones). Use [`Self::Drop`] when extensions may carry sensitive,
/// origin-scoped data. Unlike upstream `tower-http` — whose default `Standard` policy clears
/// extensions on a cross-origin hop — rama's [`Extensions`] are append-only, so no policy
/// (including [`FilterCredentials`]) can strip them; isolating origin-scoped data is solely this
/// setting's job, via [`Self::Drop`].
///
/// [`FilterCredentials`]: policy::FilterCredentials
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RedirectExtensionsBehaviour {
    /// Share the original request's extension store with redirected requests.
    ///
    /// The redirected requests reference the same underlying store, so inserts made while
    /// following a redirect are visible to the original caller as well. This is the default.
    #[default]
    Preserve,
    /// Carry a [`fork`][Extensions::fork] of the request extensions to redirected requests.
    ///
    /// The redirected request can read every extension the original request had, but its own
    /// inserts stay isolated and never leak back to the caller or accumulate across hops, which
    /// mirrors rama's convention that retries/forks fork from the original request.
    Fork,
    /// Drop all extensions on redirected requests; each starts with an empty store.
    Drop,
}

impl RedirectExtensionsBehaviour {
    /// Derive the [`Extensions`] for a redirected request from the original request's `source`.
    fn redirect_extensions(self, source: &Extensions) -> Extensions {
        match self {
            Self::Preserve => source.clone(),
            Self::Fork => source.fork(),
            Self::Drop => Extensions::new(),
        }
    }
}

/// [`Layer`] for retrying requests with a [`Service`] to follow redirection responses.
///
/// See the [module docs](self) for more details.
#[derive(Clone)]
pub struct FollowRedirectLayer<P = Standard> {
    policy: P,
    extensions_behaviour: RedirectExtensionsBehaviour,
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
        Self::with_policy(Standard::default())
    }
}

impl<P: fmt::Debug> fmt::Debug for FollowRedirectLayer<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FollowRedirectLayer")
            .field("policy", &self.policy)
            .field("extensions_behaviour", &self.extensions_behaviour)
            .finish()
    }
}

impl<P> FollowRedirectLayer<P> {
    /// Create a new [`FollowRedirectLayer`] with the given redirection [`Policy`].
    pub fn with_policy(policy: P) -> Self {
        Self {
            policy,
            extensions_behaviour: RedirectExtensionsBehaviour::default(),
        }
    }

    generate_set_and_with! {
        /// Set how request [`Extensions`] are carried over to redirected requests.
        ///
        /// Defaults to [`RedirectExtensionsBehaviour::Preserve`].
        pub fn redirect_extensions_behaviour(
            mut self,
            behaviour: RedirectExtensionsBehaviour,
        ) -> Self {
            self.extensions_behaviour = behaviour;
            self
        }
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
            extensions_behaviour: self.extensions_behaviour,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        FollowRedirect {
            inner,
            policy: self.policy,
            extensions_behaviour: self.extensions_behaviour,
        }
    }
}

/// Middleware that retries requests with a [`Service`] to follow redirection responses.
///
/// See the [module docs](self) for more details.
#[derive(Debug, Clone)]
pub struct FollowRedirect<S, P = Standard> {
    inner: S,
    policy: P,
    extensions_behaviour: RedirectExtensionsBehaviour,
}

impl<S> FollowRedirect<S> {
    /// Create a new [`FollowRedirect`] with a [`Standard`] redirection policy.
    pub fn new(inner: S) -> Self {
        Self::with_policy(inner, Standard::default())
    }
}

impl<S, P> FollowRedirect<S, P> {
    /// Create a new [`FollowRedirect`] with the given redirection [`Policy`].
    pub fn with_policy(inner: S, policy: P) -> Self {
        Self {
            inner,
            policy,
            extensions_behaviour: RedirectExtensionsBehaviour::default(),
        }
    }

    generate_set_and_with! {
        /// Set how request [`Extensions`] are carried over to redirected requests.
        ///
        /// See [`FollowRedirectLayer::with_redirect_extensions_behaviour`].
        pub fn redirect_extensions_behaviour(
            mut self,
            behaviour: RedirectExtensionsBehaviour,
        ) -> Self {
            self.extensions_behaviour = behaviour;
            self
        }
    }

    define_inner_service_accessors!();
}

impl<ReqBody, ResBody, S, P> Service<Request<ReqBody>> for FollowRedirect<S, P>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    ReqBody: StreamingBody + Default + Send + 'static,
    ResBody: Send + 'static,
    P: Policy<ReqBody, S::Error> + Clone,
{
    type Output = Response<ResBody>;
    type Error = S::Error;

    fn serve(
        &self,

        mut req: Request<ReqBody>,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> {
        let mut method = req.method().clone();
        let mut uri = req.uri().clone();
        let version = req.version();
        let mut headers = req.headers().clone();

        let mut policy = self.policy.clone();

        let mut body = BodyRepr::None;
        body.try_clone_from(&mut policy, req.body());
        policy.on_request(&mut req);

        // Snapshot the request extensions to carry over to redirected requests, per the
        // configured behaviour.
        let extensions_behaviour = self.extensions_behaviour;
        let extensions_source = req.extensions().clone();

        let service = &self.inner;

        async move {
            loop {
                let res = service.serve(req).await?;
                res.extensions().insert(RequestUri(uri.clone()));

                let previous_method = method.clone();
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
                    method: &method,
                    location: &location,
                    previous_method: &previous_method,
                    previous: &uri,
                };
                match policy.redirect(&attempt)? {
                    Action::Follow => {
                        uri = location;
                        body.try_clone_from(&mut policy, &taken_body);

                        req = Request::new(taken_body);
                        *req.uri_mut() = uri.clone();
                        *req.method_mut() = method.clone();
                        *req.version_mut() = version;
                        *req.headers_mut() = headers.clone();
                        req.set_extensions(
                            extensions_behaviour.redirect_extensions(&extensions_source),
                        );
                        policy.on_request(&mut req);
                        // Carry the filtered headers forward so anything dropped on this hop
                        // stays dropped on the next one (e.g. credentials after a cross-origin
                        // hop must not resurrect on a later same-origin hop).
                        headers = req.headers().clone();
                    }
                    Action::Stop => return Ok(res),
                }
            }
        }
    }
}

/// Response [`Extensions`] value that represents the effective request URI of
/// a response returned by a [`FollowRedirect`] middleware.
///
/// The value differs from the original request's effective URI if the middleware has followed
/// redirections.
#[derive(Debug, Clone, Extension)]
#[extension(tags(http))]
pub struct RequestUri(pub Uri);

#[derive(Debug)]
enum BodyRepr<B> {
    Some(B),
    Empty,
    None,
}

impl<B> BodyRepr<B>
where
    B: StreamingBody + Default,
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

    fn try_clone_from<P, E>(&mut self, policy: &mut P, body: &B)
    where
        P: Policy<B, E>,
    {
        match self {
            Self::Some(_) | Self::Empty => {}
            Self::None => {
                if let Some(body) = clone_body(policy, body) {
                    *self = Self::Some(body);
                }
            }
        }
    }
}

fn clone_body<P, B, E>(policy: &mut P, body: &B) -> Option<B>
where
    P: Policy<B, E>,
    B: StreamingBody + Default,
{
    if body.size_hint().exact() == Some(0) {
        Some(B::default())
    } else {
        policy.clone_body(body)
    }
}

/// Try to resolve a URI reference `relative` against a base URI `base`.
fn resolve_uri(relative: &str, base: &Uri) -> Option<Uri> {
    let relative = UriReferenceStr::new(relative).ok()?;
    let base = UriAbsoluteString::try_from(base.to_string()).ok()?;
    let uri = relative.resolve_against(&base).to_string();
    Uri::try_from(uri).ok()
}

/* // ^TODO replace w/ something similar to
let base_url = Url::parse(&base.to_string()).ok()?;
let resolved = base_url.join(relative).ok()?;
Uri::try_from(String::from(resolved)).ok()
*/

#[cfg(test)]
mod tests {
    use super::{policy::*, *};
    use crate::{Body, header::LOCATION};
    use rama_core::Layer;
    use rama_core::extensions::ExtensionsRef;
    use rama_core::service::service_fn;
    use std::convert::Infallible;

    #[tokio::test]
    async fn follows() {
        let svc = FollowRedirectLayer::with_policy(Action::Follow).into_layer(service_fn(handle));
        let req = Request::builder()
            .uri("http://example.com/42")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(req).await.unwrap();
        assert_eq!(*res.body(), 0);
        assert_eq!(
            res.extensions().get_ref::<RequestUri>().unwrap().0,
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
        let res = svc.serve(req).await.unwrap();
        assert_eq!(*res.body(), 42);
        assert_eq!(
            res.extensions().get_ref::<RequestUri>().unwrap().0,
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
        let res = svc.serve(req).await.unwrap();
        assert_eq!(*res.body(), 42 - 10);
        assert_eq!(
            res.extensions().get_ref::<RequestUri>().unwrap().0,
            "http://example.com/32"
        );
    }

    /// A server with an endpoint `/{n}` which redirects to `/{n-1}` unless `n` equals zero,
    /// returning `n` as the response body.
    async fn handle<B>(req: Request<B>) -> Result<Response<u64>, Infallible> {
        let n: u64 = req
            .uri()
            .first_path_segment()
            .and_then(|segment| segment.as_encoded_str().parse().ok())
            .unwrap();
        let mut res = Response::builder();
        if n > 0 {
            res = res
                .status(StatusCode::MOVED_PERMANENTLY)
                .header(LOCATION, format!("/{}", n - 1));
        }
        Ok::<_, Infallible>(res.body(n).unwrap())
    }

    #[derive(Clone, Debug, PartialEq, rama_core::extensions::Extension)]
    struct Marker(u32);

    /// Like [`handle`] but also copies a `Marker` request extension onto the response, so a test
    /// can observe whether it reached the (final, redirected) request.
    async fn handle_marker<B>(req: Request<B>) -> Result<Response<u64>, Infallible> {
        let n: u64 = req
            .uri()
            .first_path_segment()
            .and_then(|segment| segment.as_encoded_str().parse().ok())
            .unwrap();
        let mut res = Response::builder();
        if n > 0 {
            res = res
                .status(StatusCode::MOVED_PERMANENTLY)
                .header(LOCATION, format!("/{}", n - 1));
        }
        let res = res.body(n).unwrap();
        if let Some(marker) = req.extensions().get_ref::<Marker>() {
            res.extensions().insert(marker.clone());
        }
        Ok::<_, Infallible>(res)
    }

    #[tokio::test]
    async fn preserves_extensions_by_default() {
        let svc = FollowRedirectLayer::new().into_layer(service_fn(handle_marker));
        let req = Request::builder()
            .uri("http://example.com/3")
            .body(Body::empty())
            .unwrap();
        req.extensions().insert(Marker(7));
        let res = svc.serve(req).await.unwrap();
        // The default (Preserve) shares the original store, so every redirected request reads it.
        assert_eq!(res.extensions().get_ref::<Marker>(), Some(&Marker(7)));
    }

    #[tokio::test]
    async fn preserve_shares_extensions() {
        let svc = FollowRedirectLayer::new()
            .with_redirect_extensions_behaviour(RedirectExtensionsBehaviour::Preserve)
            .into_layer(service_fn(handle_marker));
        let req = Request::builder()
            .uri("http://example.com/3")
            .body(Body::empty())
            .unwrap();
        req.extensions().insert(Marker(7));
        let res = svc.serve(req).await.unwrap();
        assert_eq!(res.extensions().get_ref::<Marker>(), Some(&Marker(7)));
    }

    /// Drives a cross-origin redirect chain and echoes, via `x-saw-cookie`, whether the incoming
    /// request still carried a `Cookie`:
    /// `a.example.com` → `b.example.com/second` (cross-origin) → `b.example.com/final` (same-origin).
    async fn handle_cookie_chain<B>(req: Request<B>) -> Result<Response<u64>, Infallible> {
        let host = req.uri().host_str();
        let path = req.uri().path_ref_or_root();
        let location = if host.as_deref() == Some("a.example.com") {
            Some("http://b.example.com/second")
        } else if host.as_deref() == Some("b.example.com") && path == "/second" {
            Some("http://b.example.com/final")
        } else {
            None
        };
        let mut res = Response::builder();
        if let Some(location) = location {
            res = res
                .status(StatusCode::MOVED_PERMANENTLY)
                .header(LOCATION, location);
        }
        let mut res = res.body(0u64).unwrap();
        if req.headers().contains_key(crate::header::COOKIE) {
            res.headers_mut()
                .insert("x-saw-cookie", crate::HeaderValue::from_static("1"));
        }
        Ok::<_, Infallible>(res)
    }

    #[tokio::test]
    async fn credentials_do_not_resurrect_after_cross_origin() {
        // Regression for the cumulative-filtering half of tower-http #706: the default Standard
        // policy strips Cookie on the cross-origin a→b hop; it must NOT reappear on the later
        // same-origin b→b hop just because the original header snapshot is replayed.
        let svc = FollowRedirectLayer::default().into_layer(service_fn(handle_cookie_chain));
        let req = Request::builder()
            .uri("http://a.example.com/")
            .header(crate::header::COOKIE, "session=secret")
            .body(Body::empty())
            .unwrap();
        let res = svc.serve(req).await.unwrap();
        assert!(
            !res.headers().contains_key("x-saw-cookie"),
            "Cookie resurrected on a same-origin hop after being dropped cross-origin",
        );
        assert_eq!(
            res.extensions().get_ref::<RequestUri>().unwrap().0,
            "http://b.example.com/final"
        );
    }

    #[tokio::test]
    async fn drop_extensions_opt_out() {
        let svc = FollowRedirectLayer::new()
            .with_redirect_extensions_behaviour(RedirectExtensionsBehaviour::Drop)
            .into_layer(service_fn(handle_marker));
        let req = Request::builder()
            .uri("http://example.com/3")
            .body(Body::empty())
            .unwrap();
        req.extensions().insert(Marker(7));
        let res = svc.serve(req).await.unwrap();
        // Dropping extensions means the final, redirected request never sees the marker.
        assert!(res.extensions().get_ref::<Marker>().is_none());
    }

    #[tokio::test]
    async fn test_301_redirects() {
        let policy = policy::redirect_fn(|attempt| -> Result<_, Infallible> {
            if attempt.previous_method() == Method::POST && attempt.method() == Method::GET {
                Ok(Action::Stop)
            } else {
                Ok(Action::Follow)
            }
        });
        let svc = FollowRedirectLayer::with_policy(policy).into_layer(service_fn(redirections));

        // A POST request with a 301 redirection should turn into a GET
        // request, and the policy should stop the redirection.
        {
            let req = Request::builder()
                .method(Method::POST)
                .uri("http://example.com/301")
                .body(Body::empty())
                .unwrap();
            let res = svc.clone().serve(req).await.unwrap();
            assert_eq!(*res.body(), "/target/301");
            assert_eq!(
                res.extensions().get_ref::<RequestUri>().unwrap().0,
                "http://example.com/301"
            );
        }

        // A GET request with a 301 redirection should remain a GET
        // request, and the policy should allow the redirection.
        {
            let req = Request::builder()
                .method(Method::GET)
                .uri("http://example.com/301")
                .body(Body::empty())
                .unwrap();
            let res = svc.clone().serve(req).await.unwrap();
            assert_eq!(*res.body(), "/target/301/final");
            assert_eq!(
                res.extensions().get_ref::<RequestUri>().unwrap().0,
                "http://example.com/target/301"
            );
        }
    }

    #[tokio::test]
    async fn test_302_redirects() {
        let policy = policy::redirect_fn(|attempt| -> Result<_, Infallible> {
            if attempt.previous_method() != attempt.method() {
                Ok(Action::Stop)
            } else {
                Ok(Action::Follow)
            }
        });
        let svc = FollowRedirectLayer::with_policy(policy).into_layer(service_fn(redirections));

        // A POST request with a 302 redirection should turn into a GET
        // request, and the policy should stop the redirection.
        {
            let req = Request::builder()
                .method(Method::POST)
                .uri("http://example.com/302")
                .body(Body::empty())
                .unwrap();
            let res = svc.clone().serve(req).await.unwrap();
            assert_eq!(*res.body(), "/target/302");
            assert_eq!(
                res.extensions().get_ref::<RequestUri>().unwrap().0,
                "http://example.com/302"
            );
        }

        // A PUT request with a 302 redirection should remain a PUT
        // request, and the policy should allow the redirection.
        {
            let req = Request::builder()
                .method(Method::PUT)
                .uri("http://example.com/302")
                .body(Body::empty())
                .unwrap();
            let res = svc.clone().serve(req).await.unwrap();
            assert_eq!(*res.body(), "/target/302/final");
            assert_eq!(
                res.extensions().get_ref::<RequestUri>().unwrap().0,
                "http://example.com/target/302"
            );
        }

        // A HEAD request with a 302 redirection should remain a HEAD
        // request, and the policy should allow the redirection.
        {
            let req = Request::builder()
                .method(Method::HEAD)
                .uri("http://example.com/302")
                .body(Body::empty())
                .unwrap();
            let res = svc.clone().serve(req).await.unwrap();
            assert_eq!(*res.body(), "/target/302/final");
            assert_eq!(
                res.extensions().get_ref::<RequestUri>().unwrap().0,
                "http://example.com/target/302"
            );
        }
    }

    #[tokio::test]
    async fn test_303_redirects() {
        let policy = policy::redirect_fn(|attempt| -> Result<_, Infallible> {
            if attempt.previous_method() != attempt.method() {
                Ok(Action::Stop)
            } else {
                Ok(Action::Follow)
            }
        });
        let svc = FollowRedirectLayer::with_policy(policy).into_layer(service_fn(redirections));

        // A POST request with a 303 redirection should turn into a GET
        // request, and the policy should stop the redirection.
        {
            let req = Request::builder()
                .method(Method::POST)
                .uri("http://example.com/303")
                .body(Body::empty())
                .unwrap();
            let res = svc.clone().serve(req).await.unwrap();
            assert_eq!(*res.body(), "/target/303");
            assert_eq!(
                res.extensions().get_ref::<RequestUri>().unwrap().0,
                "http://example.com/303"
            );
        }

        // A PUT request with a 303 redirection should turn into a GET
        // request, and the policy should stop the redirection.
        {
            let req = Request::builder()
                .method(Method::PUT)
                .uri("http://example.com/303")
                .body(Body::empty())
                .unwrap();
            let res = svc.clone().serve(req).await.unwrap();
            assert_eq!(*res.body(), "/target/303");
            assert_eq!(
                res.extensions().get_ref::<RequestUri>().unwrap().0,
                "http://example.com/303"
            );
        }

        // A HEAD request with a 303 redirection should remain a HEAD
        // request, and the policy should allow the redirection.
        {
            let req = Request::builder()
                .method(Method::HEAD)
                .uri("http://example.com/303")
                .body(Body::empty())
                .unwrap();
            let res = svc.clone().serve(req).await.unwrap();
            assert_eq!(*res.body(), "/target/303/final");
            assert_eq!(
                res.extensions().get_ref::<RequestUri>().unwrap().0,
                "http://example.com/target/303"
            );
        }
    }

    #[tokio::test]
    async fn test_307_308_redirects() {
        let policy = policy::redirect_fn(|attempt| -> Result<_, Infallible> {
            if attempt.previous_method() != Method::POST || attempt.method() != Method::POST {
                Ok(Action::Stop)
            } else {
                Ok(Action::Follow)
            }
        });
        let svc = FollowRedirectLayer::with_policy(policy).into_layer(service_fn(redirections));

        // A POST request with a 307 redirection should remain a POST
        // request, and the policy should allow the redirection.
        {
            let req = Request::builder()
                .method(Method::POST)
                .uri("http://example.com/307")
                .body(Body::empty())
                .unwrap();
            let res = svc.clone().serve(req).await.unwrap();
            assert_eq!(*res.body(), "/target/307/final");
            assert_eq!(
                res.extensions().get_ref::<RequestUri>().unwrap().0,
                "http://example.com/target/307"
            );
        }

        // A POST request with a 308 redirection should remain a POST
        // request, and the policy should allow the redirection.
        {
            let req = Request::builder()
                .method(Method::POST)
                .uri("http://example.com/308")
                .body(Body::empty())
                .unwrap();
            let res = svc.clone().serve(req).await.unwrap();
            assert_eq!(*res.body(), "/target/308/final");
            assert_eq!(
                res.extensions().get_ref::<RequestUri>().unwrap().0,
                "http://example.com/target/308"
            );
        }
    }

    /// Returns different 3xx redirections based on the request's URI.
    async fn redirections<B>(req: Request<B>) -> Result<Response<String>, Infallible> {
        let path = req.uri().path_ref_or_root();
        let mut res = Response::builder();
        let body_str;
        res = if path == "/301" {
            let case = "/target/301";
            body_str = case.to_owned();
            res.status(StatusCode::MOVED_PERMANENTLY)
                .header(LOCATION, case)
        } else if path == "/302" {
            let case = "/target/302";
            body_str = case.to_owned();
            res.status(StatusCode::FOUND).header(LOCATION, case)
        } else if path == "/303" {
            let case = "/target/303";
            body_str = case.to_owned();
            res.status(StatusCode::SEE_OTHER).header(LOCATION, case)
        } else if path == "/307" {
            let case = "/target/307";
            body_str = case.to_owned();
            res.status(StatusCode::TEMPORARY_REDIRECT)
                .header(LOCATION, case)
        } else if path == "/308" {
            let case = "/target/308";
            body_str = case.to_owned();
            res.status(StatusCode::PERMANENT_REDIRECT)
                .header(LOCATION, case)
        } else {
            body_str = format!("{path}/final");
            res.status(StatusCode::OK)
        };
        Ok::<_, Infallible>(res.body(body_str).unwrap())
    }

    // TOOD: adapt + enable once we did Uri rework
    // #[tokio::test]
    // async fn test_resolve_uri_unicode() {
    //     let base = Uri::from_static("https://example.com/api");
    //     // Case 1: Unicode in path
    //     let relative = "/café";
    //     let resolved = resolve_uri(relative, &base);
    //     assert!(resolved.is_some(), "Should resolve URI with unicode path");
    //     assert_eq!(
    //         resolved.unwrap().to_string(),
    //         "https://example.com/caf%C3%A9"
    //     );

    //     // Case 2: IDNA (Unicode in domain)
    //     let relative_domain = "https://münchen.com/";
    //     let resolved_domain = resolve_uri(relative_domain, &base);
    //     assert!(
    //         resolved_domain.is_some(),
    //         "Should resolve URI with unicode domain"
    //     );
    //     // München is encoded as punycode: xn--mnchen-3ya
    //     assert_eq!(
    //         resolved_domain.unwrap().to_string(),
    //         "https://xn--mnchen-3ya.com/"
    //     );
    // }
}
