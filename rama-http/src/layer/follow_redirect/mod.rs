//! Middleware for following redirections.
//!
//! # Overview
//!
//! The [`FollowRedirect`] middleware retries requests with the inner [`Service`] to follow HTTP
//! redirections.
//!
//! The middleware tries to clone the original [`Request`] when making a redirected request.
//! The request body cannot always be cloned. When the original body is
//! known to be empty by [`StreamingBody::size_hint`], the middleware uses the `Default`
//! implementation of the body type to create a new request body. If you know that the body can be
//! cloned in some way, you can tell the middleware to clone it by configuring a [`policy`].
//!
//! By default every attempt — the original request included — runs on its own
//! [`fork`][Request::fork_extensions_in_place] of the caller's request [`Extensions`]: each hop
//! reads everything the caller inserted, while what it (or any inner layer) inserts stays isolated
//! from the caller and from every other hop. Isolation is structural, not deep: an inherited value
//! is shared by handle, so interior mutation through it (an atomic, a lock) stays visible to the
//! caller and to every other hop. Only the entries a hop inserts itself are private to it.
//!
//! Hop 1 pays for that fork too, redirect or not — its inserts have already happened by the time a
//! `Location` arrives, so the isolation cannot be deferred until one is seen. It is one
//! [`Extensions::fork`] (tens of nanoseconds, and one extra level on an extension miss).
//!
//! [`Extensions::fork`]: rama_core::extensions::Extensions::fork
//!
//! # Layer placement
//!
//! Place [`FollowRedirectLayer`] as early — as far outward — in the stack as your use case allows:
//! in front of everything whose work depends on the request's target, e.g. proxy or route
//! selection, DNS overwrites, per-origin credentials or per-host limits.
//!
//! Such a layer placed _outside_ this middleware runs exactly once, for the original target, and
//! every hop then inherits the decision it made for a different host or resource: hop 2 to
//! `internal.corp` is routed by the proxy hop 1 picked for `public.example`. Placed _inside_, it is
//! consulted per hop and decides on that hop's real target.
//!
//! The same holds for the extensions themselves: an inner layer's inserts cannot leak between hops,
//! but a layer outside this middleware inserts into the caller's request store, which every hop —
//! cross-origin ones included — inherits and can read. rama's [`Extensions`] are append-only, so no
//! [`policy`] (including [`FilterCredentials`]) can strip them afterwards. Keeping origin-scoped
//! state away from a redirect target therefore takes both halves: inserted _inside_ this middleware
//! _and_ derived from the hop's own target. Inside alone only makes the decision re-decidable — a
//! layer that inserts the same value for every target (e.g. `HttpProxyAddressLayer`, which stamps
//! one configured proxy) hands that value to each hop regardless of where it points. When the value
//! is inserted by the caller, scope the value itself so it cannot authorize or configure an
//! unrelated redirect target.
//!
//! The `rama` CLI keeps [`AddAuthorizationLayer`] outside on purpose: it sets a header rather than
//! an extension, so [`FilterCredentials`] _can_ strip it on a cross-origin hop.
//!
//! Consulting a per-request decider on every hop does mean an attacker-controlled `Location` chain
//! costs N decisions instead of 1, bounded by the redirect [`policy`]'s own limit. That is the
//! correct trade: the alternative is routing hop N by hop 1's answer.
//!
//! Paired with [`retry`](crate::layer::retry) — which follows the same rules per attempt — keep this
//! middleware outermost, so a retry replays one hop instead of the entire redirect chain.
//!
//! [`AddAuthorizationLayer`]: crate::layer::auth::AddAuthorizationLayer
//! [`Extensions`]: rama_core::extensions::Extensions
//! [`FilterCredentials`]: policy::FilterCredentials
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
//! #     if req.uri().as_str() != dest {
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
//! assert_eq!(response.extensions().get_ref::<RequestUri>().unwrap().0.as_str(), "https://www.rust-lang.org/");
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
    extensions::{Extension, ExtensionsRef},
};
use rama_http_types::{
    HeaderMap,
    header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING},
};
use rama_net::uri::Uri;
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
        Self::with_policy(Standard::default())
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
    pub const fn with_policy(policy: P) -> Self {
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
#[derive(Debug, Clone)]
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

impl<S, P> FollowRedirect<S, P> {
    /// Create a new [`FollowRedirect`] with the given redirection [`Policy`].
    pub const fn with_policy(inner: S, policy: P) -> Self {
        Self { inner, policy }
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

        let mut policy = self.policy.clone();

        let mut body = BodyRepr::None;
        body.try_clone_from(&mut policy, req.body());

        // Hand every attempt — this first one included — its own child store, so a per-hop insert
        // can never leak into a later hop or back to the caller.
        let caller_extensions = req.fork_extensions_in_place();

        policy.on_request(&mut req);
        // Start the redirect template from what the policy actually sent on
        // hop 1, just as later hops carry their post-policy headers forward.
        let mut headers = req.headers().clone();

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
                        req.set_extensions(caller_extensions.fork());
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
///
/// [`Extensions`]: rama_core::extensions::Extensions
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
    use parking_lot::Mutex;
    use rama_core::Layer;
    use rama_core::extensions::ExtensionsRef;
    use rama_core::service::service_fn;
    use std::{convert::Infallible, sync::Arc};

    #[test]
    fn layer_debug_includes_policy() {
        assert_eq!(
            format!("{:?}", FollowRedirectLayer::with_policy(Action::Follow)),
            "FollowRedirectLayer { policy: Follow }"
        );
    }

    #[test]
    fn body_representation_preserves_clone_refusal_and_empty_state() {
        let mut none = BodyRepr::<Body>::None;
        assert!(none.take().is_none());

        let mut empty = BodyRepr::<Body>::Empty;
        assert!(empty.take().is_some());
        assert!(empty.take().is_some());

        let mut policy = Action::Follow;
        assert!(
            clone_body::<_, _, Infallible>(&mut policy, &Body::from("not cloneable")).is_none()
        );
        assert!(clone_body::<_, _, Infallible>(&mut policy, &Body::empty()).is_some());
    }

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
            res.extensions().get_ref::<RequestUri>().unwrap().0.as_str(),
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
            res.extensions().get_ref::<RequestUri>().unwrap().0.as_str(),
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
            res.extensions().get_ref::<RequestUri>().unwrap().0.as_str(),
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
    async fn final_hop_reads_the_callers_extensions() {
        let svc = FollowRedirectLayer::new().into_layer(service_fn(handle_marker));
        let req = Request::builder()
            .uri("http://example.com/3")
            .body(Body::empty())
            .unwrap();
        req.extensions().insert(Marker(7));
        let res = svc.serve(req).await.unwrap();
        // A fork reads through to its parent, so every hop still sees the caller's extensions.
        assert_eq!(res.extensions().get_ref::<Marker>(), Some(&Marker(7)));
    }

    #[tokio::test]
    async fn fork_reads_the_callers_extensions_on_every_hop() {
        let hops = Arc::new(Mutex::new(Vec::new()));
        let svc = FollowRedirectLayer::new().into_layer(service_fn({
            let hops = hops.clone();
            move |req: Request<Body>| {
                hops.lock()
                    .push(req.extensions().get_ref::<Marker>().cloned());
                handle(req)
            }
        }));
        let req = Request::builder()
            .uri("http://example.com/2")
            .body(Body::empty())
            .unwrap();
        req.extensions().insert(Marker(7));

        svc.serve(req).await.unwrap();
        assert_eq!(
            hops.lock().as_slice(),
            [Some(Marker(7)), Some(Marker(7)), Some(Marker(7))],
        );
    }

    /// A policy that stamps a fresh `Marker` in `on_request` unless the request already carries one
    /// — the shape of an idempotent per-request preparation step.
    #[derive(Debug, Clone, Default)]
    struct StampingPolicy(u32);

    impl<B, E> Policy<B, E> for StampingPolicy {
        fn redirect(&mut self, _: &Attempt<'_>) -> Result<Action, E> {
            Ok(Action::Follow)
        }

        fn on_request(&mut self, req: &mut Request<B>) {
            if !req.extensions().contains::<Marker>() {
                req.extensions().insert(Marker(self.0));
                self.0 += 1;
            }
        }
    }

    #[tokio::test]
    async fn policy_on_request_inserts_stay_per_hop() {
        // `on_request` runs after the hop's store is forked, so its inserts are per-hop too: hop 2
        // gets its own stamp rather than inheriting hop 1's, and the caller's store never sees one.
        let hops = Arc::new(Mutex::new(Vec::new()));
        let svc =
            FollowRedirectLayer::with_policy(StampingPolicy::default()).into_layer(service_fn({
                let hops = hops.clone();
                move |req: Request<Body>| {
                    hops.lock()
                        .push(req.extensions().get_ref::<Marker>().cloned());
                    handle(req)
                }
            }));
        let req = Request::builder()
            .uri("http://example.com/2")
            .body(Body::empty())
            .unwrap();
        let caller_extensions = req.extensions().clone();

        svc.serve(req).await.unwrap();
        assert_eq!(
            hops.lock().as_slice(),
            [Some(Marker(0)), Some(Marker(1)), Some(Marker(2))],
        );
        assert!(!caller_extensions.contains::<Marker>());
    }

    #[derive(Debug, Clone, Default)]
    struct RemoveHeaderOnce(bool);

    impl<B, E> Policy<B, E> for RemoveHeaderOnce {
        fn redirect(&mut self, _: &Attempt<'_>) -> Result<Action, E> {
            Ok(Action::Follow)
        }

        fn on_request(&mut self, req: &mut Request<B>) {
            if !self.0 {
                req.headers_mut().remove("x-remove-on-first-hop");
                self.0 = true;
            }
        }
    }

    #[tokio::test]
    async fn first_hop_policy_header_changes_are_carried_forward() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let svc =
            FollowRedirectLayer::with_policy(RemoveHeaderOnce::default()).into_layer(service_fn({
                let seen = seen.clone();
                move |req: Request<Body>| {
                    seen.lock()
                        .push(req.headers().contains_key("x-remove-on-first-hop"));
                    handle(req)
                }
            }));
        let req = Request::builder()
            .uri("http://example.com/1")
            .header("x-remove-on-first-hop", "yes")
            .body(Body::empty())
            .unwrap();

        svc.serve(req).await.unwrap();
        assert_eq!(seen.lock().as_slice(), [false, false]);
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
            res.extensions().get_ref::<RequestUri>().unwrap().0.as_str(),
            "http://b.example.com/final"
        );
    }

    /// A layer that derives a `Route` from the request target, unless the current attempt already
    /// carries one — the shape of every target-dependent decider (proxy/route selection, DNS
    /// overwrite, ...). It records what each attempt ended up with.
    #[derive(Debug, Clone)]
    struct RouteDecider<S> {
        inner: S,
        seen: Arc<Mutex<Vec<String>>>,
    }

    #[derive(Clone, Debug, PartialEq, rama_core::extensions::Extension)]
    struct Route(String);

    impl<S, B> Service<Request<B>> for RouteDecider<S>
    where
        S: Service<Request<B>>,
        B: Send + 'static,
    {
        type Output = S::Output;
        type Error = S::Error;

        async fn serve(&self, req: Request<B>) -> Result<Self::Output, Self::Error> {
            if req.extensions().get_ref::<Route>().is_none() {
                let host = req.uri().host_str().unwrap_or_default().into_owned();
                req.extensions().insert(Route(host));
            }
            self.seen
                .lock()
                .push(req.extensions().get_ref::<Route>().unwrap().0.clone());
            self.inner.serve(req).await
        }
    }

    #[tokio::test]
    async fn inner_per_hop_decision_does_not_leak_into_the_next_hop() {
        // Regression: an inner decider must be consulted with *this* hop's target, never with the
        // route hop 1 picked for a different host.
        let seen = Arc::new(Mutex::new(Vec::new()));
        let svc = FollowRedirectLayer::new().into_layer(RouteDecider {
            inner: service_fn(handle_cookie_chain),
            seen: seen.clone(),
        });
        let req = Request::builder()
            .uri("http://a.example.com/")
            .body(Body::empty())
            .unwrap();

        svc.serve(req).await.unwrap();
        assert_eq!(
            seen.lock().as_slice(),
            ["a.example.com", "b.example.com", "b.example.com"],
        );
    }

    #[tokio::test]
    async fn outer_per_hop_decision_is_inherited_by_every_hop() {
        // The flip side of the above, and why placement matters: a decider *outside* the middleware
        // runs once, and its verdict for the original target is what every hop is routed by.
        let seen = Arc::new(Mutex::new(Vec::new()));
        let svc = RouteDecider {
            inner: FollowRedirectLayer::new().into_layer(service_fn({
                let seen = seen.clone();
                move |req: Request<Body>| {
                    seen.lock()
                        .push(req.extensions().get_ref::<Route>().unwrap().0.clone());
                    handle_cookie_chain(req)
                }
            })),
            seen: Arc::new(Mutex::new(Vec::new())),
        };
        let req = Request::builder()
            .uri("http://a.example.com/")
            .body(Body::empty())
            .unwrap();

        svc.serve(req).await.unwrap();
        assert_eq!(
            seen.lock().as_slice(),
            ["a.example.com", "a.example.com", "a.example.com"],
        );
    }

    #[tokio::test]
    async fn hop_inserts_never_reach_the_callers_request_store() {
        let svc = FollowRedirectLayer::new().into_layer(RouteDecider {
            inner: service_fn(handle_cookie_chain),
            seen: Arc::new(Mutex::new(Vec::new())),
        });
        let req = Request::builder()
            .uri("http://a.example.com/")
            .body(Body::empty())
            .unwrap();
        let caller_extensions = req.extensions().clone();

        svc.serve(req).await.unwrap();
        assert!(
            !caller_extensions.contains::<Route>(),
            "a hop's insert leaked back into the caller's request extensions",
        );
    }

    #[tokio::test]
    async fn response_still_exposes_the_final_hops_extensions() {
        // Isolating the request store does not hide per-hop metadata from the caller: a response
        // forks from the request that produced it (as the h1/h2 client stacks do), so the final
        // hop's chain — and the caller's own extensions — remain readable through the response.
        let svc = FollowRedirectLayer::new().into_layer(RouteDecider {
            inner: service_fn(async |req: Request<Body>| {
                let request_extensions = req.extensions().clone();
                let mut res = handle_cookie_chain(req).await?;
                res.set_extensions(request_extensions.fork());
                Ok::<_, Infallible>(res)
            }),
            seen: Arc::new(Mutex::new(Vec::new())),
        });
        let req = Request::builder()
            .uri("http://a.example.com/")
            .body(Body::empty())
            .unwrap();
        req.extensions().insert(Marker(7));

        let res = svc.serve(req).await.unwrap();
        assert_eq!(
            res.extensions().get_ref::<Route>(),
            Some(&Route("b.example.com".to_owned())),
        );
        assert_eq!(res.extensions().get_ref::<Marker>(), Some(&Marker(7)));
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
                res.extensions().get_ref::<RequestUri>().unwrap().0.as_str(),
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
                res.extensions().get_ref::<RequestUri>().unwrap().0.as_str(),
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
                res.extensions().get_ref::<RequestUri>().unwrap().0.as_str(),
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
                res.extensions().get_ref::<RequestUri>().unwrap().0.as_str(),
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
                res.extensions().get_ref::<RequestUri>().unwrap().0.as_str(),
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
                res.extensions().get_ref::<RequestUri>().unwrap().0.as_str(),
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
                res.extensions().get_ref::<RequestUri>().unwrap().0.as_str(),
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
                res.extensions().get_ref::<RequestUri>().unwrap().0.as_str(),
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
                res.extensions().get_ref::<RequestUri>().unwrap().0.as_str(),
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
                res.extensions().get_ref::<RequestUri>().unwrap().0.as_str(),
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
