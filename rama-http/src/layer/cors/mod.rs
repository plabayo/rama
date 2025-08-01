//! Middleware which adds headers for [CORS][mdn].
//!
//! # Example
//!
//! ```
//! use std::convert::Infallible;
//! use rama_core::bytes::Bytes;
//!
//! use rama_http::{Body, Request, Response, Method, header};
//! use rama_http::layer::cors::{Any, CorsLayer};
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Service, Layer};
//!
//! async fn handle(request: Request) -> Result<Response, Infallible> {
//!     Ok(Response::new(Body::default()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let cors = CorsLayer::new()
//!     // allow `GET` and `POST` when accessing the resource
//!     .allow_methods([Method::GET, Method::POST])
//!     // allow requests from any origin
//!     .allow_origin(Any);
//!
//! let mut service = cors.into_layer(service_fn(handle));
//!
//! let request = Request::builder()
//!     .header(header::ORIGIN, "https://example.com")
//!     .body(Body::default())
//!     .unwrap();
//!
//! let response = service
//!     .serve(Context::default(), request)
//!     .await?;
//!
//! assert_eq!(
//!     response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
//!     "*",
//! );
//! # Ok(())
//! # }
//! ```
//!
//! [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

#![allow(clippy::enum_variant_names)]

use crate::dep::http::{
    HeaderMap, HeaderValue, Method, Request, Response,
    header::{self, HeaderName},
};
use rama_core::{
    Context, Layer, Service,
    bytes::{BufMut, BytesMut},
};
use rama_utils::macros::define_inner_service_accessors;
use std::{array, fmt, mem};

mod allow_credentials;
mod allow_headers;
mod allow_methods;
mod allow_origin;
mod allow_private_network;
mod expose_headers;
mod max_age;
mod vary;

#[cfg(test)]
mod tests;

#[doc(inline)]
pub use self::{
    allow_credentials::AllowCredentials, allow_headers::AllowHeaders, allow_methods::AllowMethods,
    allow_origin::AllowOrigin, allow_private_network::AllowPrivateNetwork,
    expose_headers::ExposeHeaders, max_age::MaxAge, vary::Vary,
};

/// Layer that applies the [`Cors`] middleware which adds headers for [CORS][mdn].
///
/// See the [module docs](crate::layer::cors) for an example.
///
/// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
#[derive(Debug, Clone)]
#[must_use]
pub struct CorsLayer {
    allow_credentials: AllowCredentials,
    allow_headers: AllowHeaders,
    allow_methods: AllowMethods,
    allow_origin: AllowOrigin,
    allow_private_network: AllowPrivateNetwork,
    expose_headers: ExposeHeaders,
    max_age: MaxAge,
    vary: Vary,
    handle_options_request: bool,
}

#[allow(clippy::declare_interior_mutable_const)]
const WILDCARD: HeaderValue = HeaderValue::from_static("*");

impl CorsLayer {
    /// Create a new `CorsLayer`.
    ///
    /// No headers are sent by default. Use the builder methods to customize
    /// the behavior.
    ///
    /// You need to set at least an allowed origin for browsers to make
    /// successful cross-origin requests to your service.
    pub fn new() -> Self {
        Self {
            allow_credentials: Default::default(),
            allow_headers: Default::default(),
            allow_methods: Default::default(),
            allow_origin: Default::default(),
            allow_private_network: Default::default(),
            expose_headers: Default::default(),
            max_age: Default::default(),
            vary: Default::default(),
            handle_options_request: false,
        }
    }

    /// A permissive configuration:
    ///
    /// - All request headers allowed.
    /// - All methods allowed.
    /// - All origins allowed.
    /// - All headers exposed.
    pub fn permissive() -> Self {
        Self::new()
            .allow_headers(Any)
            .allow_methods(Any)
            .allow_origin(Any)
            .expose_headers(Any)
    }

    /// A very permissive configuration:
    ///
    /// - **Credentials allowed.**
    /// - The method received in `Access-Control-Request-Method` is sent back
    ///   as an allowed method.
    /// - The origin of the preflight request is sent back as an allowed origin.
    /// - The header names received in `Access-Control-Request-Headers` are sent
    ///   back as allowed headers.
    /// - No headers are currently exposed, but this may change in the future.
    pub fn very_permissive() -> Self {
        Self::new()
            .allow_credentials(true)
            .allow_headers(AllowHeaders::mirror_request())
            .allow_methods(AllowMethods::mirror_request())
            .allow_origin(AllowOrigin::mirror_request())
    }

    /// Set the [`Access-Control-Allow-Credentials`][mdn] header.
    ///
    /// ```
    /// use rama_http::layer::cors::CorsLayer;
    ///
    /// let layer = CorsLayer::new().allow_credentials(true);
    /// ```
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
    pub fn allow_credentials<T>(mut self, allow_credentials: T) -> Self
    where
        T: Into<AllowCredentials>,
    {
        self.allow_credentials = allow_credentials.into();
        self
    }

    /// Set the value of the [`Access-Control-Allow-Headers`][mdn] header.
    ///
    /// ```
    /// use rama_http::layer::cors::CorsLayer;
    /// use rama_http::header::{AUTHORIZATION, ACCEPT};
    ///
    /// let layer = CorsLayer::new().allow_headers([AUTHORIZATION, ACCEPT]);
    /// ```
    ///
    /// All headers can be allowed with
    ///
    /// ```
    /// use rama_http::layer::cors::{Any, CorsLayer};
    ///
    /// let layer = CorsLayer::new().allow_headers(Any);
    /// ```
    ///
    /// You can also use an async closure:
    ///
    /// ```
    /// # #[derive(Clone)]
    /// # struct Client;
    /// # fn get_api_client() -> Client {
    /// #     Client
    /// # }
    /// # impl Client {
    /// #     async fn fetch_allowed_origins(&self) -> Vec<HeaderValue> {
    /// #         vec![HeaderValue::from_static("http://example.com")]
    /// #     }
    /// #     async fn fetch_allowed_origins_for_path(&self, _path: String) -> Vec<HeaderValue> {
    /// #         vec![HeaderValue::from_static("http://example.com")]
    /// #     }
    /// # }
    /// use rama_http::layer::cors::{CorsLayer, AllowOrigin};
    /// use rama_http::dep::http::{request::Parts as RequestParts, HeaderValue};
    ///
    /// let client = get_api_client();
    ///
    /// let layer = CorsLayer::new().allow_origin(AllowOrigin::async_predicate(
    ///     move |origin: HeaderValue, _request_parts: &RequestParts| {
    ///         let client = client.clone();
    ///         async move {
    ///             // fetch list of origins that are allowed
    ///             let origins = client.fetch_allowed_origins().await;
    ///             origins.contains(&origin)
    ///         }
    ///     },
    /// ));
    ///
    /// let client = get_api_client();
    ///
    /// // if using &RequestParts, make sure all the values are owned
    /// // before passing into the future
    /// let layer = CorsLayer::new().allow_origin(AllowOrigin::async_predicate(
    ///     move |origin: HeaderValue, parts: &RequestParts| {
    ///         let client = client.clone();
    ///         let path = parts.uri.path().to_owned();
    ///
    ///         async move {
    ///             // fetch list of origins that are allowed for this path
    ///             let origins = client.fetch_allowed_origins_for_path(path).await;
    ///             origins.contains(&origin)
    ///         }
    ///     },
    /// ));
    /// ```
    ///
    /// Note that multiple calls to this method will override any previous
    /// calls.
    ///
    /// Also note that `Access-Control-Allow-Headers` is required for requests that have
    /// `Access-Control-Request-Headers`.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers
    pub fn allow_headers<T>(mut self, headers: T) -> Self
    where
        T: Into<AllowHeaders>,
    {
        self.allow_headers = headers.into();
        self
    }

    /// Set the value of the [`Access-Control-Max-Age`][mdn] header.
    ///
    /// ```
    /// use std::time::Duration;
    /// use rama_http::layer::cors::CorsLayer;
    ///
    /// let layer = CorsLayer::new().max_age(Duration::from_secs(60) * 10);
    /// ```
    ///
    /// By default the header will not be set which disables caching and will
    /// require a preflight call for all requests.
    ///
    /// Note that each browser has a maximum internal value that takes
    /// precedence when the Access-Control-Max-Age is greater. For more details
    /// see [mdn].
    ///
    /// If you need more flexibility, you can use supply a function which can
    /// dynamically decide the max-age based on the origin and other parts of
    /// each preflight request:
    ///
    /// ```
    /// # struct MyServerConfig { cors_max_age: Duration }
    /// use std::time::Duration;
    ///
    /// use rama_http::dep::http::{request::Parts as RequestParts, HeaderValue};
    /// use rama_http::layer::cors::{CorsLayer, MaxAge};
    ///
    /// let layer = CorsLayer::new().max_age(MaxAge::dynamic(
    ///     |_origin: &HeaderValue, parts: &RequestParts| -> Duration {
    ///         // Let's say you want to be able to reload your config at
    ///         // runtime and have another middleware that always inserts
    ///         // the current config into the request extensions
    ///         let config = parts.extensions.get::<MyServerConfig>().unwrap();
    ///         config.cors_max_age
    ///     },
    /// ));
    /// ```
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age
    pub fn max_age<T>(mut self, max_age: T) -> Self
    where
        T: Into<MaxAge>,
    {
        self.max_age = max_age.into();
        self
    }

    /// Set the value of the [`Access-Control-Allow-Methods`][mdn] header.
    ///
    /// ```
    /// use rama_http::layer::cors::CorsLayer;
    /// use rama_http::Method;
    ///
    /// let layer = CorsLayer::new().allow_methods([Method::GET, Method::POST]);
    /// ```
    ///
    /// All methods can be allowed with
    ///
    /// ```
    /// use rama_http::layer::cors::{Any, CorsLayer};
    ///
    /// let layer = CorsLayer::new().allow_methods(Any);
    /// ```
    ///
    /// Note that multiple calls to this method will override any previous
    /// calls.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods
    pub fn allow_methods<T>(mut self, methods: T) -> Self
    where
        T: Into<AllowMethods>,
    {
        self.allow_methods = methods.into();
        self
    }

    /// Set the value of the [`Access-Control-Allow-Origin`][mdn] header.
    ///
    /// ```
    /// use rama_http::HeaderValue;
    /// use rama_http::layer::cors::CorsLayer;
    ///
    /// let layer = CorsLayer::new().allow_origin(
    ///     "http://example.com".parse::<HeaderValue>().unwrap(),
    /// );
    /// ```
    ///
    /// Multiple origins can be allowed with
    ///
    /// ```
    /// use rama_http::layer::cors::CorsLayer;
    ///
    /// let origins = [
    ///     "http://example.com".parse().unwrap(),
    ///     "http://api.example.com".parse().unwrap(),
    /// ];
    ///
    /// let layer = CorsLayer::new().allow_origin(origins);
    /// ```
    ///
    /// All origins can be allowed with
    ///
    /// ```
    /// use rama_http::layer::cors::{Any, CorsLayer};
    ///
    /// let layer = CorsLayer::new().allow_origin(Any);
    /// ```
    ///
    /// You can also use a closure
    ///
    /// ```
    /// use rama_http::layer::cors::{CorsLayer, AllowOrigin};
    /// use rama_http::dep::http::{request::Parts as RequestParts, HeaderValue};
    ///
    /// let layer = CorsLayer::new().allow_origin(AllowOrigin::predicate(
    ///     |origin: &HeaderValue, _request_parts: &RequestParts| {
    ///         origin.as_bytes().ends_with(b".rust-lang.org")
    ///     },
    /// ));
    /// ```
    ///
    /// Note that multiple calls to this method will override any previous
    /// calls.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
    pub fn allow_origin<T>(mut self, origin: T) -> Self
    where
        T: Into<AllowOrigin>,
    {
        self.allow_origin = origin.into();
        self
    }

    /// Set the value of the [`Access-Control-Expose-Headers`][mdn] header.
    ///
    /// ```
    /// use rama_http::layer::cors::CorsLayer;
    /// use rama_http::header::CONTENT_ENCODING;
    ///
    /// let layer = CorsLayer::new().expose_headers([CONTENT_ENCODING]);
    /// ```
    ///
    /// All headers can be allowed with
    ///
    /// ```
    /// use rama_http::layer::cors::{Any, CorsLayer};
    ///
    /// let layer = CorsLayer::new().expose_headers(Any);
    /// ```
    ///
    /// Note that multiple calls to this method will override any previous
    /// calls.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Expose-Headers
    pub fn expose_headers<T>(mut self, headers: T) -> Self
    where
        T: Into<ExposeHeaders>,
    {
        self.expose_headers = headers.into();
        self
    }

    /// Set the value of the [`Access-Control-Allow-Private-Network`][wicg] header.
    ///
    /// ```
    /// use rama_http::layer::cors::CorsLayer;
    ///
    /// let layer = CorsLayer::new().allow_private_network(true);
    /// ```
    ///
    /// [wicg]: https://wicg.github.io/private-network-access/
    pub fn allow_private_network<T>(mut self, allow_private_network: T) -> Self
    where
        T: Into<AllowPrivateNetwork>,
    {
        self.allow_private_network = allow_private_network.into();
        self
    }

    /// Set the value(s) of the [`Vary`][mdn] header.
    ///
    /// In contrast to the other headers, this one has a non-empty default of
    /// [`preflight_request_headers()`].
    ///
    /// You only need to set this is you want to remove some of these defaults,
    /// or if you use a closure for one of the other headers and want to add a
    /// vary header accordingly.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary
    pub fn vary<T>(mut self, headers: T) -> Self
    where
        T: Into<Vary>,
    {
        self.vary = headers.into();
        self
    }

    /// Handle OPTIONS request with the inner service.
    ///
    /// By default it is not passed on to the inner service,
    /// and instead just returned with a 200 OK (empty body).
    ///
    /// NOTE that this does not stop the response headers from being added,
    /// it only defines who "creates" the response, the modification happens regardless.
    pub fn handle_options_request(mut self) -> Self {
        self.handle_options_request = true;
        self
    }
}

/// Represents a wildcard value (`*`) used with some CORS headers such as
/// [`CorsLayer::allow_methods`].
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct Any;

/// Represents a wildcard value (`*`) used with some CORS headers such as
/// [`CorsLayer::allow_methods`].
#[deprecated = "Use Any as a unit struct literal instead"]
pub fn any() -> Any {
    Any
}

fn separated_by_commas<I>(mut iter: I) -> Option<HeaderValue>
where
    I: Iterator<Item = HeaderValue>,
{
    match iter.next() {
        Some(fst) => {
            let mut result = BytesMut::from(fst.as_bytes());
            for val in iter {
                result.reserve(val.len() + 1);
                result.put_u8(b',');
                result.extend_from_slice(val.as_bytes());
            }

            Some(HeaderValue::from_maybe_shared(result.freeze()).unwrap())
        }
        None => None,
    }
}

impl Default for CorsLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for CorsLayer {
    type Service = Cors<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ensure_usable_cors_rules(self);
        Cors {
            inner,
            layer: self.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ensure_usable_cors_rules(&self);
        Cors { inner, layer: self }
    }
}

/// Middleware which adds headers for [CORS][mdn].
///
/// See the [module docs](crate::layer::cors) for an example.
///
/// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
pub struct Cors<S> {
    inner: S,
    layer: CorsLayer,
}

impl<S: fmt::Debug> fmt::Debug for Cors<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Cors")
            .field("inner", &self.inner)
            .field("layer", &self.layer)
            .finish()
    }
}

impl<S: Clone> Clone for Cors<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            layer: self.layer.clone(),
        }
    }
}

impl<S> Cors<S> {
    /// Create a new `Cors`.
    ///
    /// See [`CorsLayer::new`] for more details.
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            layer: CorsLayer::new(),
        }
    }

    /// A permissive configuration.
    ///
    /// See [`CorsLayer::permissive`] for more details.
    pub fn permissive(inner: S) -> Self {
        Self {
            inner,
            layer: CorsLayer::permissive(),
        }
    }

    /// A very permissive configuration.
    ///
    /// See [`CorsLayer::very_permissive`] for more details.
    pub fn very_permissive(inner: S) -> Self {
        Self {
            inner,
            layer: CorsLayer::very_permissive(),
        }
    }

    define_inner_service_accessors!();

    /// Set the [`Access-Control-Allow-Credentials`][mdn] header.
    ///
    /// See [`CorsLayer::allow_credentials`] for more details.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
    #[must_use]
    pub fn allow_credentials<T>(self, allow_credentials: T) -> Self
    where
        T: Into<AllowCredentials>,
    {
        self.map_layer(|layer| layer.allow_credentials(allow_credentials))
    }

    /// Set the value of the [`Access-Control-Allow-Headers`][mdn] header.
    ///
    /// See [`CorsLayer::allow_headers`] for more details.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers
    #[must_use]
    pub fn allow_headers<T>(self, headers: T) -> Self
    where
        T: Into<AllowHeaders>,
    {
        self.map_layer(|layer| layer.allow_headers(headers))
    }

    /// Set the value of the [`Access-Control-Max-Age`][mdn] header.
    ///
    /// See [`CorsLayer::max_age`] for more details.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age
    #[must_use]
    pub fn max_age<T>(self, max_age: T) -> Self
    where
        T: Into<MaxAge>,
    {
        self.map_layer(|layer| layer.max_age(max_age))
    }

    /// Set the value of the [`Access-Control-Allow-Methods`][mdn] header.
    ///
    /// See [`CorsLayer::allow_methods`] for more details.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods
    #[must_use]
    pub fn allow_methods<T>(self, methods: T) -> Self
    where
        T: Into<AllowMethods>,
    {
        self.map_layer(|layer| layer.allow_methods(methods))
    }

    /// Set the value of the [`Access-Control-Allow-Origin`][mdn] header.
    ///
    /// See [`CorsLayer::allow_origin`] for more details.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
    #[must_use]
    pub fn allow_origin<T>(self, origin: T) -> Self
    where
        T: Into<AllowOrigin>,
    {
        self.map_layer(|layer| layer.allow_origin(origin))
    }

    /// Set the value of the [`Access-Control-Expose-Headers`][mdn] header.
    ///
    /// See [`CorsLayer::expose_headers`] for more details.
    ///
    /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Expose-Headers
    #[must_use]
    pub fn expose_headers<T>(self, headers: T) -> Self
    where
        T: Into<ExposeHeaders>,
    {
        self.map_layer(|layer| layer.expose_headers(headers))
    }

    /// Set the value of the [`Access-Control-Allow-Private-Network`][wicg] header.
    ///
    /// See [`CorsLayer::allow_private_network`] for more details.
    ///
    /// [wicg]: https://wicg.github.io/private-network-access/
    #[must_use]
    pub fn allow_private_network<T>(self, allow_private_network: T) -> Self
    where
        T: Into<AllowPrivateNetwork>,
    {
        self.map_layer(|layer| layer.allow_private_network(allow_private_network))
    }

    #[must_use]
    fn map_layer<F>(mut self, f: F) -> Self
    where
        F: FnOnce(CorsLayer) -> CorsLayer,
    {
        self.layer = f(self.layer);
        self
    }
}

impl<S, State, ReqBody, ResBody> Service<State, Request<ReqBody>> for Cors<S>
where
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
    State: Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let (parts, body) = req.into_parts();
        let origin = parts.headers.get(&header::ORIGIN);

        let mut headers = HeaderMap::new();

        // These headers are applied to both preflight and subsequent regular CORS requests:
        // https://fetch.spec.whatwg.org/#http-responses
        headers.extend(self.layer.allow_credentials.to_header(origin, &parts));
        headers.extend(self.layer.allow_private_network.to_header(origin, &parts));
        headers.extend(self.layer.vary.to_header());

        let allow_origin_future = self.layer.allow_origin.to_future(origin, &parts);
        headers.extend(allow_origin_future.await);

        // Return results immediately upon preflight request
        if parts.method == Method::OPTIONS {
            // These headers are applied only to preflight requests
            headers.extend(self.layer.allow_methods.to_header(&parts));
            headers.extend(self.layer.allow_headers.to_header(&parts));
            headers.extend(self.layer.max_age.to_header(origin, &parts));

            Ok(if self.layer.handle_options_request {
                let req = Request::from_parts(parts, body);

                let mut response: Response<ResBody> = self.inner.serve(ctx, req).await?;
                let response_headers = response.headers_mut();

                // vary header can have multiple values, don't overwrite
                // previously-set value(s).
                if let Some(vary) = headers.remove(header::VARY) {
                    response_headers.append(header::VARY, vary);
                }
                // extend will overwrite previous headers of remaining names
                response_headers.extend(headers.drain());

                response
            } else {
                let mut response = Response::new(ResBody::default());
                mem::swap(response.headers_mut(), &mut headers);

                response
            })
        } else {
            // This header is applied only to non-preflight requests
            headers.extend(self.layer.expose_headers.to_header(&parts));

            let req = Request::from_parts(parts, body);

            let mut response: Response<ResBody> = self.inner.serve(ctx, req).await?;
            let response_headers = response.headers_mut();

            // vary header can have multiple values, don't overwrite
            // previously-set value(s).
            if let Some(vary) = headers.remove(header::VARY) {
                response_headers.append(header::VARY, vary);
            }
            // extend will overwrite previous headers of remaining names
            response_headers.extend(headers.drain());

            Ok(response)
        }
    }
}

fn ensure_usable_cors_rules(layer: &CorsLayer) {
    if layer.allow_credentials.is_true() {
        assert!(
            !layer.allow_headers.is_wildcard(),
            "Invalid CORS configuration: Cannot combine `Access-Control-Allow-Credentials: true` \
             with `Access-Control-Allow-Headers: *`"
        );

        assert!(
            !layer.allow_methods.is_wildcard(),
            "Invalid CORS configuration: Cannot combine `Access-Control-Allow-Credentials: true` \
             with `Access-Control-Allow-Methods: *`"
        );

        assert!(
            !layer.allow_origin.is_wildcard(),
            "Invalid CORS configuration: Cannot combine `Access-Control-Allow-Credentials: true` \
             with `Access-Control-Allow-Origin: *`"
        );

        assert!(
            !layer.expose_headers.is_wildcard(),
            "Invalid CORS configuration: Cannot combine `Access-Control-Allow-Credentials: true` \
             with `Access-Control-Expose-Headers: *`"
        );
    }
}

/// Returns an iterator over the three request headers that may be involved in a CORS preflight request.
///
/// This is the default set of header names returned in the `vary` header
pub fn preflight_request_headers() -> impl Iterator<Item = HeaderName> {
    #[allow(deprecated)] // Can be changed when MSRV >= 1.53
    array::IntoIter::new([
        header::ORIGIN,
        header::ACCESS_CONTROL_REQUEST_METHOD,
        header::ACCESS_CONTROL_REQUEST_HEADERS,
    ])
}
