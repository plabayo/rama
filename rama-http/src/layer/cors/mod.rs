//! Middleware which adds headers for [CORS][mdn].
//!
//! [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

use crate::{
    HeaderMap, HeaderValue, Method, Request, Response,
    header::{self},
};
use rama_core::error::BoxError;
use rama_core::{Layer, Service};
use rama_http_headers::{
    AccessControlAllowHeaders, AccessControlAllowMethods, AccessControlExposeHeaders,
    AccessControlMaxAge, HeaderMapExt, Vary, util::Seconds,
};
use rama_http_types::{body::OptionalBody, request::Parts as RequestParts};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};
use std::{mem, sync::Arc};

mod allow_credentials;
mod allow_headers;
mod allow_methods;
mod allow_origin;
mod allow_private_network;
mod max_age;

#[cfg(test)]
mod tests;

use self::{
    allow_credentials::AllowCredentials, allow_headers::AllowHeaders, allow_methods::AllowMethods,
    allow_origin::AllowOrigin, allow_private_network::AllowPrivateNetwork, max_age::MaxAge,
};

/// Layer that applies the [`Cors`] middleware which adds headers for [CORS][mdn].
///
/// See the [module docs](crate::layer::cors) for an example.
///
/// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
#[derive(Debug, Clone)]
#[must_use]
pub struct CorsLayer {
    allow_credentials: Option<AllowCredentials>,
    allow_headers: Option<AllowHeaders>,
    allow_methods: Option<AllowMethods>,
    allow_origin: Option<AllowOrigin>,
    allow_private_network: Option<AllowPrivateNetwork>,
    expose_headers: Option<AccessControlExposeHeaders>,
    max_age: Option<MaxAge>,
    vary: Vary,
    handle_options_request: bool,
}

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
            allow_credentials: None,
            allow_headers: None,
            allow_methods: None,
            allow_origin: None,
            allow_private_network: None,
            expose_headers: None,
            max_age: None,
            vary: Vary::preflight_request_headers(),
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
        Self {
            allow_headers: Some(AllowHeaders::Const(AccessControlAllowHeaders::new_any())),
            allow_methods: Some(AllowMethods::Const(AccessControlAllowMethods::new_any())),
            allow_origin: Some(AllowOrigin::Any),
            expose_headers: Some(AccessControlExposeHeaders::new_any()),
            ..Self::new()
        }
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
        Self {
            allow_credentials: Some(AllowCredentials::Const),
            allow_headers: Some(AllowHeaders::MirrorRequest),
            allow_methods: Some(AllowMethods::MirrorRequest),
            allow_origin: Some(AllowOrigin::MirrorRequest),
            ..Self::new()
        }
    }

    fn is_allow_credentials_any(&self) -> bool {
        matches!(self.allow_credentials, Some(AllowCredentials::Const))
    }

    generate_set_and_with! {
        /// Always set the [`Access-Control-Allow-Credentials`][mdn] header.
        ///
        /// # Errors
        ///
        /// Errors in case any of the other CORS headers which
        /// support the wildcard value have been set to use it.
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
        pub fn allow_credentials(mut self) -> Result<Self, BoxError> {
            if self.allow_headers.as_ref().map(|v| v.is_any()).unwrap_or_default()
                || self.allow_methods.as_ref().map(|v| v.is_any()).unwrap_or_default()
                || self.allow_origin.as_ref().map(|v| v.is_any()).unwrap_or_default()
                || self.expose_headers.as_ref().map(|v| v.is_any()).unwrap_or_default() {
                return Err(BoxError::from("CORS combo error: allow credentials is not allowed if some of the wildcard-abled headers are set to use the wildcard value"));
            }
            self.allow_credentials = Some(AllowCredentials::Const);
            Ok(self)
        }
    }

    generate_set_and_with! {
        /// Set the [`Access-Control-Allow-Credentials`][mdn] header if predicate is satisfied.
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
        pub fn allow_credentials_if(
            mut self,
            predicate: impl Fn(&HeaderValue, &RequestParts) -> bool + Send + Sync + 'static
        ) -> Self {
            self.allow_credentials = Some(AllowCredentials::Predicate(Arc::new(predicate)));
            self
        }
    }

    generate_set_and_with! {
        /// Set the value of the [`Access-Control-Allow-Headers`][mdn] header.
        ///
        /// # Errors
        ///
        /// Errors in case credentials are allowed and the given header
        /// contains the wildcard value (`*`).
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers
        pub fn allow_headers(mut self, headers: AccessControlAllowHeaders) -> Result<Self, BoxError> {
            if headers.is_any() && self.is_allow_credentials_any() {
                return Err(BoxError::from("Invalid CORS configuration: Cannot combine `Access-Control-Allow-Credentials: true` with `Access-Control-Allow-Headers: *`"))
            }
            self.allow_headers = Some(AllowHeaders::Const(headers));
            Ok(self)
        }
    }

    generate_set_and_with! {
        /// Set the value of the [`Access-Control-Max-Age`][mdn] header.
        ///
        /// By default the header will not be set which disables caching and will
        /// require a preflight call for all requests.
        ///
        /// Note that each browser has a maximum internal value that takes
        /// precedence when the Access-Control-Max-Age is greater. For more details
        /// see [mdn].
        ///
        /// If you need more flexibility, you can use supply a function which can
        /// dynamically decide the optional max-age based on the origin and other parts of
        /// each preflight request.
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age
        pub fn max_age(mut self, header: AccessControlMaxAge) -> Self {
            self.max_age = Some(MaxAge::Const(header));
            self
        }
    }

    generate_set_and_with! {
        /// Set the [`Access-Control-Max-Age`][mdn] header if predicate is satisfied.
        ///
        /// See [`Self::with_max_age`] and [`Self::set_max_age`] for more information.
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age
        pub fn max_age_if(
            mut self,
            predicate: impl Fn(&HeaderValue, &RequestParts) -> Option<Seconds> + Send + Sync + 'static
        ) -> Self {
            self.max_age = Some(MaxAge::Predicate(Arc::new(predicate)));
            self
        }
    }

    generate_set_and_with! {
        /// Set the value of the [`Access-Control-Allow-Methods`][mdn] header.
        ///
        /// # Errors
        ///
        /// Errors in case credentials are allowed and the given header
        /// contains the wildcard value (`*`).
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods
        pub fn allow_methods(mut self, methods: AccessControlAllowMethods) -> Result<Self, BoxError> {
            if methods.is_any() && self.is_allow_credentials_any() {
                return Err(BoxError::from("Invalid CORS configuration: Cannot combine `Access-Control-Allow-Credentials: true` with `Access-Control-Allow-Methods: *`"))
            }
            self.allow_methods = Some(AllowMethods::Const(methods));
            Ok(self)
        }
    }

    generate_set_and_with! {
        /// Only set the [`Access-Control-Allow-Origin`][mdn] header with the wildcard value (`*`).
        ///
        /// # Errors
        ///
        /// Errors in case credentials are allowed.
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
        pub fn allow_origin_any(mut self) -> Result<Self, BoxError> {
            if self.is_allow_credentials_any() {
                return Err(BoxError::from("Invalid CORS configuration: Cannot combine `Access-Control-Allow-Credentials: true` with `Access-Control-Allow-Origin: *`"))
            }
            self.allow_origin = Some(AllowOrigin::Any);
            Ok(self)
        }
    }

    generate_set_and_with! {
        /// Only set the [`Access-Control-Allow-Origin`][mdn] header with the "null" value when that is the origin.
        ///
        /// Note: The value `null` should not be used.
        /// It may seem safe to return `Access-Control-Allow-Origin: "null"`;
        /// however, the origin of resources that use a non-hierarchical scheme
        /// (such as `data:` or `file:`) and sandboxed documents is serialized as `null`.
        /// Many browsers will grant such documents access to a response with an
        /// `Access-Control-Allow-Origin: null` header, and any origin can create a
        /// hostile document with a `null` origin. Therefore, the `null` value for the
        /// `Access-Control-Allow-Origin` header should be avoided
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
        pub fn allow_origin_if_null(mut self) -> Self {
            self.allow_origin = Some(AllowOrigin::Null);
            self
        }
    }

    generate_set_and_with! {
        /// Set the value of the [`Access-Control-Allow-Origin`][mdn] header if the predicate satisfied.
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
        pub fn allow_origin_if(
            mut self,
            predicate: impl Fn(&HeaderValue, &RequestParts) -> bool + Send + Sync + 'static
        ) -> Self {
            self.allow_origin = Some(AllowOrigin::Predicate(Arc::new(predicate)));
            self
        }
    }

    generate_set_and_with! {
        /// Set the value of the [`Access-Control-Expose-Headers`][mdn] header.
        ///
        /// # Errors
        ///
        /// Errors in case credentials are allowed and the given header
        /// contains the wildcard value (`*`).
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Expose-Headers
        pub fn expose_headers(mut self, headers: AccessControlExposeHeaders) -> Result<Self, BoxError> {
            if headers.is_any() && self.is_allow_credentials_any() {
                return Err(BoxError::from("Invalid CORS configuration: Cannot combine `Access-Control-Allow-Credentials: true` with `Access-Control-Expose-Headers: *`"))
            }
            self.expose_headers = Some(headers);
            Ok(self)
        }
    }

    generate_set_and_with! {
        /// Always set the [`Access-Control-Allow-Private-Network`][mdn] header.
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Private-Network
        pub fn allow_private_network(mut self) -> Self {
            self.allow_private_network = Some(AllowPrivateNetwork::Const);
            self
        }
    }

    generate_set_and_with! {
        /// Set the [`Access-Control-Allow-Private-Network`][mdn] header if predicate is satisfied.
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Private-Network
        pub fn allow_private_network_if(
            mut self,
            predicate: impl Fn(&HeaderValue, &RequestParts) -> bool + Send + Sync + 'static
        ) -> Self {
            self.allow_private_network = Some(AllowPrivateNetwork::Predicate(Arc::new(predicate)));
            self
        }
    }

    generate_set_and_with! {
        /// Set the value(s) of the [`Vary`][mdn] header.
        ///
        /// You only need to set this if you want to remove some of these defaults,
        /// or if you use a closure for one of the other headers and want to add a
        /// vary header accordingly.
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary
        pub fn vary(mut self, header: Vary) -> Self
        {
            self.vary = header;
            self
        }
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

impl Default for CorsLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for CorsLayer {
    type Service = Cors<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Cors {
            inner,
            layer: self.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        Cors { inner, layer: self }
    }
}

/// Middleware which adds headers for [CORS][mdn].
///
/// See the [module docs](crate::layer::cors) for an example.
///
/// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
#[derive(Debug, Clone)]
pub struct Cors<S> {
    inner: S,
    layer: CorsLayer,
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

    generate_set_and_with! {
        /// Always set the [`Access-Control-Allow-Credentials`][mdn] header.
        ///
        /// # Errors
        ///
        /// Errors in case any of the other CORS headers which
        /// support the wildcard value have been set to use it.
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
        pub fn allow_credentials(mut self) -> Result<Self, BoxError> {
            self.layer.try_set_allow_credentials()?;
            Ok(self)
        }
    }

    generate_set_and_with! {
        /// Set the [`Access-Control-Allow-Credentials`][mdn] header if predicate is satisfied.
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
        pub fn allow_credentials_if(
            mut self,
            predicate: impl Fn(&HeaderValue, &RequestParts) -> bool + Send + Sync + 'static
        ) -> Self {
            self.layer.set_allow_credentials_if(predicate);
            self
        }
    }

    generate_set_and_with! {
        /// Set the value of the [`Access-Control-Allow-Headers`][mdn] header.
        ///
        /// # Errors
        ///
        /// Errors in case credentials are allowed and the given header
        /// contains the wildcard value (`*`).
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers
        pub fn allow_headers(mut self, headers: AccessControlAllowHeaders) -> Result<Self, BoxError> {
            self.layer.try_set_allow_headers(headers)?;
            Ok(self)
        }
    }

    generate_set_and_with! {
        /// Set the value of the [`Access-Control-Max-Age`][mdn] header.
        ///
        /// By default the header will not be set which disables caching and will
        /// require a preflight call for all requests.
        ///
        /// Note that each browser has a maximum internal value that takes
        /// precedence when the Access-Control-Max-Age is greater. For more details
        /// see [mdn].
        ///
        /// If you need more flexibility, you can use supply a function which can
        /// dynamically decide the optional max-age based on the origin and other parts of
        /// each preflight request.
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age
        pub fn max_age(mut self, header: AccessControlMaxAge) -> Self {
            self.layer.set_max_age(header);
            self
        }
    }

    generate_set_and_with! {
        /// Set the [`Access-Control-Max-Age`][mdn] header if predicate is satisfied.
        ///
        /// See [`Self::with_max_age`] and [`Self::set_max_age`] for more information.
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age
        pub fn max_age_if(
            mut self,
            predicate: impl Fn(&HeaderValue, &RequestParts) -> Option<Seconds> + Send + Sync + 'static
        ) -> Self {
            self.layer.set_max_age_if(predicate);
            self
        }
    }

    generate_set_and_with! {
        /// Set the value of the [`Access-Control-Allow-Methods`][mdn] header.
        ///
        /// # Errors
        ///
        /// Errors in case credentials are allowed and the given header
        /// contains the wildcard value (`*`).
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods
        pub fn allow_methods(mut self, methods: AccessControlAllowMethods) -> Result<Self, BoxError> {
            self.layer.try_set_allow_methods(methods)?;
            Ok(self)
        }
    }

    generate_set_and_with! {
        /// Only set the [`Access-Control-Allow-Origin`][mdn] header with the wildcard value (`*`).
        ///
        /// # Errors
        ///
        /// Errors in case credentials are allowed.
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
        pub fn allow_origin_any(mut self) -> Result<Self, BoxError> {
            self.layer.try_set_allow_origin_any()?;
            Ok(self)
        }
    }

    generate_set_and_with! {
        /// Only set the [`Access-Control-Allow-Origin`][mdn] header with the "null" value when that is the origin.
        ///
        /// Note: The value `null` should not be used.
        /// It may seem safe to return `Access-Control-Allow-Origin: "null"`;
        /// however, the origin of resources that use a non-hierarchical scheme
        /// (such as `data:` or `file:`) and sandboxed documents is serialized as `null`.
        /// Many browsers will grant such documents access to a response with an
        /// `Access-Control-Allow-Origin: null` header, and any origin can create a
        /// hostile document with a `null` origin. Therefore, the `null` value for the
        /// `Access-Control-Allow-Origin` header should be avoided
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
        pub fn allow_origin_if_null(mut self) -> Self {
            self.layer.set_allow_origin_if_null();
            self
        }
    }

    generate_set_and_with! {
        /// Set the value of the [`Access-Control-Allow-Origin`][mdn] header if the predicate satisfied.
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
        pub fn allow_origin_if(
            mut self,
            predicate: impl Fn(&HeaderValue, &RequestParts) -> bool + Send + Sync + 'static
        ) -> Self {
            self.layer.set_allow_origin_if(predicate);
            self
        }
    }

    generate_set_and_with! {
        /// Set the value of the [`Access-Control-Expose-Headers`][mdn] header.
        ///
        /// # Errors
        ///
        /// Errors in case credentials are allowed and the given header
        /// contains the wildcard value (`*`).
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Expose-Headers
        pub fn expose_headers(mut self, headers: AccessControlExposeHeaders) -> Result<Self, BoxError> {
            self.layer.try_set_expose_headers(headers)?;
            Ok(self)
        }
    }

    generate_set_and_with! {
        /// Always set the [`Access-Control-Allow-Private-Network`][mdn] header.
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Private-Network
        pub fn allow_private_network(mut self) -> Self {
            self.layer.set_allow_private_network();
            self
        }
    }

    generate_set_and_with! {
        /// Set the [`Access-Control-Allow-Private-Network`][mdn] header if predicate is satisfied.
        ///
        /// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Private-Network
        pub fn allow_private_network_if(
            mut self,
            predicate: impl Fn(&HeaderValue, &RequestParts) -> bool + Send + Sync + 'static
        ) -> Self {
            self.layer.set_allow_private_network_if(predicate);
            self
        }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for Cors<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = Response<OptionalBody<ResBody>>;
    type Error = S::Error;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let (parts, body) = req.into_parts();
        let origin = parts.headers.get(&header::ORIGIN);

        let mut headers = HeaderMap::new();

        // These headers are applied to both preflight and subsequent regular CORS requests:
        // https://fetch.spec.whatwg.org/#http-responses
        if let Some(allow_credentials) = self.layer.allow_credentials.as_ref() {
            allow_credentials.extend_headers(&mut headers, origin, &parts);
        }
        if let Some(allow_private_network) = self.layer.allow_private_network.as_ref() {
            allow_private_network.extend_headers(&mut headers, origin, &parts);
        }

        headers.typed_insert(&self.layer.vary);

        if let Some(allow_origin) = self.layer.allow_origin.as_ref() {
            allow_origin.extend_headers(&mut headers, origin, &parts);
        }

        // Return results immediately upon preflight request
        if parts.method == Method::OPTIONS {
            // These headers are applied only to preflight requests
            if let Some(allow_methods) = &self.layer.allow_methods {
                allow_methods.extend_headers(&mut headers, &parts);
            }
            if let Some(allow_headers) = &self.layer.allow_headers {
                allow_headers.extend_headers(&mut headers, &parts);
            }
            if let Some(max_age) = &self.layer.max_age {
                max_age.extend_headers(&mut headers, origin, &parts);
            }

            Ok(if self.layer.handle_options_request {
                let req = Request::from_parts(parts, body);

                let mut response: Response<ResBody> = self.inner.serve(req).await?;
                let response_headers = response.headers_mut();

                // vary header can have multiple values, don't overwrite
                // previously-set value(s).
                if let Some(vary) = headers.remove(header::VARY) {
                    response_headers.append(header::VARY, vary);
                }
                // extend will overwrite previous headers of remaining names
                response_headers.extend(headers.drain());

                response.map(OptionalBody::some)
            } else {
                let mut response = Response::new(OptionalBody::none());
                mem::swap(response.headers_mut(), &mut headers);

                response
            })
        } else {
            // This header is applied only to non-preflight requests
            if let Some(ref header) = self.layer.expose_headers {
                headers.typed_insert(header);
            }

            let req = Request::from_parts(parts, body);

            let mut response: Response<ResBody> = self.inner.serve(req).await?;
            let response_headers = response.headers_mut();

            // vary header can have multiple values, don't overwrite
            // previously-set value(s).
            if let Some(vary) = headers.remove(header::VARY) {
                response_headers.append(header::VARY, vary);
            }
            // extend will overwrite previous headers of remaining names
            response_headers.extend(headers.drain());

            Ok(response.map(OptionalBody::some))
        }
    }
}
