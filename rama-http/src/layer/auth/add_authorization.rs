//! Add authorization to requests using the [`Authorization`] header.
//!
//! [`Authorization`]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
//!
//! # Example
//!
//! ```
//! use rama_core::bytes::Bytes;
//!
//! use rama_http::layer::validate_request::{ValidateRequestHeader, ValidateRequestHeaderLayer};
//! use rama_http::layer::auth::AddAuthorizationLayer;
//! use rama_http::{Body, Request, Response, StatusCode, header::AUTHORIZATION};
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Service, Layer};
//! use rama_core::error::BoxError;
//! use rama_net::user::Basic;
//!
//! # async fn handle(request: Request) -> Result<Response, BoxError> {
//! #     Ok(Response::new(Body::default()))
//! # }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! # let service_that_requires_auth = ValidateRequestHeader::auth(
//! #     service_fn(handle),
//! #     Basic::new_static("username", "password"),
//! # );
//! let mut client = (
//!     // Use basic auth with the given username and password
//!     AddAuthorizationLayer::new(Basic::new_static("username", "password")),
//! ).layer(service_that_requires_auth);
//!
//! // Make a request, we don't have to add the `Authorization` header manually
//! let response = client
//!     .serve(Context::default(), Request::new(Body::default()))
//!     .await?;
//!
//! assert_eq!(StatusCode::OK, response.status());
//! # Ok(())
//! # }
//! ```

use crate::{HeaderValue, Request, Response};
use rama_core::{Context, Layer, Service};
use rama_http_headers::authorization::Credentials;
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// Layer that applies [`AddAuthorization`] which adds authorization to all requests using the
/// [`Authorization`] header.
///
/// See the [module docs](crate::layer::auth::add_authorization) for an example.
///
/// You can also use [`SetRequestHeader`] if you have a use case that isn't supported by this
/// middleware.
///
/// [`Authorization`]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
/// [`SetRequestHeader`]: crate::layer::set_header::SetRequestHeader
#[derive(Debug, Clone)]
pub struct AddAuthorizationLayer {
    value: Option<HeaderValue>,
    if_not_present: bool,
}

impl AddAuthorizationLayer {
    /// Create a new [`AddAuthorizationLayer`] that does not add any authorization.
    ///
    /// Can be useful if you only want to add authorization for some branches
    /// of your service.
    pub fn none() -> Self {
        Self {
            value: None,
            if_not_present: false,
        }
    }

    /// Authorize requests using the given [`Credentials`].
    pub fn new(credential: impl Credentials) -> Self {
        let encoded = credential.encode();
        Self {
            value: Some(encoded),
            if_not_present: false,
        }
    }

    /// Mark the header as [sensitive].
    ///
    /// This can for example be used to hide the header value from logs.
    ///
    /// [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
    pub fn as_sensitive(mut self, sensitive: bool) -> Self {
        if let Some(value) = &mut self.value {
            value.set_sensitive(sensitive);
        }
        self
    }

    /// Mark the header as [sensitive].
    ///
    /// This can for example be used to hide the header value from logs.
    ///
    /// [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
    pub fn set_as_sensitive(&mut self, sensitive: bool) -> &mut Self {
        if let Some(value) = &mut self.value {
            value.set_sensitive(sensitive);
        }
        self
    }

    /// Preserve the existing `Authorization` header if it exists.
    ///
    /// This can be useful if you want to use different authorization headers for different requests.
    pub fn if_not_present(mut self, value: bool) -> Self {
        self.if_not_present = value;
        self
    }

    /// Preserve the existing `Authorization` header if it exists.
    ///
    /// This can be useful if you want to use different authorization headers for different requests.
    pub fn set_if_not_present(&mut self, value: bool) -> &mut Self {
        self.if_not_present = value;
        self
    }
}

impl<S> Layer<S> for AddAuthorizationLayer {
    type Service = AddAuthorization<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AddAuthorization {
            inner,
            value: self.value.clone(),
            if_not_present: self.if_not_present,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        AddAuthorization {
            inner,
            value: self.value,
            if_not_present: self.if_not_present,
        }
    }
}

/// Middleware that adds authorization all requests using the [`Authorization`] header.
///
/// See the [module docs](crate::layer::auth::add_authorization) for an example.
///
/// You can also use [`SetRequestHeader`] if you have a use case that isn't supported by this
/// middleware.
///
/// [`Authorization`]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
/// [`SetRequestHeader`]: crate::layer::set_header::SetRequestHeader
pub struct AddAuthorization<S> {
    inner: S,
    value: Option<HeaderValue>,
    if_not_present: bool,
}

impl<S> AddAuthorization<S> {
    /// Create a new [`AddAuthorization`] that does not add any authorization.
    ///
    /// Can be useful if you only want to add authorization for some branches
    /// of your service.
    pub fn none(inner: S) -> Self {
        AddAuthorizationLayer::none().into_layer(inner)
    }

    /// Authorize requests using the given [`Credentials`].
    pub fn new(inner: S, credential: impl Credentials) -> Self {
        AddAuthorizationLayer::new(credential).into_layer(inner)
    }

    define_inner_service_accessors!();

    /// Mark the header as [sensitive].
    ///
    /// This can for example be used to hide the header value from logs.
    ///
    /// [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
    pub fn as_sensitive(mut self, sensitive: bool) -> Self {
        if let Some(value) = &mut self.value {
            value.set_sensitive(sensitive);
        }
        self
    }

    /// Mark the header as [sensitive].
    ///
    /// This can for example be used to hide the header value from logs.
    ///
    /// [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
    pub fn set_as_sensitive(&mut self, sensitive: bool) -> &mut Self {
        if let Some(value) = &mut self.value {
            value.set_sensitive(sensitive);
        }
        self
    }

    /// Preserve the existing `Authorization` header if it exists.
    ///
    /// This can be useful if you want to use different authorization headers for different requests.
    pub fn if_not_present(mut self, value: bool) -> Self {
        self.if_not_present = value;
        self
    }

    /// Preserve the existing `Authorization` header if it exists.
    ///
    /// This can be useful if you want to use different authorization headers for different requests.
    pub fn set_if_not_present(&mut self, value: bool) -> &mut Self {
        self.if_not_present = value;
        self
    }
}

impl<S: fmt::Debug> fmt::Debug for AddAuthorization<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddAuthorization")
            .field("inner", &self.inner)
            .field("value", &self.value)
            .field("if_not_present", &self.if_not_present)
            .finish()
    }
}

impl<S: Clone> Clone for AddAuthorization<S> {
    fn clone(&self) -> Self {
        AddAuthorization {
            inner: self.inner.clone(),
            value: self.value.clone(),
            if_not_present: self.if_not_present,
        }
    }
}

impl<S, State, ReqBody, ResBody> Service<State, Request<ReqBody>> for AddAuthorization<S>
where
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    State: Clone + Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        mut req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(value) = &self.value
            && (!self.if_not_present
                || !req
                    .headers()
                    .contains_key(rama_http_types::header::AUTHORIZATION))
        {
            req.headers_mut()
                .insert(rama_http_types::header::AUTHORIZATION, value.clone());
        }
        self.inner.serve(ctx, req).await
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    use crate::layer::validate_request::ValidateRequestHeaderLayer;
    use crate::{Body, Request, Response, StatusCode};
    use rama_core::error::BoxError;
    use rama_core::service::service_fn;
    use rama_core::{Context, Service};
    use rama_net::user::{Basic, Bearer};
    use std::convert::Infallible;

    #[tokio::test]
    async fn basic() {
        // service that requires auth for all requests
        let svc = ValidateRequestHeaderLayer::auth(Basic::new_static("foo", "bar"))
            .into_layer(service_fn(echo));

        // make a client that adds auth
        let client = AddAuthorization::new(svc, Basic::new_static("foo", "bar"));

        let res = client
            .serve(Context::default(), Request::new(Body::empty()))
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn token() {
        // service that requires auth for all requests
        let svc = ValidateRequestHeaderLayer::auth(Bearer::new_static("foo"))
            .into_layer(service_fn(echo));

        // make a client that adds auth
        let client = AddAuthorization::new(svc, Bearer::new_static("foo"));

        let res = client
            .serve(Context::default(), Request::new(Body::empty()))
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn making_header_sensitive() {
        let svc = ValidateRequestHeaderLayer::auth(Bearer::new_static("foo")).into_layer(
            service_fn(async |request: Request<Body>| {
                let auth = request
                    .headers()
                    .get(rama_http_types::header::AUTHORIZATION)
                    .unwrap();
                assert!(auth.is_sensitive());

                Ok::<_, Infallible>(Response::new(Body::empty()))
            }),
        );

        let client = AddAuthorization::new(svc, Bearer::new_static("foo")).as_sensitive(true);

        let res = client
            .serve(Context::default(), Request::new(Body::empty()))
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    async fn echo<Body>(req: Request<Body>) -> Result<Response<Body>, BoxError> {
        Ok(Response::new(req.into_body()))
    }
}
