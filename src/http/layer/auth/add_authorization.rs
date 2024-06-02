//! Add authorization to requests using the [`Authorization`] header.
//!
//! [`Authorization`]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
//!
//! # Example
//!
//! ```
//! use bytes::Bytes;
//!
//! use rama::http::layer::validate_request::{ValidateRequestHeader, ValidateRequestHeaderLayer};
//! use rama::http::layer::auth::AddAuthorizationLayer;
//! use rama::http::{Body, Request, Response, StatusCode, header::AUTHORIZATION};
//! use rama::service::{Context, Service, ServiceBuilder, service_fn};
//! use rama::error::BoxError;
//!
//! # async fn handle(request: Request) -> Result<Response, BoxError> {
//! #     Ok(Response::new(Body::default()))
//! # }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! # let service_that_requires_auth = ValidateRequestHeader::basic(
//! #     service_fn(handle),
//! #     "username",
//! #     "password",
//! # );
//! let mut client = ServiceBuilder::new()
//!     // Use basic auth with the given username and password
//!     .layer(AddAuthorizationLayer::basic("username", "password"))
//!     .service(service_that_requires_auth);
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

use base64::Engine as _;
use std::convert::TryFrom;

use crate::http::{HeaderValue, Request, Response};
use crate::service::{Context, Layer, Service};

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Layer that applies [`AddAuthorization`] which adds authorization to all requests using the
/// [`Authorization`] header.
///
/// See the [module docs](crate::http::layer::auth::add_authorization) for an example.
///
/// You can also use [`SetRequestHeader`] if you have a use case that isn't supported by this
/// middleware.
///
/// [`Authorization`]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
/// [`SetRequestHeader`]: crate::http::layer::set_header::SetRequestHeader
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

    /// Authorize requests using a username and password pair.
    ///
    /// The `Authorization` header will be set to `Basic {credentials}` where `credentials` is
    /// `base64_encode("{username}:{password}")`.
    ///
    /// Since the username and password is sent in clear text it is recommended to use HTTPS/TLS
    /// with this method. However use of HTTPS/TLS is not enforced by this middleware.
    pub fn basic(username: &str, password: &str) -> Self {
        let encoded = BASE64.encode(format!("{}:{}", username, password));
        let value = HeaderValue::try_from(format!("Basic {}", encoded)).unwrap();
        Self {
            value: Some(value),
            if_not_present: false,
        }
    }

    /// Authorize requests using a "bearer token". Commonly used for OAuth 2.
    ///
    /// The `Authorization` header will be set to `Bearer {token}`.
    ///
    /// # Panics
    ///
    /// Panics if the token is not a valid [`HeaderValue`].
    pub fn bearer(token: &str) -> Self {
        let value =
            HeaderValue::try_from(format!("Bearer {}", token)).expect("token is not valid header");
        Self {
            value: Some(value),
            if_not_present: false,
        }
    }

    /// Mark the header as [sensitive].
    ///
    /// This can for example be used to hide the header value from logs.
    ///
    /// [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
    #[allow(clippy::wrong_self_convention)]
    pub fn as_sensitive(mut self, sensitive: bool) -> Self {
        if let Some(value) = &mut self.value {
            value.set_sensitive(sensitive);
        }
        self
    }

    /// Preserve the existing `Authorization` header if it exists.
    ///
    /// This can be useful if you want to use different authorization headers for different requests.
    pub fn if_not_present(mut self) -> Self {
        self.if_not_present = true;
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
}

/// Middleware that adds authorization all requests using the [`Authorization`] header.
///
/// See the [module docs](crate::http::layer::auth::add_authorization) for an example.
///
/// You can also use [`SetRequestHeader`] if you have a use case that isn't supported by this
/// middleware.
///
/// [`Authorization`]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
/// [`SetRequestHeader`]: crate::http::layer::set_header::SetRequestHeader
#[derive(Debug, Clone)]
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
        AddAuthorizationLayer::none().layer(inner)
    }

    /// Authorize requests using a username and password pair.
    ///
    /// The `Authorization` header will be set to `Basic {credentials}` where `credentials` is
    /// `base64_encode("{username}:{password}")`.
    ///
    /// Since the username and password is sent in clear text it is recommended to use HTTPS/TLS
    /// with this method. However use of HTTPS/TLS is not enforced by this middleware.
    pub fn basic(inner: S, username: &str, password: &str) -> Self {
        AddAuthorizationLayer::basic(username, password).layer(inner)
    }

    /// Authorize requests using a "bearer token". Commonly used for OAuth 2.
    ///
    /// The `Authorization` header will be set to `Bearer {token}`.
    ///
    /// # Panics
    ///
    /// Panics if the token is not a valid [`HeaderValue`].
    pub fn bearer(inner: S, token: &str) -> Self {
        AddAuthorizationLayer::bearer(token).layer(inner)
    }

    define_inner_service_accessors!();

    /// Mark the header as [sensitive].
    ///
    /// This can for example be used to hide the header value from logs.
    ///
    /// [sensitive]: https://docs.rs/http/latest/http/header/struct.HeaderValue.html#method.set_sensitive
    #[allow(clippy::wrong_self_convention)]
    pub fn as_sensitive(mut self, sensitive: bool) -> Self {
        if let Some(value) = &mut self.value {
            value.set_sensitive(sensitive);
        }
        self
    }

    /// Preserve the existing `Authorization` header if it exists.
    ///
    /// This can be useful if you want to use different authorization headers for different requests.
    pub fn if_not_present(mut self) -> Self {
        self.if_not_present = true;
        self
    }
}

impl<S, State, ReqBody, ResBody> Service<State, Request<ReqBody>> for AddAuthorization<S>
where
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    State: Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        ctx: Context<State>,
        mut req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(value) = &self.value {
            if !self.if_not_present || !req.headers().contains_key(http::header::AUTHORIZATION) {
                req.headers_mut()
                    .insert(http::header::AUTHORIZATION, value.clone());
            }
        }
        self.inner.serve(ctx, req).await
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    #[allow(unused_imports)]
    use super::*;

    use crate::error::BoxError;
    use crate::http::layer::validate_request::ValidateRequestHeaderLayer;
    use crate::http::{Body, Request, Response, StatusCode};
    use crate::service::{Context, Service, ServiceBuilder};

    #[tokio::test]
    async fn basic() {
        // service that requires auth for all requests
        let svc = ServiceBuilder::new()
            .layer(ValidateRequestHeaderLayer::basic("foo", "bar"))
            .service_fn(echo);

        // make a client that adds auth
        let client = AddAuthorization::basic(svc, "foo", "bar");

        let res = client
            .serve(Context::default(), Request::new(Body::empty()))
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn token() {
        // service that requires auth for all requests
        let svc = ServiceBuilder::new()
            .layer(ValidateRequestHeaderLayer::bearer("foo"))
            .service_fn(echo);

        // make a client that adds auth
        let client = AddAuthorization::bearer(svc, "foo");

        let res = client
            .serve(Context::default(), Request::new(Body::empty()))
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn making_header_sensitive() {
        let svc = ServiceBuilder::new()
            .layer(ValidateRequestHeaderLayer::bearer("foo"))
            .service_fn(|request: Request<Body>| async move {
                let auth = request.headers().get(http::header::AUTHORIZATION).unwrap();
                assert!(auth.is_sensitive());

                Ok::<_, Infallible>(Response::new(Body::empty()))
            });

        let client = AddAuthorization::bearer(svc, "foo").as_sensitive(true);

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
