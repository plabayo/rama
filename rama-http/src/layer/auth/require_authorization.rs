//! Authorize requests using [`ValidateRequest`].
//!
//! [`Authorization`]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
//!
//! # Example
//!
//! ```
//! use bytes::Bytes;
//!
//! use rama_http::layer::validate_request::{ValidateRequest, ValidateRequestHeader, ValidateRequestHeaderLayer};
//! use rama_http::{Body, Request, Response, StatusCode, header::AUTHORIZATION};
//! use rama_core::service::service_fn;
//! use rama_core::{Context, Service, Layer};
//! use rama_core::error::BoxError;
//!
//! async fn handle(request: Request) -> Result<Response, BoxError> {
//!     Ok(Response::new(Body::default()))
//! }
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), BoxError> {
//! let mut service = (
//!     // Require the `Authorization` header to be `Bearer passwordlol`
//!     ValidateRequestHeaderLayer::bearer("passwordlol"),
//! ).layer(service_fn(handle));
//!
//! // Requests with the correct token are allowed through
//! let request = Request::builder()
//!     .header(AUTHORIZATION, "Bearer passwordlol")
//!     .body(Body::default())
//!     .unwrap();
//!
//! let response = service
//!     .serve(Context::default(), request)
//!     .await?;
//!
//! assert_eq!(StatusCode::OK, response.status());
//!
//! // Requests with an invalid token get a `401 Unauthorized` response
//! let request = Request::builder()
//!     .body(Body::default())
//!     .unwrap();
//!
//! let response = service
//!     .serve(Context::default(), request)
//!     .await?;
//!
//! assert_eq!(StatusCode::UNAUTHORIZED, response.status());
//! # Ok(())
//! # }
//! ```
//!
//! Custom validation can be made by implementing [`ValidateRequest`].

use crate::layer::validate_request::{
    ValidateRequest, ValidateRequestHeader, ValidateRequestHeaderLayer,
};
use crate::{
    Request, Response, StatusCode,
    header::{self, HeaderValue},
};
use base64::Engine as _;
use rama_core::Context;
use std::{fmt, marker::PhantomData, sync::Arc};

use rama_net::user::UserId;
use sealed::AuthorizerSeal;

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

impl<C> ValidateRequestHeaderLayer<AuthorizeContext<C>> {
    /// Allow anonymous requests.
    pub fn set_allow_anonymous(&mut self, allow_anonymous: bool) -> &mut Self {
        self.validate.allow_anonymous = allow_anonymous;
        self
    }

    /// Allow anonymous requests.
    pub fn with_allow_anonymous(mut self, allow_anonymous: bool) -> Self {
        self.validate.allow_anonymous = allow_anonymous;
        self
    }
}

impl<S, C> ValidateRequestHeader<S, AuthorizeContext<C>> {
    /// Allow anonymous requests.
    pub fn set_allow_anonymous(&mut self, allow_anonymous: bool) -> &mut Self {
        self.validate.allow_anonymous = allow_anonymous;
        self
    }

    /// Allow anonymous requests.
    pub fn with_allow_anonymous(mut self, allow_anonymous: bool) -> Self {
        self.validate.allow_anonymous = allow_anonymous;
        self
    }
}

impl<S, ResBody> ValidateRequestHeader<S, AuthorizeContext<Basic<ResBody>>> {
    /// Authorize requests using a username and password pair.
    ///
    /// The `Authorization` header is required to be `Basic {credentials}` where `credentials` is
    /// `base64_encode("{username}:{password}")`.
    ///
    /// Since the username and password is sent in clear text it is recommended to use HTTPS/TLS
    /// with this method. However use of HTTPS/TLS is not enforced by this middleware.
    pub fn basic(inner: S, username: &str, value: &str) -> Self
    where
        ResBody: Default,
    {
        Self::custom(inner, AuthorizeContext::new(Basic::new(username, value)))
    }
}

impl<ResBody> ValidateRequestHeaderLayer<AuthorizeContext<Basic<ResBody>>> {
    /// Authorize requests using a username and password pair.
    ///
    /// The `Authorization` header is required to be `Basic {credentials}` where `credentials` is
    /// `base64_encode("{username}:{password}")`.
    ///
    /// Since the username and password is sent in clear text it is recommended to use HTTPS/TLS
    /// with this method. However use of HTTPS/TLS is not enforced by this middleware.
    pub fn basic(username: &str, password: &str) -> Self
    where
        ResBody: Default,
    {
        Self::custom(AuthorizeContext::new(Basic::new(username, password)))
    }
}

impl<S, ResBody> ValidateRequestHeader<S, AuthorizeContext<Bearer<ResBody>>> {
    /// Authorize requests using a "bearer token". Commonly used for OAuth 2.
    ///
    /// The `Authorization` header is required to be `Bearer {token}`.
    ///
    /// # Panics
    ///
    /// Panics if the token is not a valid [`HeaderValue`].
    pub fn bearer(inner: S, token: &str) -> Self
    where
        ResBody: Default,
    {
        Self::custom(inner, AuthorizeContext::new(Bearer::new(token)))
    }
}

impl<ResBody> ValidateRequestHeaderLayer<AuthorizeContext<Bearer<ResBody>>> {
    /// Authorize requests using a "bearer token". Commonly used for OAuth 2.
    ///
    /// The `Authorization` header is required to be `Bearer {token}`.
    ///
    /// # Panics
    ///
    /// Panics if the token is not a valid [`HeaderValue`].
    pub fn bearer(token: &str) -> Self
    where
        ResBody: Default,
    {
        Self::custom(AuthorizeContext::new(Bearer::new(token)))
    }
}

/// Type that performs "bearer token" authorization.
///
/// See [`ValidateRequestHeader::bearer`] for more details.
pub struct Bearer<ResBody> {
    header_value: HeaderValue,
    _ty: PhantomData<fn() -> ResBody>,
}

impl<ResBody> Bearer<ResBody> {
    fn new(token: &str) -> Self
    where
        ResBody: Default,
    {
        Self {
            header_value: format!("Bearer {}", token)
                .parse()
                .expect("token is not a valid header value"),
            _ty: PhantomData,
        }
    }
}

impl<ResBody> Clone for Bearer<ResBody> {
    fn clone(&self) -> Self {
        Self {
            header_value: self.header_value.clone(),
            _ty: PhantomData,
        }
    }
}

impl<ResBody> fmt::Debug for Bearer<ResBody> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bearer")
            .field("header_value", &self.header_value)
            .finish()
    }
}

// TODO: revisit ValidateRequest and related types so we do not require
// the associated Response types for all these traits. E.g. by forcing
// downstream users that their response bodies can be turned into the standard `rama::http::Body`
impl<S, B, C> ValidateRequest<S, B> for AuthorizeContext<C>
where
    C: Authorizer,
    B: Send + 'static,
    S: Clone + Send + Sync + 'static,
{
    type ResponseBody = C::ResBody;

    async fn validate(
        &self,
        ctx: Context<S>,
        request: Request<B>,
    ) -> Result<(Context<S>, Request<B>), Response<Self::ResponseBody>> {
        match request.headers().get(header::AUTHORIZATION) {
            Some(header_value) if self.credential.is_valid(header_value) => Ok((ctx, request)),
            None if self.allow_anonymous => {
                let mut ctx = ctx;
                ctx.insert(UserId::Anonymous);
                Ok((ctx, request))
            }
            _ => {
                let mut res = Response::new(Self::ResponseBody::default());
                *res.status_mut() = StatusCode::UNAUTHORIZED;

                if let Some(www_auth) = C::www_authenticate_header() {
                    res.headers_mut().insert(header::WWW_AUTHENTICATE, www_auth);
                } else {
                    res.headers_mut()
                        .insert(header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
                }

                Err(res)
            }
        }
    }
}

/// Type that performs basic authorization.
///
/// See [`ValidateRequestHeader::basic`] for more details.
pub struct Basic<ResBody> {
    header_value: HeaderValue,
    _ty: PhantomData<fn() -> ResBody>,
}

impl<ResBody> Basic<ResBody> {
    fn new(username: &str, password: &str) -> Self
    where
        ResBody: Default,
    {
        let encoded = BASE64.encode(format!("{}:{}", username, password));
        let header_value = format!("Basic {}", encoded).parse().unwrap();
        Self {
            header_value,
            _ty: PhantomData,
        }
    }
}

impl<ResBody> Clone for Basic<ResBody> {
    fn clone(&self) -> Self {
        Self {
            header_value: self.header_value.clone(),
            _ty: PhantomData,
        }
    }
}

impl<ResBody> fmt::Debug for Basic<ResBody> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Basic")
            .field("header_value", &self.header_value)
            .finish()
    }
}

// Private module with the actual implementation details
mod sealed {
    use super::*;

    /// Private trait that contains the actual authorization logic
    pub(super) trait AuthorizerSeal: Send + Sync + 'static {
        /// Check if the given header value is valid for this authorizer.
        fn is_valid(&self, header_value: &HeaderValue) -> bool;

        /// Return the WWW-Authenticate header value if applicable.
        fn www_authenticate_header() -> Option<HeaderValue>;
    }

    impl<ResBody: Default + Send + 'static> AuthorizerSeal for Basic<ResBody> {
        fn is_valid(&self, header_value: &HeaderValue) -> bool {
            header_value == &self.header_value
        }

        fn www_authenticate_header() -> Option<HeaderValue> {
            Some(HeaderValue::from_static("Basic"))
        }
    }

    impl<ResBody: Default + Send + 'static> AuthorizerSeal for Bearer<ResBody> {
        fn is_valid(&self, header_value: &HeaderValue) -> bool {
            header_value == &self.header_value
        }

        fn www_authenticate_header() -> Option<HeaderValue> {
            None
        }
    }

    impl<T, const N: usize> AuthorizerSeal for [T; N]
    where
        T: AuthorizerSeal,
    {
        fn is_valid(&self, header_value: &HeaderValue) -> bool {
            self.iter().any(|auth| auth.is_valid(header_value))
        }

        fn www_authenticate_header() -> Option<HeaderValue> {
            None
        }
    }

    impl<T> AuthorizerSeal for Vec<T>
    where
        T: AuthorizerSeal,
    {
        fn is_valid(&self, header_value: &HeaderValue) -> bool {
            self.iter().any(|auth| auth.is_valid(header_value))
        }

        fn www_authenticate_header() -> Option<HeaderValue> {
            None
        }
    }

    impl<T> AuthorizerSeal for Arc<T>
    where
        T: AuthorizerSeal,
    {
        fn is_valid(&self, header_value: &HeaderValue) -> bool {
            (**self).is_valid(header_value)
        }

        fn www_authenticate_header() -> Option<HeaderValue> {
            T::www_authenticate_header()
        }
    }
}

/// Trait for authorizing requests.
pub trait Authorizer: sealed::AuthorizerSeal {
    type ResBody: Default + Send + 'static;
}

// Implement the public trait for our existing types
impl<ResBody: Default + Send + 'static> Authorizer for Basic<ResBody> {
    type ResBody = ResBody;
}
impl<ResBody: Default + Send + 'static> Authorizer for Bearer<ResBody> {
    type ResBody = ResBody;
}
impl<T: Authorizer, const N: usize> Authorizer for [T; N] {
    type ResBody = T::ResBody;
}
impl<T: Authorizer> Authorizer for Vec<T> {
    type ResBody = T::ResBody;
}
impl<T: Authorizer> Authorizer for Arc<T> {
    type ResBody = T::ResBody;
}

pub struct AuthorizeContext<C> {
    credential: C,
    allow_anonymous: bool,
}

impl<C> AuthorizeContext<C> {
    /// Create a new [`AuthorizeContext`] with the given credential.
    pub(crate) fn new(credential: C) -> Self {
        Self {
            credential,
            allow_anonymous: false,
        }
    }
}

impl<C: Clone> Clone for AuthorizeContext<C> {
    fn clone(&self) -> Self {
        Self {
            credential: self.credential.clone(),
            allow_anonymous: self.allow_anonymous,
        }
    }
}

impl<C: fmt::Debug> fmt::Debug for AuthorizeContext<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizeContext")
            .field("credential", &self.credential)
            .field("allow_anonymous", &self.allow_anonymous)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::layer::validate_request::ValidateRequestHeaderLayer;
    use crate::{Body, header};

    use rama_core::error::BoxError;
    use rama_core::service::service_fn;
    use rama_core::{Context, Layer, Service};

    #[tokio::test]
    async fn valid_basic_token() {
        let service = ValidateRequestHeaderLayer::basic("foo", "bar").layer(service_fn(echo));

        let request = Request::get("/")
            .header(
                header::AUTHORIZATION,
                format!("Basic {}", BASE64.encode("foo:bar")),
            )
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn invalid_basic_token() {
        let service = ValidateRequestHeaderLayer::basic("foo", "bar").layer(service_fn(echo));

        let request = Request::get("/")
            .header(
                header::AUTHORIZATION,
                format!("Basic {}", BASE64.encode("wrong:credentials")),
            )
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        let www_authenticate = res.headers().get(header::WWW_AUTHENTICATE).unwrap();
        assert_eq!(www_authenticate, "Basic");
    }

    #[tokio::test]
    async fn valid_bearer_token() {
        let service = ValidateRequestHeaderLayer::bearer("foobar").layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::AUTHORIZATION, "Bearer foobar")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn basic_auth_is_case_sensitive_in_prefix() {
        let service = ValidateRequestHeaderLayer::basic("foo", "bar").layer(service_fn(echo));

        let request = Request::get("/")
            .header(
                header::AUTHORIZATION,
                format!("basic {}", BASE64.encode("foo:bar")),
            )
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn basic_auth_is_case_sensitive_in_value() {
        let service = ValidateRequestHeaderLayer::basic("foo", "bar").layer(service_fn(echo));

        let request = Request::get("/")
            .header(
                header::AUTHORIZATION,
                format!("Basic {}", BASE64.encode("Foo:bar")),
            )
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_bearer_token() {
        let service = ValidateRequestHeaderLayer::bearer("foobar").layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::AUTHORIZATION, "Bearer wat")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bearer_token_is_case_sensitive_in_prefix() {
        let service = ValidateRequestHeaderLayer::bearer("foobar").layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::AUTHORIZATION, "bearer foobar")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bearer_token_is_case_sensitive_in_token() {
        let service = ValidateRequestHeaderLayer::bearer("foobar").layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::AUTHORIZATION, "Bearer Foobar")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn multiple_basic_auth_vec() {
        let auth1 = Basic::new("user1", "pass1");
        let auth2 = Basic::new("user2", "pass2");
        let auth_vec = vec![auth1, auth2];
        let auth_context = AuthorizeContext::new(auth_vec);
        let service = ValidateRequestHeaderLayer::custom(auth_context).layer(service_fn(echo));

        // Test first credential
        let request = Request::builder()
            .header(
                header::AUTHORIZATION,
                format!("Basic {}", BASE64.encode("user1:pass1")),
            )
            .body(Body::default())
            .unwrap();
        let response = service.serve(Context::default(), request).await.unwrap();
        assert_eq!(StatusCode::OK, response.status());

        // Test second credential
        let request = Request::builder()
            .header(
                header::AUTHORIZATION,
                format!("Basic {}", BASE64.encode("user2:pass2")),
            )
            .body(Body::default())
            .unwrap();
        let response = service.serve(Context::default(), request).await.unwrap();
        assert_eq!(StatusCode::OK, response.status());

        // Test invalid credential
        let request = Request::builder()
            .header(
                header::AUTHORIZATION,
                format!("Basic {}", BASE64.encode("invalid:invalid")),
            )
            .body(Body::default())
            .unwrap();
        let response = service.serve(Context::default(), request).await.unwrap();
        assert_eq!(StatusCode::UNAUTHORIZED, response.status());
    }

    #[tokio::test]
    async fn multiple_basic_auth_array() {
        let auth1 = Basic::new("user1", "pass1");
        let auth_array = [auth1.clone(), auth1.clone()];
        let auth_context = AuthorizeContext::new(auth_array);
        let service = ValidateRequestHeaderLayer::custom(auth_context).layer(service_fn(echo));

        // Test valid credential
        let request = Request::builder()
            .header(
                header::AUTHORIZATION,
                format!("Basic {}", BASE64.encode("user1:pass1")),
            )
            .body(Body::default())
            .unwrap();
        let response = service.serve(Context::default(), request).await.unwrap();
        assert_eq!(StatusCode::OK, response.status());
    }

    #[tokio::test]
    async fn arc_basic_auth() {
        let auth = Basic::new("user", "pass");
        let arc_auth = Arc::new(auth);
        let auth_context = AuthorizeContext::new(arc_auth);
        let service = ValidateRequestHeaderLayer::custom(auth_context).layer(service_fn(echo));

        let request = Request::builder()
            .header(
                header::AUTHORIZATION,
                format!("Basic {}", BASE64.encode("user:pass")),
            )
            .body(Body::default())
            .unwrap();
        let response = service.serve(Context::default(), request).await.unwrap();
        assert_eq!(StatusCode::OK, response.status());
    }

    #[tokio::test]
    async fn conversion_methods() {
        let auth: Basic<Body> = Basic::new("user", "pass");
        let auth_context = AuthorizeContext::new(auth);

        // Test vector
        let auth_vec = vec![auth_context.credential.clone()];
        let vec_context = AuthorizeContext {
            credential: auth_vec,
            allow_anonymous: auth_context.allow_anonymous,
        };
        assert_eq!(vec_context.credential.len(), 1);

        // Test array
        let auth_array = [
            auth_context.credential.clone(),
            auth_context.credential.clone(),
        ];
        let array_context = AuthorizeContext {
            credential: auth_array,
            allow_anonymous: auth_context.allow_anonymous,
        };
        assert_eq!(array_context.credential.len(), 2);

        // Test Arc
        let arc_auth = Arc::new(auth_context.credential);
        let arc_context = AuthorizeContext {
            credential: arc_auth,
            allow_anonymous: auth_context.allow_anonymous,
        };
        assert_eq!(Arc::strong_count(&arc_context.credential), 1);
    }

    #[tokio::test]
    async fn basic_allows_anonymous_if_header_is_missing() {
        let service = ValidateRequestHeaderLayer::basic("foo", "bar")
            .with_allow_anonymous(true)
            .layer(service_fn(echo));

        let request = Request::get("/").body(Body::empty()).unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn basic_fails_if_allow_anonymous_and_credentials_are_invalid() {
        let service = ValidateRequestHeaderLayer::basic("foo", "bar")
            .with_allow_anonymous(true)
            .layer(service_fn(echo));

        let request = Request::get("/")
            .header(
                header::AUTHORIZATION,
                format!("Basic {}", BASE64.encode("wrong:credentials")),
            )
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn bearer_allows_anonymous_if_header_is_missing() {
        let service = ValidateRequestHeaderLayer::bearer("foobar")
            .with_allow_anonymous(true)
            .layer(service_fn(echo));

        let request = Request::get("/").body(Body::empty()).unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn bearer_fails_if_allow_anonymous_and_credentials_are_invalid() {
        let service = ValidateRequestHeaderLayer::bearer("foobar")
            .with_allow_anonymous(true)
            .layer(service_fn(echo));

        let request = Request::get("/")
            .header(header::AUTHORIZATION, "Bearer wrong")
            .body(Body::empty())
            .unwrap();

        let res = service.serve(Context::default(), request).await.unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    async fn echo<Body>(req: Request<Body>) -> Result<Response<Body>, BoxError> {
        Ok(Response::new(req.into_body()))
    }
}
