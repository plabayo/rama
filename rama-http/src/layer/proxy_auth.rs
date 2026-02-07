//! Middleware that validates if a request has the appropriate Proxy Authorisation.
//!
//! If the request is not authorized a `407 Proxy Authentication Required` response will be sent.

use crate::header::PROXY_AUTHENTICATE;
use crate::headers::authorization::Authority;
use crate::headers::{HeaderMapExt, ProxyAuthorization, authorization::Credentials};
use crate::{Request, Response, StatusCode};
use rama_core::error::{BoxError, ErrorContext as _};
use rama_core::extensions::{Extension, ExtensionsMut, ExtensionsRef};
use rama_core::{Layer, Service};
use rama_http_types::body::OptionalBody;
use rama_net::user::UserId;
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;
use std::marker::PhantomData;

/// Layer that applies the [`ProxyAuthService`] middleware which apply a timeout to requests.
///
/// See the [module docs](super) for an example.
pub struct ProxyAuthLayer<A, C, L = ()> {
    proxy_auth: A,
    allow_anonymous: bool,
    _phantom: PhantomData<fn(C, L) -> ()>,
}

impl<A: fmt::Debug, C, L> fmt::Debug for ProxyAuthLayer<A, C, L> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ProxyAuthLayer")
            .field("proxy_auth", &self.proxy_auth)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn(C, L) -> ()>()),
            )
            .finish()
    }
}

impl<A: Clone, C, L> Clone for ProxyAuthLayer<A, C, L> {
    fn clone(&self) -> Self {
        Self {
            proxy_auth: self.proxy_auth.clone(),
            allow_anonymous: self.allow_anonymous,
            _phantom: PhantomData,
        }
    }
}

impl<A, C> ProxyAuthLayer<A, C, ()> {
    /// Creates a new [`ProxyAuthLayer`].
    pub const fn new(proxy_auth: A) -> Self {
        Self {
            proxy_auth,
            allow_anonymous: false,
            _phantom: PhantomData,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Allow anonymous requests.
        pub fn allow_anonymous(mut self, allow_anonymous: bool) -> Self {
            self.allow_anonymous = allow_anonymous;
            self
        }
    }
}

impl<A, C, L> ProxyAuthLayer<A, C, L> {
    /// Overwrite the Labels extract type
    ///
    /// This is used if the username contains labels that you need to extract out.
    /// Example implementation is the [`UsernameOpaqueLabelParser`].
    ///
    /// You can provide your own extractor by implementing the [`UsernameLabelParser`] trait.
    ///
    /// [`UsernameOpaqueLabelParser`]: rama_core::username::UsernameOpaqueLabelParser
    /// [`UsernameLabelParser`]: rama_core::username::UsernameLabelParser
    pub fn with_labels<L2>(self) -> ProxyAuthLayer<A, C, L2> {
        ProxyAuthLayer {
            proxy_auth: self.proxy_auth,
            allow_anonymous: self.allow_anonymous,
            _phantom: PhantomData,
        }
    }
}

impl<A, C, L, S> Layer<S> for ProxyAuthLayer<A, C, L>
where
    A: Authority<C, L> + Clone,
    C: Credentials + Clone + Send + Sync + 'static,
{
    type Service = ProxyAuthService<A, C, S, L>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyAuthService::new(self.proxy_auth.clone(), inner)
            .with_allow_anonymous(self.allow_anonymous)
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ProxyAuthService::new(self.proxy_auth, inner).with_allow_anonymous(self.allow_anonymous)
    }
}

/// Middleware that validates if a request has the appropriate Proxy Authorisation.
///
/// If the request is not authorized a `407 Proxy Authentication Required` response will be sent.
/// If `allow_anonymous` is set to `true` then requests without a Proxy Authorization header will be
/// allowed and the user will be authoized as [`UserId::Anonymous`].
///
/// See the [module docs](self) for an example.
pub struct ProxyAuthService<A, C, S, L = ()> {
    proxy_auth: A,
    allow_anonymous: bool,
    inner: S,
    _phantom: PhantomData<fn(C, L) -> ()>,
}

impl<A, C, S, L> ProxyAuthService<A, C, S, L> {
    /// Creates a new [`ProxyAuthService`].
    pub const fn new(proxy_auth: A, inner: S) -> Self {
        Self {
            proxy_auth,
            allow_anonymous: false,
            inner,
            _phantom: PhantomData,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Allow anonymous requests.
        pub fn allow_anonymous(mut self, allow_anonymous: bool) -> Self {
            self.allow_anonymous = allow_anonymous;
            self
        }
    }

    define_inner_service_accessors!();
}

impl<A: fmt::Debug, C, S: fmt::Debug, L> fmt::Debug for ProxyAuthService<A, C, S, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyAuthService")
            .field("proxy_auth", &self.proxy_auth)
            .field("allow_anonymous", &self.allow_anonymous)
            .field("inner", &self.inner)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn(C, L) -> ()>()),
            )
            .finish()
    }
}

impl<A: Clone, C, S: Clone, L> Clone for ProxyAuthService<A, C, S, L> {
    fn clone(&self) -> Self {
        Self {
            proxy_auth: self.proxy_auth.clone(),
            allow_anonymous: self.allow_anonymous,
            inner: self.inner.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<A, C, L, S, ReqBody, ResBody> Service<Request<ReqBody>> for ProxyAuthService<A, C, S, L>
where
    A: Authority<C, L>,
    C: Credentials + Extension + Clone,
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error: Into<BoxError>>,
    L: 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = Response<OptionalBody<ResBody>>;
    type Error = BoxError;

    async fn serve(&self, mut req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        if let Some(credentials) = req
            .headers()
            .typed_get::<ProxyAuthorization<C>>()
            .map(|h| h.0)
            .or_else(|| req.extensions().get::<C>().cloned())
        {
            if let Some(ext) = self.proxy_auth.authorized(credentials).await {
                req.extensions_mut().extend(ext);
                Ok(self
                    .inner
                    .serve(req)
                    .await
                    .into_box_error()?
                    .map(OptionalBody::some))
            } else {
                Ok(Response::builder()
                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .header(PROXY_AUTHENTICATE, C::SCHEME)
                    .body(OptionalBody::none())
                    .context("create auth-required response")?)
            }
        } else if self.allow_anonymous {
            req.extensions_mut().insert(UserId::Anonymous);
            Ok(self
                .inner
                .serve(req)
                .await
                .into_box_error()?
                .map(OptionalBody::some))
        } else {
            Ok(Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header(PROXY_AUTHENTICATE, C::SCHEME)
                .body(OptionalBody::none())
                .context("create auth-required response")?)
        }
    }
}
