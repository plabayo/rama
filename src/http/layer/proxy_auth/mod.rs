//! Middleware that validates if a request has the appropriate Proxy Authorisation.
//!
//! If the request is not authorized a `407 Proxy Authentication Required` response will be sent.

use crate::http::headers::{authorization::Credentials, HeaderMapExt, ProxyAuthorization};
use crate::http::{Request, Response, StatusCode};
use crate::service::{Context, Layer, Service};
use std::marker::PhantomData;

mod auth;
#[doc(inline)]
pub use auth::{ProxyAuthority, ProxyAuthoritySync};

/// Layer that applies the [`ProxyAuthService`] middleware which apply a timeout to requests.
///
/// See the [module docs](super) for an example.
#[derive(Debug, Clone)]
pub struct ProxyAuthLayer<A, C> {
    proxy_auth: A,
    filter_char: Option<char>,
    _phantom: PhantomData<fn(C) -> ()>,
}

impl<A, C> ProxyAuthLayer<A, C> {
    /// Creates a new [`ProxyAuthLayer`].
    pub fn new(proxy_auth: A) -> Self {
        ProxyAuthLayer {
            proxy_auth,
            filter_char: None,
            _phantom: PhantomData,
        }
    }

    /// Sets the filter character to be used for the [`ProxyAuthority`] implementation.
    ///
    /// See [`UsernameConfig`](crate::proxy::UsernameConfig) for more information.
    ///
    /// [`ProxyAuthority`]: self::auth::ProxyAuthority
    /// [`ProxyFilter`]: crate::proxy::ProxyFilter
    pub fn filter_char(mut self, filter_char: char) -> Self {
        self.filter_char = Some(filter_char);
        self
    }
}

impl<A, C, S> Layer<S> for ProxyAuthLayer<A, C>
where
    A: ProxyAuthority<C> + Clone,
    C: Credentials + Clone + Send + Sync + 'static,
{
    type Service = ProxyAuthService<A, C, S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyAuthService::new(self.filter_char, self.proxy_auth.clone(), inner)
    }
}

/// Middleware that validates if a request has the appropriate Proxy Authorisation.
///
/// If the request is not authorized a `407 Proxy Authentication Required` response will be sent.
///
/// See the [module docs](self) for an example.
#[derive(Debug, Clone)]
pub struct ProxyAuthService<A, C, S> {
    filter_char: Option<char>,
    proxy_auth: A,
    inner: S,
    _phantom: PhantomData<fn(C) -> ()>,
}

impl<A, C, S> ProxyAuthService<A, C, S> {
    /// Creates a new [`ProxyAuthService`].
    ///
    /// The `filter_char` is used to extract the [`ProxyFilter`] data from the username.
    ///
    /// See [`UsernameConfig`](crate::proxy::UsernameConfig) for more information.
    ///
    /// [`ProxyFilter`]: crate::proxy::ProxyFilter
    pub fn new(filter_char: Option<char>, proxy_auth: A, inner: S) -> Self {
        Self {
            filter_char,
            proxy_auth,
            inner,
            _phantom: PhantomData,
        }
    }

    define_inner_service_accessors!();
}

impl<A, C, S, State, ReqBody, ResBody> Service<State, Request<ReqBody>>
    for ProxyAuthService<A, C, S>
where
    A: ProxyAuthority<C>,
    C: Credentials + Clone + Send + Sync + 'static,
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
    State: Send + Sync + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(credentials) = req
            .headers()
            .typed_get::<ProxyAuthorization<C>>()
            .map(|h| h.0)
            .or_else(|| ctx.get::<C>().cloned())
        {
            if let Some(ext) = self
                .proxy_auth
                .authorized(self.filter_char, credentials)
                .await
            {
                ctx.extend(ext);
                self.inner.serve(ctx, req).await
            } else {
                Ok(Response::builder()
                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .body(Default::default())
                    .unwrap())
            }
        } else {
            Ok(Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .body(Default::default())
                .unwrap())
        }
    }
}
