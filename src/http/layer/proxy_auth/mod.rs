//! Middleware that validates if a request has the appropriate Proxy Authorisation.
//!
//! If the request is not authorized a `407 Proxy Authentication Required` response will be sent.

use crate::http::header::PROXY_AUTHENTICATE;
use crate::http::headers::{
    authorization::{Basic, Credentials},
    HeaderMapExt, ProxyAuthorization,
};
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
pub struct ProxyAuthLayer<A, C = Basic, L = ()> {
    proxy_auth: A,
    _phantom: PhantomData<fn(C, L) -> ()>,
}

impl<A, C> ProxyAuthLayer<A, C, ()> {
    /// Creates a new [`ProxyAuthLayer`].
    pub fn new(proxy_auth: A) -> Self {
        ProxyAuthLayer {
            proxy_auth,
            _phantom: PhantomData,
        }
    }
}

impl<A, C, L> ProxyAuthLayer<A, C, L> {
    /// Overwrite the Labels extract type
    ///
    /// This is used if the username contains labels that you need to extract out.
    /// Example implementations are [`UsernameOpaqueLabelParser`] and [`ProxyFilterUsernameParser`].
    ///
    /// You can provide your own extractor by implementing the [`UsernameLabelParser`] trait.
    ///
    /// [`UsernameOpaqueLabelParser`]: crate::utils::username::UsernameOpaqueLabelParser
    /// [`ProxyFilterUsernameParser`]: crate::proxy::ProxyFilterUsernameParser
    /// [`UsernameLabelParser`]: crate::utils::username::UsernameLabelParser
    pub fn with_labels<L2>(self) -> ProxyAuthLayer<A, C, L2> {
        ProxyAuthLayer {
            proxy_auth: self.proxy_auth,
            _phantom: PhantomData,
        }
    }
}

impl<A> ProxyAuthLayer<A, Basic, ()> {
    /// Creates a new [`ProxyAuthLayer`] with the default [`Basic`] credentials.
    pub fn basic(proxy_auth: A) -> Self {
        ProxyAuthLayer {
            proxy_auth,
            _phantom: PhantomData,
        }
    }
}

impl<A, C, L, S> Layer<S> for ProxyAuthLayer<A, C, L>
where
    A: ProxyAuthority<C, L> + Clone,
    C: Credentials + Clone + Send + Sync + 'static,
{
    type Service = ProxyAuthService<A, C, S, L>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyAuthService::new(self.proxy_auth.clone(), inner)
    }
}

/// Middleware that validates if a request has the appropriate Proxy Authorisation.
///
/// If the request is not authorized a `407 Proxy Authentication Required` response will be sent.
///
/// See the [module docs](self) for an example.
#[derive(Debug, Clone)]
pub struct ProxyAuthService<A, C, S, L = ()> {
    proxy_auth: A,
    inner: S,
    _phantom: PhantomData<fn(C, L) -> ()>,
}

impl<A, C, S, L> ProxyAuthService<A, C, S, L> {
    /// Creates a new [`ProxyAuthService`].
    pub fn new(proxy_auth: A, inner: S) -> Self {
        Self {
            proxy_auth,
            inner,
            _phantom: PhantomData,
        }
    }

    define_inner_service_accessors!();
}

impl<A, C, L, S, State, ReqBody, ResBody> Service<State, Request<ReqBody>>
    for ProxyAuthService<A, C, S, L>
where
    A: ProxyAuthority<C, L>,
    C: Credentials + Clone + Send + Sync + 'static,
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    L: 'static,
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
            if let Some(ext) = self.proxy_auth.authorized(credentials).await {
                ctx.extend(ext);
                self.inner.serve(ctx, req).await
            } else {
                Ok(Response::builder()
                    .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                    .header(PROXY_AUTHENTICATE, C::SCHEME)
                    .body(Default::default())
                    .unwrap())
            }
        } else {
            Ok(Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header(PROXY_AUTHENTICATE, C::SCHEME)
                .body(Default::default())
                .unwrap())
        }
    }
}
