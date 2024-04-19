//! [`ProxyDB`] layer support to select a proxy based on the given [`Context`].
//!
//! This layer expects a [`ProxyFilter`] to be available in the [`Context`],
//! which can be added by using the [`HeaderConfigLayer`]
//! when operating on the HTTP layer and/or by parsing it via the TCP proxy username labels (e.g. `john-country-us-residential`),
//! in case you support that as part of your transport-layer authentication. And of course you can
//! combine the two approaches.
//!
//! [`ProxyDB`]: crate::proxy::ProxyDB
//! [`Context`]: crate::service::Context
//! [`HeaderConfigLayer`]: crate::http::layer::header_config::HeaderConfigLayer

use crate::{
    http::{Request, RequestContext},
    service::{Context, Layer, Service},
};

use super::{Proxy, ProxyDB, ProxyFilter};

#[derive(Debug)]
/// A [`Service`] which selects a [`Proxy`] based on the given [`Context`].
///
/// Depending on the [`ProxySelectMode`] the selection proxies might be optional,
/// or use the default [`ProxyFilter`] in case none is defined.
///
/// A predicate can be used to provide additional filtering on the found proxies,
/// that otherwise did match the used [`ProxyFilter`].
pub struct ProxyDBService<S, D, P = ()> {
    inner: S,
    db: D,
    mode: ProxySelectMode,
    predicate: P,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/// The modus operandi to decide how to deal with a missing [`ProxyFilter`] in the [`Context`]
/// when selecting a [`Proxy`] from the [`ProxyDB`].
///
/// More advanced behavour can be achieved by combining one of these modi
/// with another (custom) layer prepending the parent.
pub enum ProxySelectMode {
    #[default]
    /// The [`ProxyFilter`] is optional, and if not present, no proxy is selected.
    Optional,
    /// The [`ProxyFilter`] is optional, and if not present, the default [`ProxyFilter`] is used.
    Default,
    /// The [`ProxyFilter`] is required, and if not present, an error is returned.
    Required,
}

#[derive(Debug)]
/// The error type for the [`ProxyDBService`],
/// wrapping all errors that can happen in its lifetime.
pub enum ProxySelectError<E1, E2> {
    /// The [`ProxyFilter`] is missing in the [`Context`], while it is required ([`ProxySelectMode::Required`]).
    MissingFilter,
    /// An error happened while querying the [`ProxyDB`] for a [`Proxy`].
    ///
    /// Most common errors are I/O errors, not found errors (for the given [`ProxyFilter`]), or
    /// a mismatch in the proxy returned and the current context. This error is in generally not recoverable,
    /// as the proxy db is expected to handle recoverable errors itself.
    ProxyDBError(E1),
    /// An error happened while serving the inner [`Service`],
    /// what this means is outside the scope of this layer.
    ServiceError(E2),
}

impl<E1, E2> Clone for ProxySelectError<E1, E2>
where
    E1: Clone,
    E2: Clone,
{
    fn clone(&self) -> Self {
        match self {
            Self::MissingFilter => Self::MissingFilter,
            Self::ProxyDBError(e) => Self::ProxyDBError(e.clone()),
            Self::ServiceError(e) => Self::ServiceError(e.clone()),
        }
    }
}

impl<E1, E2> std::fmt::Display for ProxySelectError<E1, E2>
where
    E1: std::fmt::Display,
    E2: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingFilter => write!(f, "Missing ProxyFilter in Context"),
            Self::ProxyDBError(e) => write!(f, "ProxyDB Error: {}", e),
            Self::ServiceError(e) => write!(f, "Service Error: {}", e),
        }
    }
}

impl<E1, E2> std::error::Error for ProxySelectError<E1, E2>
where
    E1: std::error::Error + 'static,
    E2: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MissingFilter => None,
            Self::ProxyDBError(e) => Some(e),
            Self::ServiceError(e) => Some(e),
        }
    }
}

impl<S, D, P> Clone for ProxyDBService<S, D, P>
where
    S: Clone,
    D: Clone,
    P: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            db: self.db.clone(),
            mode: self.mode,
            predicate: self.predicate.clone(),
        }
    }
}

impl<S, D> ProxyDBService<S, D> {
    /// Create a new [`ProxyDBService`] with the given inner [`Service`], [`ProxyDB`], and [`ProxySelectMode`].
    ///
    /// Use [`ProxyDBService::with_predicate`] if you want to add a predicate to the service,
    /// to provide custom additional filtering on the found proxies.
    pub fn new(inner: S, db: D, mode: ProxySelectMode) -> Self {
        Self {
            inner,
            db,
            mode,
            predicate: (),
        }
    }
}

impl<S, D, P> ProxyDBService<S, D, P> {
    /// Create a new [`ProxyDBService`] with the given inner [`Service`], [`ProxyDB`], [`ProxySelectMode`], and predicate.
    ///
    /// This is the same as [`ProxyDBService::new`] but with an additional predicate,
    /// that will be used as an additional filter when selecting a [`Proxy`].
    pub fn with_predicate(inner: S, db: D, mode: ProxySelectMode, predicate: P) -> Self {
        Self {
            inner,
            db,
            mode,
            predicate,
        }
    }
}

impl<S, D, State, Body> Service<State, Request<Body>> for ProxyDBService<S, D>
where
    S: Service<State, Request<Body>>,
    S::Error: Send + Sync + 'static,
    D: ProxyDB,
    D::Error: Send + Sync + 'static,
    State: Send + Sync + 'static,
    Body: Send + 'static,
{
    type Response = S::Response;
    type Error = ProxySelectError<D::Error, S::Error>;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let maybe_filter = match self.mode {
            ProxySelectMode::Optional => ctx.get::<ProxyFilter>().cloned(),
            ProxySelectMode::Default => ctx
                .get::<ProxyFilter>()
                .cloned()
                .or_else(|| Some(ProxyFilter::default())),
            ProxySelectMode::Required => Some(
                ctx.get::<ProxyFilter>()
                    .cloned()
                    .ok_or(ProxySelectError::MissingFilter)?,
            ),
        };

        if let Some(filter) = maybe_filter {
            let req_ctx = ctx.get_or_insert_with(|| RequestContext::from(&req));
            let proxy = self
                .db
                .get_proxy(req_ctx.clone(), filter)
                .await
                .map_err(ProxySelectError::ProxyDBError)?;
            ctx.insert(proxy);
        }

        self.inner
            .serve(ctx, req)
            .await
            .map_err(ProxySelectError::ServiceError)
    }
}

impl<S, D, P, State, Body> Service<State, Request<Body>> for ProxyDBService<S, D, P>
where
    S: Service<State, Request<Body>>,
    S::Error: Send + Sync + 'static,
    D: ProxyDB,
    D::Error: Send + Sync + 'static,
    P: Fn(&Proxy) -> bool + Clone + Send + Sync + 'static,
    State: Send + Sync + 'static,
    Body: Send + 'static,
{
    type Response = S::Response;
    type Error = ProxySelectError<D::Error, S::Error>;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let maybe_filter = match self.mode {
            ProxySelectMode::Optional => ctx.get::<ProxyFilter>().cloned(),
            ProxySelectMode::Default => Some(ctx.get_or_insert_default::<ProxyFilter>().clone()),
            ProxySelectMode::Required => Some(
                ctx.get::<ProxyFilter>()
                    .cloned()
                    .ok_or(ProxySelectError::MissingFilter)?,
            ),
        };

        if let Some(filter) = maybe_filter {
            let req_ctx = ctx.get_or_insert_with(|| RequestContext::from(&req));
            let proxy = self
                .db
                .get_proxy_if(req_ctx.clone(), filter, self.predicate.clone())
                .await
                .map_err(ProxySelectError::ProxyDBError)?;
            ctx.insert(proxy);
        }

        self.inner
            .serve(ctx, req)
            .await
            .map_err(ProxySelectError::ServiceError)
    }
}

#[derive(Debug)]
/// A [`Layer`] which wraps an inner [`Service`] to select a [`Proxy`] based on the given [`Context`],
/// and insert, if a [`Proxy`] is selected, it in the [`Context`] for further processing.
///
/// See [`ProxyDBService`] for more details.
pub struct ProxyDBLayer<D, P = ()> {
    db: D,
    mode: ProxySelectMode,
    predicate: P,
}

impl<D, P> Clone for ProxyDBLayer<D, P>
where
    D: Clone,
    P: Clone,
{
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            mode: self.mode,
            predicate: self.predicate.clone(),
        }
    }
}

impl<D> ProxyDBLayer<D> {
    /// Create a new [`ProxyDBLayer`] with the given [`ProxyDB`] and [`ProxySelectMode`].
    ///
    /// Use [`ProxyDBLayer::with_predicate`] if you want to add a predicate to the [`ProxyDBService`],
    /// to provide custom additional filtering on the found proxies.
    pub fn new(db: D, mode: ProxySelectMode) -> Self {
        Self {
            db,
            mode,
            predicate: (),
        }
    }
}

impl<D, P> ProxyDBLayer<D, P> {
    /// Create a new [`ProxyDBLayer`] with the given [`ProxyDB`], [`ProxySelectMode`], and predicate.
    ///
    /// This is the same as [`ProxyDBLayer::new`] but with an additional predicate,
    /// that will be used as an additional filter when selecting a [`Proxy`] in the [`ProxyDBService`].
    pub fn with_predicate(db: D, mode: ProxySelectMode, predicate: P) -> Self {
        Self {
            db,
            mode,
            predicate,
        }
    }
}

impl<S, D, P> Layer<S> for ProxyDBLayer<D, P>
where
    D: Clone,
    P: Clone,
{
    type Service = ProxyDBService<S, D, P>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyDBService::with_predicate(inner, self.db.clone(), self.mode, self.predicate.clone())
    }
}
