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
//!
//! # Example
//!
//! ```rust
//! use rama::{
//!    http::{Body, Version, Request},
//!    proxy::{
//!         MemoryProxyDB, MemoryProxyDBQueryError, ProxyCsvRowReader, Proxy,
//!         layer::{ProxyDBLayer, ProxySelectMode},
//!         ProxyFilter,
//!    },
//!    service::{Context, ServiceBuilder, Service, Layer},
//! };
//! use itertools::Itertools;
//! use std::{convert::Infallible, sync::Arc};
//!
//! #[tokio::main]
//! async fn main() {
//!     let db = MemoryProxyDB::try_from_iter([
//!         Proxy {
//!             id: "42".to_owned(),
//!             tcp: true,
//!             udp: true,
//!             http: true,
//!             socks5: true,
//!             datacenter: false,
//!             residential: true,
//!             mobile: true,
//!             authority: "12.34.12.34:8080".to_owned(),
//!             pool_id: None,
//!             country: Some("*".into()),
//!             city: Some("*".into()),
//!             carrier: Some("*".into()),
//!             credentials: None,
//!         },
//!         Proxy {
//!             id: "100".to_owned(),
//!             tcp: true,
//!             udp: false,
//!             http: true,
//!             socks5: false,
//!             datacenter: true,
//!             residential: false,
//!             mobile: false,
//!             authority: "123.123.123.123:8080".to_owned(),
//!             pool_id: None,
//!             country: Some("US".into()),
//!             city: None,
//!             carrier: None,
//!             credentials: None,
//!         },
//!     ])
//!     .unwrap();
//!     
//!     let service = ServiceBuilder::new()
//!         .layer(ProxyDBLayer::new(Arc::new(db), ProxySelectMode::Default))
//!         .service_fn(|ctx: Context<()>, _: Request| async move {
//!             Ok::<_, Infallible>(ctx.get::<Proxy>().unwrap().clone())
//!         });
//!     
//!     let mut ctx = Context::default();
//!     ctx.insert(ProxyFilter {
//!         country: Some(vec!["BE".into()]),
//!         mobile: Some(true),
//!         residential: Some(true),
//!         ..Default::default()
//!     });
//!     
//!     let req = Request::builder()
//!         .version(Version::HTTP_3)
//!         .method("GET")
//!         .uri("https://example.com")
//!         .body(Body::empty())
//!         .unwrap();
//!     
//!     let proxy = service.serve(ctx, req).await.unwrap();
//!     assert_eq!(proxy.id, "42");
//! }
//! ```

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

#[derive(Debug, Clone, Default)]
/// The modus operandi to decide how to deal with a missing [`ProxyFilter`] in the [`Context`]
/// when selecting a [`Proxy`] from the [`ProxyDB`].
///
/// More advanced behaviour can be achieved by combining one of these modi
/// with another (custom) layer prepending the parent.
pub enum ProxySelectMode {
    #[default]
    /// The [`ProxyFilter`] is optional, and if not present, no proxy is selected.
    Optional,
    /// The [`ProxyFilter`] is optional, and if not present, the default [`ProxyFilter`] is used.
    Default,
    /// The [`ProxyFilter`] is required, and if not present, an error is returned.
    Required,
    /// The [`ProxyFilter`] is optional, and if not present, the provided fallback [`ProxyFilter`] is used.
    Fallback(ProxyFilter),
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
            mode: self.mode.clone(),
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
            ProxySelectMode::Fallback(ref filter) => {
                ctx.get::<ProxyFilter>().cloned().or(Some(filter.clone()))
            }
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
            ProxySelectMode::Fallback(ref filter) => {
                ctx.get::<ProxyFilter>().cloned().or(Some(filter.clone()))
            }
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
            mode: self.mode.clone(),
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
        ProxyDBService::with_predicate(
            inner,
            self.db.clone(),
            self.mode.clone(),
            self.predicate.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        http::{Body, Version},
        proxy::{MemoryProxyDB, MemoryProxyDBQueryError, ProxyCsvRowReader, StringFilter},
        service::ServiceBuilder,
    };
    use itertools::Itertools;
    use std::{convert::Infallible, sync::Arc};

    #[tokio::test]
    async fn test_proxy_db_default_happy_path_example() {
        let db = MemoryProxyDB::try_from_iter([
            Proxy {
                id: "42".to_owned(),
                tcp: true,
                udp: true,
                http: true,
                socks5: true,
                datacenter: false,
                residential: true,
                mobile: true,
                authority: "12.34.12.34:8080".to_owned(),
                pool_id: None,
                country: Some("*".into()),
                city: Some("*".into()),
                carrier: Some("*".into()),
                credentials: None,
            },
            Proxy {
                id: "100".to_owned(),
                tcp: true,
                udp: false,
                http: true,
                socks5: false,
                datacenter: true,
                residential: false,
                mobile: false,
                authority: "123.123.123.123:8080".to_owned(),
                pool_id: None,
                country: Some("US".into()),
                city: None,
                carrier: None,
                credentials: None,
            },
        ])
        .unwrap();

        let service = ServiceBuilder::new()
            .layer(ProxyDBLayer::new(Arc::new(db), ProxySelectMode::Default))
            .service_fn(|ctx: Context<()>, _: Request| async move {
                Ok::<_, Infallible>(ctx.get::<Proxy>().unwrap().clone())
            });

        let mut ctx = Context::default();
        ctx.insert(ProxyFilter {
            country: Some(vec!["BE".into()]),
            mobile: Some(true),
            residential: Some(true),
            ..Default::default()
        });

        let req = Request::builder()
            .version(Version::HTTP_3)
            .method("GET")
            .uri("https://example.com")
            .body(Body::empty())
            .unwrap();

        let proxy = service.serve(ctx, req).await.unwrap();
        assert_eq!(proxy.id, "42");
    }

    const RAW_CSV_DATA: &str = include_str!("./test_proxydb_rows.csv");

    async fn memproxydb() -> MemoryProxyDB {
        let mut reader = ProxyCsvRowReader::raw(RAW_CSV_DATA);
        let mut rows = Vec::new();
        while let Some(proxy) = reader.next().await.unwrap() {
            rows.push(proxy);
        }
        MemoryProxyDB::try_from_rows(rows).unwrap()
    }

    #[tokio::test]
    async fn test_proxy_db_service_optional() {
        let db = memproxydb().await;

        let service = ServiceBuilder::new()
            .layer(ProxyDBLayer::new(Arc::new(db), ProxySelectMode::Optional))
            .service_fn(|ctx: Context<()>, _: Request| async move {
                Ok::<_, Infallible>(ctx.get::<Proxy>().cloned())
            });

        for (filter, expected_id, req) in [
            (
                None,
                None,
                Request::builder()
                    .version(Version::HTTP_11)
                    .method("GET")
                    .uri("http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
            (
                Some(ProxyFilter {
                    id: Some("3031533634".to_owned()),
                    ..Default::default()
                }),
                Some("3031533634".to_owned()),
                Request::builder()
                    .version(Version::HTTP_11)
                    .method("GET")
                    .uri("http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
            (
                Some(ProxyFilter {
                    country: Some(vec![StringFilter::new("BE")]),
                    mobile: Some(true),
                    residential: Some(true),
                    ..Default::default()
                }),
                Some("2593294918".to_owned()),
                Request::builder()
                    .version(Version::HTTP_3)
                    .method("GET")
                    .uri("https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
        ] {
            let mut ctx = Context::default();
            if let Some(filter) = filter {
                ctx.insert(filter);
            }

            let maybe_proxy = service.serve(ctx, req).await.unwrap();

            assert_eq!(
                maybe_proxy.map(|p| p.id).unwrap_or_default(),
                expected_id.unwrap_or_default()
            );
        }
    }

    #[tokio::test]
    async fn test_proxy_db_service_default() {
        let db = memproxydb().await;

        let service = ServiceBuilder::new()
            .layer(ProxyDBLayer::new(Arc::new(db), ProxySelectMode::Default))
            .service_fn(|ctx: Context<()>, _: Request| async move {
                Ok::<_, Infallible>(ctx.get::<Proxy>().unwrap().clone())
            });

        for (filter, expected_ids, req_info) in [
            (None, "1125300915,1259341971,1264821985,129108927,1316455915,1425588737,1571861931,1810781137,1836040682,1844412609,1885107293,2021561518,2079461709,2107229589,2141152822,2438596154,2497865606,2521901221,2551759475,2560727338,2593294918,2798907087,2854473221,2880295577,2909724448,2912880381,292096733,2951529660,3031533634,3187902553,3269411602,3269465574,339020035,3481200027,3498810974,3503691556,362091157,3679054656,371209663,3861736957,39048766,3976711563,4062553709,49590203,56402588,724884866,738626121,767809962,846528631,906390012", (Version::HTTP_11, "GET", "http://example.com")),
            (
                Some(ProxyFilter {
                    country: Some(vec![StringFilter::new("BE")]),
                    mobile: Some(true),
                    residential: Some(true),
                    ..Default::default()
                }),
                "2593294918",
                (Version::HTTP_3, "GET", "https://example.com"),
            ),
        ] {
            let mut seen_ids = Vec::new();
            for _ in 0..5000 {
                let mut ctx = Context::default();
                if let Some(filter) = filter.clone() {
                    ctx.insert(filter);
                }

                let req = Request::builder()
                    .version(req_info.0)
                    .method(req_info.1)
                    .uri(req_info.2)
                    .body(Body::empty())
                    .unwrap();

                let proxy = service.serve(ctx, req).await.unwrap();
                if !seen_ids.contains(&proxy.id) {
                    seen_ids.push(proxy.id);
                }
            }

            let seen_ids = seen_ids.into_iter().sorted().join(",");
            assert_eq!(seen_ids, expected_ids);
        }
    }

    #[tokio::test]
    async fn test_proxy_db_service_fallback() {
        let db = memproxydb().await;

        let service = ServiceBuilder::new()
            .layer(ProxyDBLayer::new(
                Arc::new(db),
                // useful if you want to have a fallback that doesn't blow your budget
                ProxySelectMode::Fallback(ProxyFilter {
                    datacenter: Some(true),
                    residential: Some(false),
                    mobile: Some(false),
                    ..Default::default()
                }),
            ))
            .service_fn(|ctx: Context<()>, _: Request| async move {
                Ok::<_, Infallible>(ctx.get::<Proxy>().unwrap().clone())
            });

        for (filter, expected_ids, req_info) in [
            (
                None,
                "1316455915,2521901221,3679054656,3861736957,3976711563,4062553709,49590203",
                (Version::HTTP_11, "GET", "http://example.com"),
            ),
            (
                Some(ProxyFilter {
                    country: Some(vec![StringFilter::new("BE")]),
                    mobile: Some(true),
                    residential: Some(true),
                    ..Default::default()
                }),
                "2593294918",
                (Version::HTTP_3, "GET", "https://example.com"),
            ),
        ] {
            let mut seen_ids = Vec::new();
            for _ in 0..5000 {
                let mut ctx = Context::default();
                if let Some(filter) = filter.clone() {
                    ctx.insert(filter);
                }

                let req = Request::builder()
                    .version(req_info.0)
                    .method(req_info.1)
                    .uri(req_info.2)
                    .body(Body::empty())
                    .unwrap();

                let proxy = service.serve(ctx, req).await.unwrap();
                if !seen_ids.contains(&proxy.id) {
                    seen_ids.push(proxy.id);
                }
            }

            let seen_ids = seen_ids.into_iter().sorted().join(",");
            assert_eq!(seen_ids, expected_ids);
        }
    }

    #[tokio::test]
    async fn test_proxy_db_service_required() {
        let db = memproxydb().await;

        let service = ServiceBuilder::new()
            .layer(ProxyDBLayer::new(Arc::new(db), ProxySelectMode::Required))
            .service_fn(|ctx: Context<()>, _: Request| async move {
                Ok::<_, Infallible>(ctx.get::<Proxy>().unwrap().clone())
            });

        for (filter, expected, req) in [
            (
                None,
                Err(ProxySelectError::MissingFilter::<MemoryProxyDBQueryError, Infallible>),
                Request::builder()
                    .version(Version::HTTP_11)
                    .method("GET")
                    .uri("http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
            (
                Some(ProxyFilter {
                    country: Some(vec![StringFilter::new("BE")]),
                    mobile: Some(true),
                    residential: Some(true),
                    ..Default::default()
                }),
                Ok("2593294918".to_owned()),
                Request::builder()
                    .version(Version::HTTP_3)
                    .method("GET")
                    .uri("https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
            (
                Some(ProxyFilter {
                    id: Some("FooBar".into()),
                    ..Default::default()
                }),
                Err(ProxySelectError::ProxyDBError::<_, Infallible>(
                    MemoryProxyDBQueryError::not_found(),
                )),
                Request::builder()
                    .version(Version::HTTP_3)
                    .method("GET")
                    .uri("https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
            (
                Some(ProxyFilter {
                    id: Some("1316455915".into()),
                    country: Some(vec![StringFilter::new("BE")]),
                    mobile: Some(true),
                    residential: Some(true),
                    ..Default::default()
                }),
                Err(ProxySelectError::ProxyDBError::<_, Infallible>(
                    MemoryProxyDBQueryError::mismatch(),
                )),
                Request::builder()
                    .version(Version::HTTP_3)
                    .method("GET")
                    .uri("https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
        ] {
            let mut ctx = Context::default();
            if let Some(filter) = filter {
                ctx.insert(filter);
            }

            let proxy_result = service.serve(ctx, req).await;
            match expected {
                Ok(expected_id) => {
                    assert_eq!(proxy_result.unwrap().id, expected_id);
                }
                Err(expected_err) => match (proxy_result.unwrap_err(), expected_err) {
                    (ProxySelectError::MissingFilter, ProxySelectError::MissingFilter) => {}
                    (ProxySelectError::ProxyDBError(a), ProxySelectError::ProxyDBError(b)) => {
                        assert_eq!(a.kind(), b.kind())
                    }
                    (err, _) => panic!("Expected MissingFilter error: {:?}", err),
                },
            }
        }
    }

    #[tokio::test]
    async fn test_proxy_db_service_required_with_predicate() {
        let db = memproxydb().await;

        let service = ServiceBuilder::new()
            .layer(ProxyDBLayer::with_predicate(
                Arc::new(db),
                ProxySelectMode::Required,
                |proxy: &Proxy| proxy.mobile,
            ))
            .service_fn(|ctx: Context<()>, _: Request| async move {
                Ok::<_, Infallible>(ctx.get::<Proxy>().unwrap().clone())
            });

        for (filter, expected, req) in [
            (
                None,
                Err(ProxySelectError::MissingFilter::<MemoryProxyDBQueryError, Infallible>),
                Request::builder()
                    .version(Version::HTTP_11)
                    .method("GET")
                    .uri("http://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
            (
                Some(ProxyFilter {
                    country: Some(vec![StringFilter::new("BE")]),
                    mobile: Some(true),
                    residential: Some(true),
                    ..Default::default()
                }),
                Ok("2593294918".to_owned()),
                Request::builder()
                    .version(Version::HTTP_3)
                    .method("GET")
                    .uri("https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
            (
                Some(ProxyFilter {
                    id: Some("FooBar".into()),
                    ..Default::default()
                }),
                Err(ProxySelectError::ProxyDBError::<_, Infallible>(
                    MemoryProxyDBQueryError::not_found(),
                )),
                Request::builder()
                    .version(Version::HTTP_3)
                    .method("GET")
                    .uri("https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
            (
                Some(ProxyFilter {
                    id: Some("1316455915".into()),
                    country: Some(vec![StringFilter::new("BE")]),
                    mobile: Some(true),
                    residential: Some(true),
                    ..Default::default()
                }),
                Err(ProxySelectError::ProxyDBError::<_, Infallible>(
                    MemoryProxyDBQueryError::mismatch(),
                )),
                Request::builder()
                    .version(Version::HTTP_3)
                    .method("GET")
                    .uri("https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
            // match found, but due to custom predicate it won't check, given it is not mobile
            (
                Some(ProxyFilter {
                    id: Some("1316455915".into()),
                    ..Default::default()
                }),
                Err(ProxySelectError::ProxyDBError::<_, Infallible>(
                    MemoryProxyDBQueryError::mismatch(),
                )),
                Request::builder()
                    .version(Version::HTTP_3)
                    .method("GET")
                    .uri("https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
        ] {
            let mut ctx = Context::default();
            if let Some(filter) = filter {
                ctx.insert(filter);
            }

            let proxy_result = service.serve(ctx, req).await;
            match expected {
                Ok(expected_id) => {
                    assert_eq!(proxy_result.unwrap().id, expected_id);
                }
                Err(expected_err) => match (proxy_result.unwrap_err(), expected_err) {
                    (ProxySelectError::MissingFilter, ProxySelectError::MissingFilter) => {}
                    (ProxySelectError::ProxyDBError(a), ProxySelectError::ProxyDBError(b)) => {
                        assert_eq!(a.kind(), b.kind())
                    }
                    (err, _) => panic!("Expected MissingFilter error: {:?}", err),
                },
            }
        }
    }
}
