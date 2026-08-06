use super::{Proxy, ProxyContext, ProxyDB, ProxyFilter, ProxyQueryPredicate};
use rama_core::error::BoxErrorExt as _;
use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext, ErrorExt},
    extensions::{Extensions, ExtensionsRef},
};
use rama_net::{
    Protocol, TransportProtocolInputExt,
    client::{ProxyRoute, ProxyRouteIndex, ProxyRoutes},
    transport::TransportProtocol,
    user::ProxyCredential,
};
use rama_utils::collections::NonEmptyVec;
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// A [`Service`] which resolves proxy candidates from the given input `Extensions`.
///
/// Depending on the [`ProxyFilterMode`] the selection proxies might be optional,
/// or use the default [`ProxyFilter`] in case none is defined.
///
/// A predicate can be used to provide additional filtering on the found proxies,
/// that otherwise did match the used [`ProxyFilter`].
///
/// By default every match is published as [`ProxyRoutes`]. The inner service
/// must expose the singular route it selected through its output extensions;
/// this service then inserts the corresponding [`Proxy`] and proxy ID there.
/// Legacy single-proxy mode inserts one singular [`ProxyRoute`] instead.
///
/// See [the crate docs](crate) for examples and more info on the usage of this service.
///
/// [`Proxy`]: crate::Proxy
#[derive(Debug, Clone)]
pub struct ProxyDBService<S, D, P, F> {
    inner: S,
    db: D,
    mode: ProxyFilterMode,
    predicate: P,
    username_formatter: F,
    overwrite_proxy: bool,
    single_proxy: bool,
}

#[derive(Debug, Clone, Default)]
/// The modus operandi to decide how to deal with a missing [`ProxyFilter`] in the input `Extensions`
/// when selecting a [`Proxy`] from the [`ProxyDB`].
///
/// More advanced behaviour can be achieved by combining one of these modi
/// with another (custom) layer prepending the parent.
pub enum ProxyFilterMode {
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

impl<S, D> ProxyDBService<S, D, bool, ()> {
    /// Create a new [`ProxyDBService`] with the given inner [`Service`] and [`ProxyDB`].
    pub const fn new(inner: S, db: D) -> Self {
        Self {
            inner,
            db,
            mode: ProxyFilterMode::Optional,
            predicate: true,
            username_formatter: (),
            overwrite_proxy: false,
            single_proxy: false,
        }
    }
}

impl<S, D, P, F> ProxyDBService<S, D, P, F> {
    rama_utils::macros::generate_set_and_with! {
        /// Set a [`ProxyFilterMode`] to define the behaviour surrounding
        /// [`ProxyFilter`] usage, e.g. if a proxy filter is required to be available or not,
        /// or what to do if it is optional and not available.
        pub fn filter_mode(mut self, mode: ProxyFilterMode) -> Self {
            self.mode = mode;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Select and insert only one proxy instead of publishing every match as
        /// an ordered route plan. This uses the database's singular-selection
        /// semantics, preserves legacy pre-fallback behaviour, and is disabled
        /// by default.
        pub fn single_proxy(mut self, single_proxy: bool) -> Self {
            self.single_proxy = single_proxy;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Overwrite an existing singular [`ProxyRoute`] with the selected
        /// proxy route or route plan. This is disabled by default in both
        /// plural and singular selection modes.
        pub fn overwrite_proxy(mut self, overwrite_proxy: bool) -> Self {
            self.overwrite_proxy = overwrite_proxy;
            self
        }
    }

    /// Set a [`ProxyQueryPredicate`] that will be used
    /// to possibly filter out proxies that according to the filters are correct,
    /// but not according to the predicate.
    pub fn with_select_predicate<Predicate>(
        self,
        p: Predicate,
    ) -> ProxyDBService<S, D, Predicate, F> {
        ProxyDBService {
            inner: self.inner,
            db: self.db,
            mode: self.mode,
            predicate: p,
            username_formatter: self.username_formatter,
            overwrite_proxy: self.overwrite_proxy,
            single_proxy: self.single_proxy,
        }
    }

    /// Set a [`UsernameFormatter`][crate::UsernameFormatter] that will be used to format
    /// the username based on the selected [`Proxy`]. This is required
    /// in case the proxy is a router that accepts or maybe even requires
    /// username labels to configure proxies further down/up stream.
    pub fn with_username_formatter<Formatter>(
        self,
        f: Formatter,
    ) -> ProxyDBService<S, D, P, Formatter> {
        ProxyDBService {
            inner: self.inner,
            db: self.db,
            mode: self.mode,
            predicate: self.predicate,
            username_formatter: f,
            overwrite_proxy: self.overwrite_proxy,
            single_proxy: self.single_proxy,
        }
    }

    define_inner_service_accessors!();
}

#[derive(Debug)]
struct PreparedProxy {
    proxy: Proxy,
    route: ProxyRoute,
}

fn prepare_proxy<F: UsernameFormatter>(
    formatter: &F,
    proxy: Proxy,
    filter: &ProxyFilter,
    transport_protocol: TransportProtocol,
    extensions: &Extensions,
) -> Result<PreparedProxy, BoxError> {
    let mut proxy_address = proxy.address.clone();

    proxy_address.credential = proxy_address
        .credential
        .take()
        .map(|credential| {
            Ok::<_, BoxError>(match credential {
                ProxyCredential::Basic(ref basic) => {
                    match formatter.fmt_username(&proxy, filter, basic.username(), extensions) {
                        Some(username) => ProxyCredential::Basic(
                            basic.clone_with_new_username(
                                username
                                    .try_into()
                                    .context("returned formatted username is invalid")?,
                            ),
                        ),
                        None => credential,
                    }
                }
                ProxyCredential::Bearer(_) => credential,
            })
        })
        .transpose()?;

    if proxy_address.protocol.is_none() {
        proxy_address.protocol = match transport_protocol {
            TransportProtocol::Udp => {
                if proxy.socks5 {
                    Some(Protocol::SOCKS5)
                } else if proxy.socks5h {
                    Some(Protocol::SOCKS5H)
                } else {
                    return Err(BoxError::from_static_str(
                        "selected udp proxy does not have a valid protocol available (db bug?!)",
                    ));
                }
            }
            TransportProtocol::Tcp => match proxy_address.address.port {
                Protocol::HTTP_DEFAULT_PORT | Protocol::HTTP_ALT_PORT if proxy.http => {
                    Some(Protocol::HTTP)
                }
                Protocol::HTTPS_DEFAULT_PORT | Protocol::HTTPS_ALT_PORT if proxy.https => {
                    Some(Protocol::HTTPS)
                }
                Protocol::SOCKS5_DEFAULT_PORT if proxy.socks5 => Some(Protocol::SOCKS5),
                Protocol::SOCKS5H_DEFAULT_PORT if proxy.socks5h => Some(Protocol::SOCKS5H),
                _ => {
                    if proxy.socks5 {
                        Some(Protocol::SOCKS5)
                    } else if proxy.socks5h {
                        Some(Protocol::SOCKS5H)
                    } else if proxy.http {
                        Some(Protocol::HTTP)
                    } else if proxy.https {
                        Some(Protocol::HTTPS)
                    } else {
                        return Err(BoxError::from_static_str(
                            "selected tcp proxy does not have a valid protocol available (db bug?!)",
                        ));
                    }
                }
            },
        };
    }

    Ok(PreparedProxy {
        proxy,
        route: ProxyRoute::Proxy(proxy_address),
    })
}

fn selected_proxy<'a>(
    extensions: &Extensions,
    candidates: &'a NonEmptyVec<PreparedProxy>,
) -> Result<&'a Proxy, BoxError> {
    let selected_route = extensions
        .get_ref::<ProxyRoute>()
        .context("proxy db service output contains no selected proxy route")?;

    if let Some(index) = extensions
        .get_ref::<ProxyRouteIndex>()
        .copied()
        .map(ProxyRouteIndex::get)
        && let Some(candidate) = candidates.get(index)
        && &candidate.route == selected_route
    {
        return Ok(&candidate.proxy);
    }

    let mut matches = candidates
        .into_iter()
        .filter(|candidate| &candidate.route == selected_route);
    let selected = matches
        .next()
        .context("selected proxy route does not match a proxy db candidate")?;
    if matches.next().is_some() {
        return Err(BoxError::from_static_str(
            "selected proxy route matches multiple proxy db candidates without a route index",
        ));
    }
    Ok(&selected.proxy)
}

impl<S, D, P, F, Input> Service<Input> for ProxyDBService<S, D, P, F>
where
    S: Service<Input, Error: Into<BoxError> + Send + Sync + 'static>,
    S::Output: ExtensionsRef,
    D: ProxyDB<Error: Into<BoxError> + Send + Sync + 'static>,
    P: ProxyQueryPredicate,
    F: UsernameFormatter,
    Input: TransportProtocolInputExt + ExtensionsRef + Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        if input.extensions().contains::<ProxyRoute>() && !self.overwrite_proxy {
            return self.inner.serve(input).await.into_box_error();
        }

        let maybe_filter = match self.mode {
            ProxyFilterMode::Optional => input.extensions().get_ref::<ProxyFilter>().cloned(),
            ProxyFilterMode::Default => Some(
                if let Some(stored) = input.extensions().get_ref::<ProxyFilter>() {
                    stored.clone()
                } else {
                    input.extensions().insert(ProxyFilter::default());
                    ProxyFilter::default()
                },
            ),
            ProxyFilterMode::Required => Some(
                input
                    .extensions()
                    .get_ref::<ProxyFilter>()
                    .cloned()
                    .context("missing proxy filter")?,
            ),
            ProxyFilterMode::Fallback(ref filter) => Some(
                if let Some(stored) = input.extensions().get_ref::<ProxyFilter>() {
                    stored.clone()
                } else {
                    input.extensions().insert(filter.clone());
                    filter.clone()
                },
            ),
        };

        let Some(filter) = maybe_filter else {
            return self.inner.serve(input).await.into_box_error();
        };

        let transport_protocol = input.transport_protocol().unwrap_or(TransportProtocol::Tcp);
        let proxy_ctx = ProxyContext {
            protocol: transport_protocol,
        };
        let proxies = if self.single_proxy {
            self.db
                .get_proxy_if(proxy_ctx, filter.clone(), self.predicate.clone())
                .await
                .map(NonEmptyVec::new)
        } else {
            self.db
                .get_proxies_if(proxy_ctx, filter.clone(), self.predicate.clone())
                .await
        }
        .map_err(|err| {
            ProxySelectError {
                inner: err.into(),
                filter: filter.clone(),
            }
            .into_box_error()
        })?;

        let candidates = proxies.try_map(|proxy| {
            prepare_proxy(
                &self.username_formatter,
                proxy,
                &filter,
                transport_protocol,
                input.extensions(),
            )
        })?;

        if self.single_proxy {
            input.extensions().insert(candidates.head.route.clone());
        } else {
            input.extensions().insert(
                ProxyRoutes::new(
                    (&candidates)
                        .into_iter()
                        .map(|candidate| candidate.route.clone()),
                )
                .with_overwrite(self.overwrite_proxy),
            );
        }

        let output = self.inner.serve(input).await.into_box_error()?;
        let proxy = selected_proxy(output.extensions(), &candidates)?;
        output
            .extensions()
            .insert(super::ProxyID::from(proxy.id.clone()));
        output.extensions().insert(proxy.clone());
        Ok(output)
    }
}

#[derive(Debug)]
struct ProxySelectError {
    inner: BoxError,
    filter: ProxyFilter,
}

impl fmt::Display for ProxySelectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "proxy select error ({}) for filter: {:?}",
            self.inner, self.filter
        )
    }
}

impl std::error::Error for ProxySelectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.inner.source().unwrap_or_else(|| self.inner.as_ref()))
    }
}

/// A [`Layer`] which wraps an inner [`Service`] to resolve proxy candidates
/// based on the input extensions and publish the selected proxy on the output.
///
/// See [the crate docs](crate) for examples and more info on the usage of this service.
#[derive(Debug, Clone)]
pub struct ProxyDBLayer<D, P, F> {
    db: D,
    mode: ProxyFilterMode,
    predicate: P,
    username_formatter: F,
    overwrite_proxy: bool,
    single_proxy: bool,
}

impl<D> ProxyDBLayer<D, bool, ()> {
    /// Create a new [`ProxyDBLayer`] with the given [`ProxyDB`].
    pub const fn new(db: D) -> Self {
        Self {
            db,
            mode: ProxyFilterMode::Optional,
            predicate: true,
            username_formatter: (),
            overwrite_proxy: false,
            single_proxy: false,
        }
    }
}

impl<D, P, F> ProxyDBLayer<D, P, F> {
    rama_utils::macros::generate_set_and_with! {
        /// Set a [`ProxyFilterMode`] to define the behaviour surrounding
        /// [`ProxyFilter`] usage, e.g. if a proxy filter is required to be available or not,
        /// or what to do if it is optional and not available.
        pub fn filter_mode(mut self, mode: ProxyFilterMode) -> Self {
            self.mode = mode;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Select and insert only one proxy instead of publishing every match as
        /// an ordered route plan. This uses the database's singular-selection
        /// semantics, preserves legacy pre-fallback behaviour, and is disabled
        /// by default.
        pub fn single_proxy(mut self, single_proxy: bool) -> Self {
            self.single_proxy = single_proxy;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Overwrite an existing singular [`ProxyRoute`] with the selected
        /// proxy route or route plan. This is disabled by default in both
        /// plural and singular selection modes.
        pub fn overwrite_proxy(mut self, overwrite_proxy: bool) -> Self {
            self.overwrite_proxy = overwrite_proxy;
            self
        }
    }

    /// Set a [`ProxyQueryPredicate`] that will be used
    /// to possibly filter out proxies that according to the filters are correct,
    /// but not according to the predicate.
    #[must_use]
    pub fn with_select_predicate<Predicate>(self, p: Predicate) -> ProxyDBLayer<D, Predicate, F> {
        ProxyDBLayer {
            db: self.db,
            mode: self.mode,
            predicate: p,
            username_formatter: self.username_formatter,
            overwrite_proxy: self.overwrite_proxy,
            single_proxy: self.single_proxy,
        }
    }

    /// Set a [`UsernameFormatter`][crate::UsernameFormatter] that will be used to format
    /// the username based on the selected [`Proxy`]. This is required
    /// in case the proxy is a router that accepts or maybe even requires
    /// username labels to configure proxies further down/up stream.
    #[must_use]
    pub fn with_username_formatter<Formatter>(self, f: Formatter) -> ProxyDBLayer<D, P, Formatter> {
        ProxyDBLayer {
            db: self.db,
            mode: self.mode,
            predicate: self.predicate,
            username_formatter: f,
            overwrite_proxy: self.overwrite_proxy,
            single_proxy: self.single_proxy,
        }
    }
}

impl<S, D, P, F> Layer<S> for ProxyDBLayer<D, P, F>
where
    D: Clone,
    P: Clone,
    F: Clone,
{
    type Service = ProxyDBService<S, D, P, F>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyDBService {
            inner,
            db: self.db.clone(),
            mode: self.mode.clone(),
            predicate: self.predicate.clone(),
            username_formatter: self.username_formatter.clone(),
            overwrite_proxy: self.overwrite_proxy,
            single_proxy: self.single_proxy,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ProxyDBService {
            inner,
            db: self.db,
            mode: self.mode,
            predicate: self.predicate,
            username_formatter: self.username_formatter,
            overwrite_proxy: self.overwrite_proxy,
            single_proxy: self.single_proxy,
        }
    }
}

/// Trait that is used to allow the formatting of a username,
/// e.g. to allow proxy routers to have proxy config labels in the username.
pub trait UsernameFormatter: Send + Sync + 'static {
    /// format the username based on the root properties of the given proxy.
    fn fmt_username(
        &self,
        proxy: &Proxy,
        filter: &ProxyFilter,
        username: &str,
        extensions: &Extensions,
    ) -> Option<String>;
}

impl UsernameFormatter for () {
    fn fmt_username(
        &self,
        _proxy: &Proxy,
        _filter: &ProxyFilter,
        _username: &str,
        _extensions: &Extensions,
    ) -> Option<String> {
        None
    }
}

impl<F> UsernameFormatter for F
where
    F: Fn(&Proxy, &ProxyFilter, &str) -> Option<String> + Send + Sync + 'static,
{
    fn fmt_username(
        &self,
        proxy: &Proxy,
        filter: &ProxyFilter,
        username: &str,
        _extensions: &Extensions,
    ) -> Option<String> {
        (self)(proxy, filter, username)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryProxyDB, Proxy, ProxyCsvRowReader, StringFilter};
    use itertools::Itertools;
    use rama_core::{ServiceInput, extensions::ExtensionsRef, service::service_fn};
    use rama_http_types::{Body, Request, Version};
    use rama_net::{
        Protocol,
        address::{HostWithPort, ProxyAddress},
        asn::Asn,
        client::{
            ConnectRequest, ConnectionError, ConnectionErrorKind, EstablishedClientConnection,
            ProxyRoute, ProxyRoutesConnector,
        },
    };
    use rama_utils::str::non_empty_str;
    use std::{
        convert::Infallible,
        str::FromStr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    fn selected_proxy_address(input: &impl ExtensionsRef) -> Option<&ProxyAddress> {
        input
            .extensions()
            .get_ref::<ProxyRoute>()
            .and_then(ProxyRoute::proxy_address)
    }

    fn test_proxy(id: &str, address: &str) -> Proxy {
        Proxy {
            id: id.try_into().unwrap(),
            address: address.parse().unwrap(),
            tcp: true,
            udp: false,
            http: true,
            https: false,
            socks5: false,
            socks5h: false,
            datacenter: true,
            residential: false,
            mobile: false,
            pool_id: None,
            continent: None,
            country: None,
            state: None,
            city: None,
            carrier: None,
            asn: None,
        }
    }

    #[derive(Debug, Clone)]
    struct OrderedProxyDB(NonEmptyVec<Proxy>);

    impl ProxyDB for OrderedProxyDB {
        type Error = BoxError;

        async fn get_proxies_if(
            &self,
            _ctx: ProxyContext,
            _filter: ProxyFilter,
            predicate: impl ProxyQueryPredicate,
        ) -> Result<NonEmptyVec<Proxy>, Self::Error> {
            NonEmptyVec::collect(
                (&self.0)
                    .into_iter()
                    .filter(|proxy| predicate.execute(proxy))
                    .cloned(),
            )
            .context("ordered test proxy db has no matching proxies")
        }
    }

    #[tokio::test]
    async fn default_mode_retries_all_candidates_and_records_selected_proxy() {
        let first = test_proxy("first", "first:secret@a.example:8080");
        let mut second = test_proxy("second", "second:secret@b.example:1080");
        second.http = false;
        second.socks5 = true;

        let db = OrderedProxyDB(NonEmptyVec::from((first, vec![second.clone()])));
        let attempts = Arc::new(AtomicUsize::new(0));
        let inner = service_fn({
            let attempts = attempts.clone();
            move |input: ConnectRequest| {
                let attempts = attempts.clone();
                async move {
                    let route = input.extensions().get_ref::<ProxyRoute>().unwrap();
                    let proxy_address = route.proxy_address().unwrap();
                    let attempt = attempts.fetch_add(1, Ordering::SeqCst);

                    if attempt == 0 {
                        assert_eq!(
                            proxy_address.to_string(),
                            "http://first-first:secret@a.example:8080"
                        );
                        Err(ConnectionError::transport(
                            BoxError::from_static_str("first proxy unavailable"),
                            ConnectionErrorKind::Unavailable,
                        ))
                    } else {
                        assert_eq!(attempt, 1);
                        assert_eq!(
                            proxy_address.to_string(),
                            "socks5://second-second:secret@b.example:1080"
                        );
                        Ok(EstablishedClientConnection {
                            input,
                            conn: ServiceInput::new(()),
                        })
                    }
                }
            }
        });
        let service = ProxyDBLayer::new(db)
            .with_filter_mode(ProxyFilterMode::Default)
            .with_username_formatter(|proxy: &Proxy, _filter: &ProxyFilter, username: &str| {
                Some(format!("{username}-{}", proxy.id))
            })
            .into_layer(ProxyRoutesConnector::new(inner));
        let input = ConnectRequest::new("www.example.com:443".parse().unwrap());

        let established = service.serve(input).await.unwrap();

        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(
            established
                .extensions()
                .get_ref::<ProxyRouteIndex>()
                .copied()
                .map(ProxyRouteIndex::get),
            Some(1)
        );
        let selected = established.extensions().get_ref::<Proxy>().unwrap();
        assert_eq!(selected.id, second.id);
        assert_eq!(selected.address, second.address);
        assert_eq!(selected.socks5, second.socks5);
        assert_eq!(
            established
                .extensions()
                .get_ref::<crate::ProxyID>()
                .map(crate::ProxyID::as_str),
            Some("second")
        );
    }

    #[tokio::test]
    async fn route_index_correlates_duplicate_proxy_addresses() {
        let first = test_proxy("first", "duplicate.example:8080");
        let second = test_proxy("second", "duplicate.example:8080");
        let db = OrderedProxyDB(NonEmptyVec::from((first, vec![second])));
        let inner = service_fn(async |input: ConnectRequest| {
            if input
                .extensions()
                .get_ref::<ProxyRouteIndex>()
                .copied()
                .map(ProxyRouteIndex::get)
                == Some(0)
            {
                Err(ConnectionError::transport(
                    BoxError::from_static_str("first candidate unavailable"),
                    ConnectionErrorKind::Unavailable,
                ))
            } else {
                Ok(EstablishedClientConnection {
                    input,
                    conn: ServiceInput::new(()),
                })
            }
        });
        let service = ProxyDBLayer::new(db)
            .with_filter_mode(ProxyFilterMode::Default)
            .into_layer(ProxyRoutesConnector::new(inner));

        let established = service
            .serve(ConnectRequest::new("www.example.com:443".parse().unwrap()))
            .await
            .unwrap();

        assert_eq!(
            established
                .extensions()
                .get_ref::<crate::ProxyID>()
                .map(crate::ProxyID::as_str),
            Some("second")
        );
    }

    #[tokio::test]
    async fn existing_singular_route_is_preserved_by_default_in_multi_mode() {
        let db = OrderedProxyDB(NonEmptyVec::new(test_proxy(
            "database",
            "database.example:8080",
        )));
        let service = ProxyDBLayer::new(db)
            .with_filter_mode(ProxyFilterMode::Default)
            .into_layer(service_fn(async |input: Request| {
                Ok::<_, Infallible>(input)
            }));
        let input = Request::builder()
            .uri("https://example.com")
            .body(Body::empty())
            .unwrap();
        input
            .extensions()
            .insert(ProxyRoute::Proxy("existing.example:8080".parse().unwrap()));

        let output = service.serve(input).await.unwrap();

        assert_eq!(
            selected_proxy_address(&output).unwrap().address.to_string(),
            "existing.example:8080"
        );
        assert!(output.extensions().get_ref::<ProxyRoutes>().is_none());
        assert!(output.extensions().get_ref::<Proxy>().is_none());
        assert!(output.extensions().get_ref::<crate::ProxyID>().is_none());
    }

    #[tokio::test]
    async fn single_mode_can_opt_into_overwriting_existing_route() {
        let db = OrderedProxyDB(NonEmptyVec::new(test_proxy(
            "database",
            "database.example:8080",
        )));
        let service = ProxyDBLayer::new(db)
            .with_filter_mode(ProxyFilterMode::Default)
            .with_single_proxy(true)
            .with_overwrite_proxy(true)
            .into_layer(service_fn(async |input: Request| {
                Ok::<_, Infallible>(input)
            }));
        let input = Request::builder()
            .uri("https://example.com")
            .body(Body::empty())
            .unwrap();
        input
            .extensions()
            .insert(ProxyRoute::Proxy("existing.example:8080".parse().unwrap()));

        let output = service.serve(input).await.unwrap();

        assert_eq!(
            selected_proxy_address(&output).unwrap().address.to_string(),
            "database.example:8080"
        );
        assert_eq!(
            output
                .extensions()
                .get_ref::<crate::ProxyID>()
                .map(crate::ProxyID::as_str),
            Some("database")
        );
    }

    #[tokio::test]
    async fn multi_mode_can_opt_into_overwriting_existing_route() {
        let db = OrderedProxyDB(NonEmptyVec::new(test_proxy(
            "database",
            "database.example:8080",
        )));
        let inner = service_fn(async |input: ConnectRequest| {
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(()),
            })
        });
        let service = ProxyDBLayer::new(db)
            .with_filter_mode(ProxyFilterMode::Default)
            .with_overwrite_proxy(true)
            .into_layer(ProxyRoutesConnector::new(inner));
        let input = ConnectRequest::new("www.example.com:443".parse().unwrap());
        input
            .extensions()
            .insert(ProxyRoute::Proxy("existing.example:8080".parse().unwrap()));

        let output = service.serve(input).await.unwrap();

        assert_eq!(
            selected_proxy_address(&output).unwrap().address.to_string(),
            "database.example:8080"
        );
        assert!(
            output
                .extensions()
                .get_ref::<ProxyRoutes>()
                .unwrap()
                .overwrite()
        );
        assert_eq!(
            output
                .extensions()
                .get_ref::<crate::ProxyID>()
                .map(crate::ProxyID::as_str),
            Some("database")
        );
    }

    #[tokio::test]
    async fn optional_mode_without_filter_adds_no_proxy_state() {
        let db = OrderedProxyDB(NonEmptyVec::new(test_proxy(
            "database",
            "database.example:8080",
        )));
        let service = ProxyDBLayer::new(db).into_layer(service_fn(async |input: Request| {
            Ok::<_, Infallible>(input)
        }));
        let input = Request::builder()
            .uri("https://example.com")
            .body(Body::empty())
            .unwrap();

        let output = service.serve(input).await.unwrap();

        assert!(output.extensions().get_ref::<ProxyRoute>().is_none());
        assert!(output.extensions().get_ref::<ProxyRoutes>().is_none());
        assert!(output.extensions().get_ref::<Proxy>().is_none());
        assert!(output.extensions().get_ref::<crate::ProxyID>().is_none());
    }

    #[tokio::test]
    async fn plural_db_miss_does_not_call_inner_or_fall_back_direct() {
        let inner_calls = Arc::new(AtomicUsize::new(0));
        let service = ProxyDBLayer::new(())
            .with_filter_mode(ProxyFilterMode::Default)
            .into_layer(service_fn({
                let inner_calls = inner_calls.clone();
                move |input: Request| {
                    inner_calls.fetch_add(1, Ordering::SeqCst);
                    async move { Ok::<_, Infallible>(input) }
                }
            }));
        let input = Request::builder()
            .uri("https://example.com")
            .body(Body::empty())
            .unwrap();

        service.serve(input).await.unwrap_err();

        assert_eq!(inner_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_proxy_db_default_happy_path_example() {
        let db = MemoryProxyDB::try_from_iter([
            Proxy {
                id: non_empty_str!("42"),
                address: ProxyAddress::from_str("12.34.12.34:8080").unwrap(),
                tcp: true,
                udp: true,
                http: true,
                https: true,
                socks5: true,
                socks5h: true,
                datacenter: false,
                residential: true,
                mobile: true,
                pool_id: None,
                continent: Some("*".into()),
                country: Some("*".into()),
                state: Some("*".into()),
                city: Some("*".into()),
                carrier: Some("*".into()),
                asn: Some(Asn::unspecified()),
            },
            Proxy {
                id: non_empty_str!("100"),
                address: ProxyAddress::from_str("12.34.12.35:8080").unwrap(),
                tcp: true,
                udp: false,
                http: true,
                https: true,
                socks5: false,
                socks5h: false,
                datacenter: true,
                residential: false,
                mobile: false,
                pool_id: None,
                continent: Some("americas".into()),
                country: Some("US".into()),
                state: None,
                city: None,
                carrier: None,
                asn: Some(Asn::unspecified()),
            },
        ])
        .unwrap();

        let service = ProxyDBLayer::new(Arc::new(db))
            .with_filter_mode(ProxyFilterMode::Default)
            .into_layer(ProxyRoutesConnector::new(service_fn(
                async |req: ConnectRequest| {
                    Ok::<_, ConnectionError>(EstablishedClientConnection {
                        input: req,
                        conn: ServiceInput::new(()),
                    })
                },
            )));

        let req = ConnectRequest::new("www.example.com:443".parse().unwrap())
            .with_application_protocol(Protocol::HTTPS);

        req.extensions().insert(ProxyFilter {
            country: Some(vec!["BE".into()]),
            mobile: Some(true),
            residential: Some(true),
            ..Default::default()
        });

        let established = service.serve(req).await.unwrap();
        let proxy_address = selected_proxy_address(&established).unwrap();
        assert_eq!(
            proxy_address.address,
            HostWithPort::from(([12, 34, 12, 34], 8080))
        );
        assert_eq!(
            established
                .extensions()
                .get_ref::<Proxy>()
                .map(|p| p.id.as_ref()),
            Some("42")
        );
        assert_eq!(
            established
                .extensions()
                .get_ref::<crate::ProxyID>()
                .map(crate::ProxyID::as_str),
            Some("42")
        );
    }

    #[tokio::test]
    async fn test_proxy_db_single_proxy_example() {
        let proxy = Proxy {
            id: non_empty_str!("42"),
            address: ProxyAddress::from_str("12.34.12.34:8080").unwrap(),
            tcp: true,
            udp: true,
            http: true,
            https: true,
            socks5: true,
            socks5h: true,
            datacenter: false,
            residential: true,
            mobile: true,
            pool_id: None,
            continent: Some("*".into()),
            country: Some("*".into()),
            state: Some("*".into()),
            city: Some("*".into()),
            carrier: Some("*".into()),
            asn: Some(Asn::unspecified()),
        };

        let service = ProxyDBLayer::new(Arc::new(proxy))
            .with_filter_mode(ProxyFilterMode::Default)
            .with_single_proxy(true)
            .into_layer(service_fn(async |req: Request| Ok::<_, Infallible>(req)));

        let req = Request::builder()
            .version(Version::HTTP_3)
            .method("GET")
            .uri("https://example.com")
            .body(Body::empty())
            .unwrap();

        req.extensions().insert(ProxyFilter {
            country: Some(vec!["BE".into()]),
            mobile: Some(true),
            residential: Some(true),
            ..Default::default()
        });

        let output = service.serve(req).await.unwrap();
        let proxy_address = selected_proxy_address(&output).unwrap();
        assert_eq!(
            proxy_address.address,
            HostWithPort::from(([12, 34, 12, 34], 8080))
        );
        assert!(output.extensions().get_ref::<ProxyRoutes>().is_none());
        assert_eq!(
            output
                .extensions()
                .get_ref::<Proxy>()
                .map(|p| p.id.as_ref()),
            Some("42")
        );
    }

    #[tokio::test]
    async fn test_proxy_db_single_proxy_with_username_formatter() {
        let proxy = Proxy {
            id: non_empty_str!("42"),
            address: ProxyAddress::from_str("john:secret@12.34.12.34:8080").unwrap(),
            tcp: true,
            udp: true,
            http: true,
            https: true,
            socks5: true,
            socks5h: true,
            datacenter: false,
            residential: true,
            mobile: true,
            pool_id: Some("routers".into()),
            continent: Some("*".into()),
            country: Some("*".into()),
            state: Some("*".into()),
            city: Some("*".into()),
            carrier: Some("*".into()),
            asn: Some(Asn::unspecified()),
        };

        let service = ProxyDBLayer::new(Arc::new(proxy))
            .with_filter_mode(ProxyFilterMode::Default)
            .with_single_proxy(true)
            .with_username_formatter(|proxy: &Proxy, filter: &ProxyFilter, username: &str| {
                if proxy
                    .pool_id
                    .as_ref()
                    .map(|id| id.as_ref() == "routers")
                    .unwrap_or_default()
                {
                    use std::fmt::Write;

                    let mut output = String::new();

                    if let Some(countries) = filter.country.as_ref().filter(|t| !t.is_empty()) {
                        _ = write!(output, "country-{}", countries[0]);
                    }
                    if let Some(states) = filter.state.as_ref().filter(|t| !t.is_empty()) {
                        _ = write!(output, "state-{}", states[0]);
                    }

                    return (!output.is_empty()).then(|| format!("{username}-{output}"));
                }

                None
            })
            .into_layer(service_fn(async |req: Request| Ok::<_, Infallible>(req)));

        let req = Request::builder()
            .version(Version::HTTP_3)
            .method("GET")
            .uri("https://example.com")
            .body(Body::empty())
            .unwrap();

        req.extensions().insert(ProxyFilter {
            country: Some(vec!["BE".into()]),
            mobile: Some(true),
            residential: Some(true),
            ..Default::default()
        });

        let output = service.serve(req).await.unwrap();
        let proxy_address = selected_proxy_address(&output).unwrap();
        assert_eq!(
            "socks5://john-country-be:secret@12.34.12.34:8080",
            proxy_address.to_string()
        );
    }

    #[tokio::test]
    async fn test_proxy_db_legacy_single_proxy_transport_layer() {
        let db = MemoryProxyDB::try_from_iter([
            Proxy {
                id: non_empty_str!("42"),
                address: ProxyAddress::from_str("12.34.12.34:8080").unwrap(),
                tcp: true,
                udp: true,
                http: true,
                https: true,
                socks5: true,
                socks5h: true,
                datacenter: false,
                residential: true,
                mobile: true,
                pool_id: None,
                continent: Some("*".into()),
                country: Some("*".into()),
                state: Some("*".into()),
                city: Some("*".into()),
                carrier: Some("*".into()),
                asn: Some(Asn::unspecified()),
            },
            Proxy {
                id: non_empty_str!("100"),
                address: ProxyAddress::from_str("12.34.12.35:8080").unwrap(),
                tcp: true,
                udp: false,
                http: true,
                https: true,
                socks5: false,
                socks5h: false,
                datacenter: true,
                residential: false,
                mobile: false,
                pool_id: None,
                continent: Some("americas".into()),
                country: Some("US".into()),
                state: None,
                city: None,
                carrier: None,
                asn: Some(Asn::unspecified()),
            },
        ])
        .unwrap();

        let service = ProxyDBLayer::new(Arc::new(db))
            .with_filter_mode(ProxyFilterMode::Default)
            .with_single_proxy(true)
            .into_layer(service_fn(async |req: ConnectRequest| {
                Ok::<_, Infallible>(req)
            }));

        let req = ConnectRequest::new("www.example.com:443".parse().unwrap())
            .with_application_protocol(Protocol::HTTPS);

        req.extensions().insert(ProxyFilter {
            country: Some(vec!["BE".into()]),
            mobile: Some(true),
            residential: Some(true),
            ..Default::default()
        });

        let output = service.serve(req).await.unwrap();
        let proxy_address = selected_proxy_address(&output).unwrap();
        assert_eq!(
            proxy_address.address,
            HostWithPort::from(([12, 34, 12, 34], 8080))
        );
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
    async fn single_mode_preserves_existing_proxy_address_by_default() {
        let db = memproxydb().await;

        let service = ProxyDBLayer::new(Arc::new(db))
            .with_filter_mode(ProxyFilterMode::Default)
            .with_single_proxy(true)
            .into_layer(service_fn(async |req: Request| Ok::<_, Infallible>(req)));

        let req = Request::builder()
            .version(Version::HTTP_11)
            .method("GET")
            .uri("http://example.com")
            .body(Body::empty())
            .unwrap();

        req.extensions().insert(ProxyRoute::Proxy(
            ProxyAddress::try_from("http://john:secret@1.2.3.4:1234").unwrap(),
        ));

        let output = service.serve(req).await.unwrap();
        let proxy_address = selected_proxy_address(&output).unwrap();

        assert_eq!(proxy_address.address.to_string(), "1.2.3.4:1234");
        assert!(output.extensions().get_ref::<Proxy>().is_none());
        assert!(output.extensions().get_ref::<crate::ProxyID>().is_none());
    }

    #[tokio::test]
    async fn test_proxy_db_service_optional() {
        let db = memproxydb().await;

        let service = ProxyDBLayer::new(Arc::new(db))
            .with_single_proxy(true)
            .into_layer(service_fn(async |req: Request| Ok::<_, Infallible>(req)));

        for (filter, expected_authority, req) in [
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
                    id: Some(non_empty_str!("3031533634")),
                    ..Default::default()
                }),
                Some("105.150.55.60:4898"),
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
                Some("140.249.154.18:5800"),
                Request::builder()
                    .version(Version::HTTP_3)
                    .method("GET")
                    .uri("https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
        ] {
            if let Some(filter) = filter {
                req.extensions().insert(filter);
            }

            let output = service.serve(req).await.unwrap();
            let maybe_proxy_address = selected_proxy_address(&output);

            assert_eq!(
                maybe_proxy_address.map(|p| p.address.clone()),
                expected_authority.map(|s| HostWithPort::try_from(s).unwrap())
            );
        }
    }

    #[tokio::test]
    async fn test_proxy_db_legacy_single_proxy_default_filter() {
        let db = memproxydb().await;

        let service = ProxyDBLayer::new(Arc::new(db))
            .with_filter_mode(ProxyFilterMode::Default)
            .with_single_proxy(true)
            .into_layer(service_fn(async |req: Request| Ok::<_, Infallible>(req)));

        for (filter, expected_addresses, req_info) in [
            (
                None,
                "0.20.204.227:8373,104.207.92.167:9387,105.150.55.60:4898,106.213.197.28:9110,113.6.21.212:4525,115.29.251.35:5712,119.146.94.132:7851,129.204.152.130:6524,134.190.189.202:5772,136.186.95.10:7095,137.220.180.169:4929,140.249.154.18:5800,145.57.31.149:6304,151.254.135.9:6961,153.206.209.221:8696,162.97.174.152:1673,169.179.161.206:6843,171.174.56.89:5744,178.189.117.217:6496,182.34.76.182:2374,184.209.230.177:1358,193.188.239.29:3541,193.26.37.125:3780,204.168.216.113:1096,208.224.120.97:7118,209.176.177.182:4311,215.49.63.89:9458,223.234.242.63:7211,230.159.143.41:7296,233.22.59.115:1653,24.155.249.112:2645,247.118.71.100:1033,249.221.15.121:7434,252.69.242.136:4791,253.138.153.41:2640,28.139.151.127:2809,4.20.243.186:9155,42.54.35.118:6846,45.59.69.12:5934,46.247.45.238:3522,54.226.47.54:7442,61.112.212.160:3842,66.142.40.209:4251,66.171.139.181:4449,69.246.162.84:8964,75.43.123.181:7719,76.128.58.167:4797,85.14.163.105:8362,92.227.104.237:6161,97.192.206.72:6067",
                (Version::HTTP_11, "GET", "http://example.com"),
            ),
            (
                Some(ProxyFilter {
                    country: Some(vec![StringFilter::new("BE")]),
                    mobile: Some(true),
                    residential: Some(true),
                    ..Default::default()
                }),
                "140.249.154.18:5800",
                (Version::HTTP_3, "GET", "https://example.com"),
            ),
        ] {
            let mut seen_addresses = Vec::new();
            for _ in 0..5000 {
                let req = Request::builder()
                    .version(req_info.0)
                    .method(req_info.1)
                    .uri(req_info.2)
                    .body(Body::empty())
                    .unwrap();

                if let Some(filter) = filter.clone() {
                    req.extensions().insert(filter);
                }

                let output = service.serve(req).await.unwrap();
                let proxy_address = selected_proxy_address(&output).unwrap().address.to_string();

                if !seen_addresses.contains(&proxy_address) {
                    seen_addresses.push(proxy_address);
                }
            }

            let seen_addresses = seen_addresses.into_iter().sorted().join(",");
            assert_eq!(seen_addresses, expected_addresses);
        }
    }

    #[tokio::test]
    async fn test_proxy_db_legacy_single_proxy_fallback_filter() {
        let db = memproxydb().await;

        let service = ProxyDBLayer::new(Arc::new(db))
            .with_filter_mode(ProxyFilterMode::Fallback(ProxyFilter {
                datacenter: Some(true),
                residential: Some(false),
                mobile: Some(false),
                ..Default::default()
            }))
            .with_single_proxy(true)
            .into_layer(service_fn(async |req: Request| Ok::<_, Infallible>(req)));

        for (filter, expected_addresses, req_info) in [
            (
                None,
                "113.6.21.212:4525,119.146.94.132:7851,136.186.95.10:7095,137.220.180.169:4929,247.118.71.100:1033,249.221.15.121:7434,92.227.104.237:6161",
                (Version::HTTP_11, "GET", "http://example.com"),
            ),
            (
                Some(ProxyFilter {
                    country: Some(vec![StringFilter::new("BE")]),
                    mobile: Some(true),
                    residential: Some(true),
                    ..Default::default()
                }),
                "140.249.154.18:5800",
                (Version::HTTP_3, "GET", "https://example.com"),
            ),
        ] {
            let mut seen_addresses = Vec::new();
            for _ in 0..5000 {
                let req = Request::builder()
                    .version(req_info.0)
                    .method(req_info.1)
                    .uri(req_info.2)
                    .body(Body::empty())
                    .unwrap();

                if let Some(filter) = filter.clone() {
                    req.extensions().insert(filter);
                }

                let output = service.serve(req).await.unwrap();
                let proxy_address = selected_proxy_address(&output).unwrap().address.to_string();

                if !seen_addresses.contains(&proxy_address) {
                    seen_addresses.push(proxy_address);
                }
            }

            let seen_addresses = seen_addresses.into_iter().sorted().join(",");
            assert_eq!(seen_addresses, expected_addresses);
        }
    }

    #[tokio::test]
    async fn test_proxy_db_service_required() {
        let db = memproxydb().await;

        let service = ProxyDBLayer::new(Arc::new(db))
            .with_filter_mode(ProxyFilterMode::Required)
            .with_single_proxy(true)
            .into_layer(service_fn(async |req: Request| Ok::<_, Infallible>(req)));

        for (filter, expected_address, req) in [
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
                    country: Some(vec![StringFilter::new("BE")]),
                    mobile: Some(true),
                    residential: Some(true),
                    ..Default::default()
                }),
                Some("140.249.154.18:5800"),
                Request::builder()
                    .version(Version::HTTP_3)
                    .method("GET")
                    .uri("https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
            (
                Some(ProxyFilter {
                    id: Some(non_empty_str!("FooBar")),
                    ..Default::default()
                }),
                None,
                Request::builder()
                    .version(Version::HTTP_3)
                    .method("GET")
                    .uri("https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
            (
                Some(ProxyFilter {
                    id: Some(non_empty_str!("1316455915")),
                    country: Some(vec![StringFilter::new("BE")]),
                    mobile: Some(true),
                    residential: Some(true),
                    ..Default::default()
                }),
                None,
                Request::builder()
                    .version(Version::HTTP_3)
                    .method("GET")
                    .uri("https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
        ] {
            if let Some(filter) = filter.clone() {
                req.extensions().insert(filter);
            }

            let proxy_address_result = service.serve(req).await;
            match expected_address {
                Some(expected_address) => {
                    assert_eq!(
                        selected_proxy_address(&proxy_address_result.unwrap())
                            .unwrap()
                            .address,
                        HostWithPort::try_from(expected_address).unwrap()
                    );
                }
                None => {
                    proxy_address_result.unwrap_err();
                }
            }
        }
    }

    #[tokio::test]
    async fn test_proxy_db_service_required_with_predicate() {
        let db = memproxydb().await;

        let service = ProxyDBLayer::new(Arc::new(db))
            .with_filter_mode(ProxyFilterMode::Required)
            .with_single_proxy(true)
            .with_select_predicate(|proxy: &Proxy| proxy.mobile)
            .into_layer(service_fn(async |req: Request| Ok::<_, Infallible>(req)));

        for (filter, expected, req) in [
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
                    country: Some(vec![StringFilter::new("BE")]),
                    mobile: Some(true),
                    residential: Some(true),
                    ..Default::default()
                }),
                Some("140.249.154.18:5800"),
                Request::builder()
                    .version(Version::HTTP_3)
                    .method("GET")
                    .uri("https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
            (
                Some(ProxyFilter {
                    id: Some(non_empty_str!("FooBar")),
                    ..Default::default()
                }),
                None,
                Request::builder()
                    .version(Version::HTTP_3)
                    .method("GET")
                    .uri("https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
            (
                Some(ProxyFilter {
                    id: Some(non_empty_str!("1316455915")),
                    country: Some(vec![StringFilter::new("BE")]),
                    mobile: Some(true),
                    residential: Some(true),
                    ..Default::default()
                }),
                None,
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
                    id: Some(non_empty_str!("1316455915")),
                    ..Default::default()
                }),
                None,
                Request::builder()
                    .version(Version::HTTP_3)
                    .method("GET")
                    .uri("https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            ),
        ] {
            if let Some(filter) = filter {
                req.extensions().insert(filter);
            }

            let proxy_result = service.serve(req).await;
            match expected {
                Some(expected_address) => {
                    assert_eq!(
                        selected_proxy_address(&proxy_result.unwrap())
                            .unwrap()
                            .address,
                        HostWithPort::try_from(expected_address).unwrap()
                    );
                }
                None => {
                    proxy_result.unwrap_err();
                }
            }
        }
    }
}
