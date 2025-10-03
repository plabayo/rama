use super::{Proxy, ProxyContext, ProxyDB, ProxyFilter, ProxyQueryPredicate};
use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext, ErrorExt, OpaqueError},
    extensions::ExtensionsMut,
};
use rama_net::{
    Protocol,
    address::ProxyAddress,
    transport::{TransportProtocol, TryRefIntoTransportContext},
    user::{Basic, ProxyCredential},
};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// A [`Service`] which selects a [`Proxy`] based on the given [`Context`].
///
/// Depending on the [`ProxyFilterMode`] the selection proxies might be optional,
/// or use the default [`ProxyFilter`] in case none is defined.
///
/// A predicate can be used to provide additional filtering on the found proxies,
/// that otherwise did match the used [`ProxyFilter`].
///
/// See [the crate docs](crate) for examples and more info on the usage of this service.
///
/// [`Proxy`]: crate::Proxy
pub struct ProxyDBService<S, D, P, F> {
    inner: S,
    db: D,
    mode: ProxyFilterMode,
    predicate: P,
    username_formatter: F,
    preserve: bool,
}

#[derive(Debug, Clone, Default)]
/// The modus operandi to decide how to deal with a missing [`ProxyFilter`] in the [`Context`]
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

impl<S, D, P, F> fmt::Debug for ProxyDBService<S, D, P, F>
where
    S: fmt::Debug,
    D: fmt::Debug,
    P: fmt::Debug,
    F: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyDBService")
            .field("inner", &self.inner)
            .field("db", &self.db)
            .field("mode", &self.mode)
            .field("predicate", &self.predicate)
            .field("username_formatter", &self.username_formatter)
            .field("preserve", &self.preserve)
            .finish()
    }
}

impl<S, D, P, F> Clone for ProxyDBService<S, D, P, F>
where
    S: Clone,
    D: Clone,
    P: Clone,
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            db: self.db.clone(),
            mode: self.mode.clone(),
            predicate: self.predicate.clone(),
            username_formatter: self.username_formatter.clone(),
            preserve: self.preserve,
        }
    }
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
            preserve: false,
        }
    }
}

impl<S, D, P, F> ProxyDBService<S, D, P, F> {
    /// Set a [`ProxyFilterMode`] to define the behaviour surrounding
    /// [`ProxyFilter`] usage, e.g. if a proxy filter is required to be available or not,
    /// or what to do if it is optional and not available.
    #[must_use]
    pub fn filter_mode(mut self, mode: ProxyFilterMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set a [`ProxyFilterMode`] to define the behaviour surrounding
    /// [`ProxyFilter`] usage, e.g. if a proxy filter is required to be available or not,
    /// or what to do if it is optional and not available.
    pub fn set_filter_mode(&mut self, mode: ProxyFilterMode) -> &mut Self {
        self.mode = mode;
        self
    }

    /// Define whether or not an existing [`ProxyAddress`] (in the [`Context`])
    /// should be overwritten or not. By default `preserve=false`,
    /// meaning we will overwrite the proxy address in case we selected one now.
    ///
    /// NOTE even when `preserve=false` it might still be that there's
    /// a [`ProxyAddress`] in case it was set by a previous layer.
    #[must_use]
    pub const fn preserve_proxy(mut self, preserve: bool) -> Self {
        self.preserve = preserve;
        self
    }

    /// Define whether or not an existing [`ProxyAddress`] (in the [`Context`])
    /// should be overwritten or not. By default `preserve=false`,
    /// meaning we will overwrite the proxy address in case we selected one now.
    ///
    /// NOTE even when `preserve=false` it might still be that there's
    /// a [`ProxyAddress`] in case it was set by a previous layer.
    pub fn set_preserve_proxy(&mut self, preserve: bool) -> &mut Self {
        self.preserve = preserve;
        self
    }

    /// Set a [`ProxyQueryPredicate`] that will be used
    /// to possibly filter out proxies that according to the filters are correct,
    /// but not according to the predicate.
    pub fn select_predicate<Predicate>(self, p: Predicate) -> ProxyDBService<S, D, Predicate, F> {
        ProxyDBService {
            inner: self.inner,
            db: self.db,
            mode: self.mode,
            predicate: p,
            username_formatter: self.username_formatter,
            preserve: self.preserve,
        }
    }

    /// Set a [`UsernameFormatter`][crate::UsernameFormatter] that will be used to format
    /// the username based on the selected [`Proxy`]. This is required
    /// in case the proxy is a router that accepts or maybe even requires
    /// username labels to configure proxies further down/up stream.
    pub fn username_formatter<Formatter>(self, f: Formatter) -> ProxyDBService<S, D, P, Formatter> {
        ProxyDBService {
            inner: self.inner,
            db: self.db,
            mode: self.mode,
            predicate: self.predicate,
            username_formatter: f,
            preserve: self.preserve,
        }
    }

    define_inner_service_accessors!();
}

impl<S, D, P, F, Request> Service<Request> for ProxyDBService<S, D, P, F>
where
    S: Service<Request, Error: Into<BoxError> + Send + Sync + 'static>,
    D: ProxyDB<Error: Into<BoxError> + Send + Sync + 'static>,
    P: ProxyQueryPredicate,
    F: UsernameFormatter,
    Request: TryRefIntoTransportContext<Error: Into<BoxError> + Send + 'static>
        + ExtensionsMut
        + Send
        + 'static,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn serve(&self, mut req: Request) -> Result<Self::Response, Self::Error> {
        if self.preserve && req.extensions().contains::<ProxyAddress>() {
            // shortcut in case a proxy address is already set,
            // and we wish to preserve it
            return self.inner.serve(req).await.map_err(Into::into);
        }

        let maybe_filter = match self.mode {
            ProxyFilterMode::Optional => req.extensions().get::<ProxyFilter>().cloned(),
            ProxyFilterMode::Default => Some(
                req.extensions_mut()
                    .get_or_insert_default::<ProxyFilter>()
                    .clone(),
            ),
            ProxyFilterMode::Required => Some(
                req.extensions()
                    .get::<ProxyFilter>()
                    .cloned()
                    .context("missing proxy filter")?,
            ),
            ProxyFilterMode::Fallback(ref filter) => Some(
                req.extensions_mut()
                    .get_or_insert_with(|| filter.clone())
                    .clone(),
            ),
        };

        if let Some(filter) = maybe_filter {
            let transport_ctx = req.try_ref_into_transport_ctx().map_err(|err| {
                OpaqueError::from_boxed(err.into())
                    .context("proxydb: select proxy: get transport context")
            })?;

            let proxy_ctx = ProxyContext::from(transport_ctx);

            let transport_protocol = proxy_ctx.protocol;

            let proxy = self
                .db
                .get_proxy_if(proxy_ctx, filter.clone(), self.predicate.clone())
                .await
                .map_err(|err| {
                    OpaqueError::from_std(ProxySelectError {
                        inner: err.into(),
                        filter: filter.clone(),
                    })
                })?;

            let mut proxy_address = proxy.address.clone();

            // prepare the credential with labels in username if desired
            proxy_address.credential = proxy_address.credential.take().map(|credential| {
                match credential {
                    ProxyCredential::Basic(ref basic) => {
                        match self.username_formatter.fmt_username(
                            &proxy,
                            &filter,
                            basic.username(),
                        ) {
                            Some(username) => ProxyCredential::Basic(Basic::new(
                                username,
                                basic.password().to_owned(),
                            )),
                            None => credential, // nothing to do
                        }
                    }
                    ProxyCredential::Bearer(_) => credential, // Remark: we can support this in future too if needed
                }
            });

            // overwrite the proxy protocol if not set yet
            if proxy_address.protocol.is_none() {
                proxy_address.protocol = match transport_protocol {
                    TransportProtocol::Udp => {
                        if proxy.socks5 {
                            Some(Protocol::SOCKS5)
                        } else if proxy.socks5h {
                            Some(Protocol::SOCKS5H)
                        } else {
                            return Err(OpaqueError::from_display(
                                "selected udp proxy does not have a valid protocol available (db bug?!)",
                            )
                            .into());
                        }
                    }
                    TransportProtocol::Tcp => match proxy_address.authority.port() {
                        80 | 8080 if proxy.http => Some(Protocol::HTTP),
                        443 | 8443 if proxy.https => Some(Protocol::HTTPS),
                        1080 if proxy.socks5 => Some(Protocol::SOCKS5),
                        1080 if proxy.socks5h => Some(Protocol::SOCKS5H),
                        _ => {
                            // speed: Socks5 > Http > Https
                            if proxy.socks5 {
                                Some(Protocol::SOCKS5)
                            } else if proxy.socks5h {
                                Some(Protocol::SOCKS5H)
                            } else if proxy.http {
                                Some(Protocol::HTTP)
                            } else if proxy.https {
                                Some(Protocol::HTTPS)
                            } else {
                                return Err(OpaqueError::from_display(
                                "selected tcp proxy does not have a valid protocol available (db bug?!)",
                            )
                            .into());
                            }
                        }
                    },
                };
            }

            // insert proxy address in context so it will be used
            req.extensions_mut().insert(proxy_address);

            // insert the id of the selected proxy
            req.extensions_mut()
                .insert(super::ProxyID::from(proxy.id.clone()));

            // insert the entire proxy also in there, for full "Context"
            req.extensions_mut().insert(proxy);
        }

        self.inner.serve(req).await.map_err(Into::into)
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

/// A [`Layer`] which wraps an inner [`Service`] to select a [`Proxy`] based on the given [`Context`],
/// and insert, if a [`Proxy`] is selected, it in the [`Context`] for further processing.
///
/// See [the crate docs](crate) for examples and more info on the usage of this service.
pub struct ProxyDBLayer<D, P, F> {
    db: D,
    mode: ProxyFilterMode,
    predicate: P,
    username_formatter: F,
    preserve: bool,
}

impl<D, P, F> fmt::Debug for ProxyDBLayer<D, P, F>
where
    D: fmt::Debug,
    P: fmt::Debug,
    F: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyDBLayer")
            .field("db", &self.db)
            .field("mode", &self.mode)
            .field("predicate", &self.predicate)
            .field("username_formatter", &self.username_formatter)
            .field("preserve", &self.preserve)
            .finish()
    }
}

impl<D, P, F> Clone for ProxyDBLayer<D, P, F>
where
    D: Clone,
    P: Clone,
    F: Clone,
{
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            mode: self.mode.clone(),
            predicate: self.predicate.clone(),
            username_formatter: self.username_formatter.clone(),
            preserve: self.preserve,
        }
    }
}

impl<D> ProxyDBLayer<D, bool, ()> {
    /// Create a new [`ProxyDBLayer`] with the given [`ProxyDB`].
    pub const fn new(db: D) -> Self {
        Self {
            db,
            mode: ProxyFilterMode::Optional,
            predicate: true,
            username_formatter: (),
            preserve: false,
        }
    }
}

impl<D, P, F> ProxyDBLayer<D, P, F> {
    /// Set a [`ProxyFilterMode`] to define the behaviour surrounding
    /// [`ProxyFilter`] usage, e.g. if a proxy filter is required to be available or not,
    /// or what to do if it is optional and not available.
    #[must_use]
    pub fn filter_mode(mut self, mode: ProxyFilterMode) -> Self {
        self.mode = mode;
        self
    }

    /// Define whether or not an existing [`ProxyAddress`] (in the [`Context`])
    /// should be overwritten or not. By default `preserve=false`,
    /// meaning we will overwrite the proxy address in case we selected one now.
    ///
    /// NOTE even when `preserve=false` it might still be that there's
    /// a [`ProxyAddress`] in case it was set by a previous layer.
    #[must_use]
    pub fn preserve_proxy(mut self, preserve: bool) -> Self {
        self.preserve = preserve;
        self
    }

    /// Set a [`ProxyQueryPredicate`] that will be used
    /// to possibly filter out proxies that according to the filters are correct,
    /// but not according to the predicate.
    #[must_use]
    pub fn select_predicate<Predicate>(self, p: Predicate) -> ProxyDBLayer<D, Predicate, F> {
        ProxyDBLayer {
            db: self.db,
            mode: self.mode,
            predicate: p,
            username_formatter: self.username_formatter,
            preserve: self.preserve,
        }
    }

    /// Set a [`UsernameFormatter`][crate::UsernameFormatter] that will be used to format
    /// the username based on the selected [`Proxy`]. This is required
    /// in case the proxy is a router that accepts or maybe even requires
    /// username labels to configure proxies further down/up stream.
    #[must_use]
    pub fn username_formatter<Formatter>(self, f: Formatter) -> ProxyDBLayer<D, P, Formatter> {
        ProxyDBLayer {
            db: self.db,
            mode: self.mode,
            predicate: self.predicate,
            username_formatter: f,
            preserve: self.preserve,
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
            preserve: self.preserve,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ProxyDBService {
            inner,
            db: self.db,
            mode: self.mode,
            predicate: self.predicate,
            username_formatter: self.username_formatter,
            preserve: self.preserve,
        }
    }
}

/// Trait that is used to allow the formatting of a username,
/// e.g. to allow proxy routers to have proxy config labels in the username.
pub trait UsernameFormatter: Send + Sync + 'static {
    /// format the username based on the root properties of the given proxy.
    fn fmt_username(&self, proxy: &Proxy, filter: &ProxyFilter, username: &str) -> Option<String>;
}

impl UsernameFormatter for () {
    fn fmt_username(
        &self,
        _proxy: &Proxy,
        _filter: &ProxyFilter,
        _username: &str,
    ) -> Option<String> {
        None
    }
}

impl<F> UsernameFormatter for F
where
    F: Fn(&Proxy, &ProxyFilter, &str) -> Option<String> + Send + Sync + 'static,
{
    fn fmt_username(&self, proxy: &Proxy, filter: &ProxyFilter, username: &str) -> Option<String> {
        (self)(proxy, filter, username)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryProxyDB, Proxy, ProxyCsvRowReader, StringFilter};
    use itertools::Itertools;
    use rama_core::{
        extensions::{Extensions, ExtensionsRef},
        service::service_fn,
    };
    use rama_http_types::{Body, Request, Version};
    use rama_net::{
        Protocol,
        address::{Authority, ProxyAddress},
        asn::Asn,
    };
    use rama_utils::str::NonEmptyString;
    use std::{convert::Infallible, str::FromStr, sync::Arc};

    #[tokio::test]
    async fn test_proxy_db_default_happy_path_example() {
        let db = MemoryProxyDB::try_from_iter([
            Proxy {
                id: NonEmptyString::from_static("42"),
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
                id: NonEmptyString::from_static("100"),
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
            .filter_mode(ProxyFilterMode::Default)
            .into_layer(service_fn(async |req: Request| {
                Ok::<_, Infallible>(req.extensions().get::<ProxyAddress>().unwrap().clone())
            }));

        let mut req = Request::builder()
            .version(Version::HTTP_3)
            .method("GET")
            .uri("https://example.com")
            .body(Body::empty())
            .unwrap();

        req.extensions_mut().insert(ProxyFilter {
            country: Some(vec!["BE".into()]),
            mobile: Some(true),
            residential: Some(true),
            ..Default::default()
        });

        let proxy_address = service.serve(req).await.unwrap();
        assert_eq!(
            proxy_address.authority,
            Authority::try_from("12.34.12.34:8080").unwrap()
        );
    }

    #[tokio::test]
    async fn test_proxy_db_single_proxy_example() {
        let proxy = Proxy {
            id: NonEmptyString::from_static("42"),
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
            .filter_mode(ProxyFilterMode::Default)
            .into_layer(service_fn(async |req: Request| {
                Ok::<_, Infallible>(req.extensions().get::<ProxyAddress>().unwrap().clone())
            }));

        let mut req = Request::builder()
            .version(Version::HTTP_3)
            .method("GET")
            .uri("https://example.com")
            .body(Body::empty())
            .unwrap();

        req.extensions_mut().insert(ProxyFilter {
            country: Some(vec!["BE".into()]),
            mobile: Some(true),
            residential: Some(true),
            ..Default::default()
        });

        let proxy_address = service.serve(req).await.unwrap();
        assert_eq!(
            proxy_address.authority,
            Authority::try_from("12.34.12.34:8080").unwrap()
        );
    }

    #[tokio::test]
    async fn test_proxy_db_single_proxy_with_username_formatter() {
        let proxy = Proxy {
            id: NonEmptyString::from_static("42"),
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
            .filter_mode(ProxyFilterMode::Default)
            .username_formatter(|proxy: &Proxy, filter: &ProxyFilter, username: &str| {
                if proxy
                    .pool_id
                    .as_ref()
                    .map(|id| id.as_ref() == "routers")
                    .unwrap_or_default()
                {
                    use std::fmt::Write;

                    let mut output = String::new();

                    if let Some(countries) = filter.country.as_ref().filter(|t| !t.is_empty()) {
                        let _ = write!(output, "country-{}", countries[0]);
                    }
                    if let Some(states) = filter.state.as_ref().filter(|t| !t.is_empty()) {
                        let _ = write!(output, "state-{}", states[0]);
                    }

                    return (!output.is_empty()).then(|| format!("{username}-{output}"));
                }

                None
            })
            .into_layer(service_fn(async |req: Request| {
                Ok::<_, Infallible>(req.extensions().get::<ProxyAddress>().unwrap().clone())
            }));

        let mut req = Request::builder()
            .version(Version::HTTP_3)
            .method("GET")
            .uri("https://example.com")
            .body(Body::empty())
            .unwrap();

        req.extensions_mut().insert(ProxyFilter {
            country: Some(vec!["BE".into()]),
            mobile: Some(true),
            residential: Some(true),
            ..Default::default()
        });

        let proxy_address = service.serve(req).await.unwrap();
        assert_eq!(
            "socks5://john-country-be:secret@12.34.12.34:8080",
            proxy_address.to_string()
        );
    }

    #[tokio::test]
    async fn test_proxy_db_default_happy_path_example_transport_layer() {
        let db = MemoryProxyDB::try_from_iter([
            Proxy {
                id: NonEmptyString::from_static("42"),
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
                id: NonEmptyString::from_static("100"),
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
            .filter_mode(ProxyFilterMode::Default)
            .into_layer(service_fn(async |req: rama_tcp::client::Request| {
                Ok::<_, Infallible>(req.extensions().get::<ProxyAddress>().unwrap().clone())
            }));

        let mut req = rama_tcp::client::Request::new(
            "www.example.com:443".parse().unwrap(),
            Extensions::new(),
        )
        .with_protocol(Protocol::HTTPS);

        req.extensions_mut().insert(ProxyFilter {
            country: Some(vec!["BE".into()]),
            mobile: Some(true),
            residential: Some(true),
            ..Default::default()
        });

        let proxy_address = service.serve(req).await.unwrap();
        assert_eq!(
            proxy_address.authority,
            Authority::try_from("12.34.12.34:8080").unwrap()
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
    async fn test_proxy_db_service_preserve_proxy_address() {
        let db = memproxydb().await;

        let service = ProxyDBLayer::new(Arc::new(db))
            .preserve_proxy(true)
            .filter_mode(ProxyFilterMode::Default)
            .into_layer(service_fn(async |req: Request| {
                Ok::<_, Infallible>(req.extensions().get::<ProxyAddress>().unwrap().clone())
            }));

        let mut req = Request::builder()
            .version(Version::HTTP_11)
            .method("GET")
            .uri("http://example.com")
            .body(Body::empty())
            .unwrap();

        req.extensions_mut()
            .insert(ProxyAddress::try_from("http://john:secret@1.2.3.4:1234").unwrap());

        let proxy_address = service.serve(req).await.unwrap();

        assert_eq!(proxy_address.authority.to_string(), "1.2.3.4:1234");
    }

    #[tokio::test]
    async fn test_proxy_db_service_optional() {
        let db = memproxydb().await;

        let service =
            ProxyDBLayer::new(Arc::new(db)).into_layer(service_fn(async |req: Request| {
                Ok::<_, Infallible>(req.extensions().get::<ProxyAddress>().cloned())
            }));

        for (filter, expected_authority, mut req) in [
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
                    id: Some(NonEmptyString::from_static("3031533634")),
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
            req.extensions_mut().maybe_insert(filter);

            let maybe_proxy_address = service.serve(req).await.unwrap();

            assert_eq!(
                maybe_proxy_address.map(|p| p.authority),
                expected_authority.map(|s| Authority::try_from(s).unwrap())
            );
        }
    }

    #[tokio::test]
    async fn test_proxy_db_service_default() {
        let db = memproxydb().await;

        let service = ProxyDBLayer::new(Arc::new(db))
            .filter_mode(ProxyFilterMode::Default)
            .into_layer(service_fn(async |req: Request| {
                Ok::<_, Infallible>(req.extensions().get::<ProxyAddress>().unwrap().clone())
            }));

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
                let mut req = Request::builder()
                    .version(req_info.0)
                    .method(req_info.1)
                    .uri(req_info.2)
                    .body(Body::empty())
                    .unwrap();

                req.extensions_mut().maybe_insert(filter.clone());

                let proxy_address = service.serve(req).await.unwrap().authority.to_string();

                if !seen_addresses.contains(&proxy_address) {
                    seen_addresses.push(proxy_address);
                }
            }

            let seen_addresses = seen_addresses.into_iter().sorted().join(",");
            assert_eq!(seen_addresses, expected_addresses);
        }
    }

    #[tokio::test]
    async fn test_proxy_db_service_fallback() {
        let db = memproxydb().await;

        let service = ProxyDBLayer::new(Arc::new(db))
            .filter_mode(ProxyFilterMode::Fallback(ProxyFilter {
                datacenter: Some(true),
                residential: Some(false),
                mobile: Some(false),
                ..Default::default()
            }))
            .into_layer(service_fn(async |req: Request| {
                Ok::<_, Infallible>(req.extensions().get::<ProxyAddress>().unwrap().clone())
            }));

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
                let mut req = Request::builder()
                    .version(req_info.0)
                    .method(req_info.1)
                    .uri(req_info.2)
                    .body(Body::empty())
                    .unwrap();

                req.extensions_mut().maybe_insert(filter.clone());

                let proxy_address = service.serve(req).await.unwrap().authority.to_string();

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
            .filter_mode(ProxyFilterMode::Required)
            .into_layer(service_fn(async |req: Request| {
                Ok::<_, Infallible>(req.extensions().get::<ProxyAddress>().unwrap().clone())
            }));

        for (filter, expected_address, mut req) in [
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
                    id: Some(NonEmptyString::from_static("FooBar")),
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
                    id: Some(NonEmptyString::from_static("1316455915")),
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
            req.extensions_mut().maybe_insert(filter.clone());

            let proxy_address_result = service.serve(req).await;
            match expected_address {
                Some(expected_address) => {
                    assert_eq!(
                        proxy_address_result.unwrap().authority,
                        Authority::try_from(expected_address).unwrap()
                    );
                }
                None => {
                    assert!(proxy_address_result.is_err());
                }
            }
        }
    }

    #[tokio::test]
    async fn test_proxy_db_service_required_with_predicate() {
        let db = memproxydb().await;

        let service = ProxyDBLayer::new(Arc::new(db))
            .filter_mode(ProxyFilterMode::Required)
            .select_predicate(|proxy: &Proxy| proxy.mobile)
            .into_layer(service_fn(async |req: Request| {
                Ok::<_, Infallible>(req.extensions().get::<ProxyAddress>().unwrap().clone())
            }));

        for (filter, expected, mut req) in [
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
                    id: Some(NonEmptyString::from_static("FooBar")),
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
                    id: Some(NonEmptyString::from_static("1316455915")),
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
                    id: Some(NonEmptyString::from_static("1316455915")),
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
            req.extensions_mut().maybe_insert(filter);

            let proxy_result = service.serve(req).await;
            match expected {
                Some(expected_address) => {
                    assert_eq!(
                        proxy_result.unwrap().authority,
                        Authority::try_from(expected_address).unwrap()
                    );
                }
                None => {
                    assert!(proxy_result.is_err());
                }
            }
        }
    }
}
