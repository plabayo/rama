use rama_core::error::{BoxError, ErrorContext};
use rama_net::asn::Asn;
use rama_utils::str::NonEmptyStr;
use serde::{Deserialize, Serialize};
use std::fmt;

#[cfg(feature = "live-update")]
mod update;
#[cfg(feature = "live-update")]
#[cfg_attr(docsrs, doc(cfg(feature = "live-update")))]
#[doc(inline)]
pub use update::{LiveUpdateProxyDB, LiveUpdateProxyDBSetter, proxy_db_updater};

mod context;
pub use context::ProxyContext;

mod internal;
#[doc(inline)]
pub use internal::Proxy;

#[cfg(feature = "csv")]
mod csv;

#[cfg(feature = "csv")]
#[cfg_attr(docsrs, doc(cfg(feature = "csv")))]
#[doc(inline)]
pub use csv::{ProxyCsvRowReader, ProxyCsvRowReaderError, ProxyCsvRowReaderErrorKind};

pub(super) mod layer;

mod str;
#[doc(inline)]
pub use str::StringFilter;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// `ID` of the selected proxy. To be inserted into the `Context`,
/// only if that proxy is selected.
pub struct ProxyID(NonEmptyStr);

impl ProxyID {
    /// View  this [`ProxyID`] as a `str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl AsRef<str> for ProxyID {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl fmt::Display for ProxyID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<NonEmptyStr> for ProxyID {
    fn from(value: NonEmptyStr) -> Self {
        Self(value)
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
/// Filter to select a specific kind of proxy.
///
/// If the `id` is specified the other fields are used
/// as a validator to see if the only possible matching proxy
/// matches these fields.
///
/// If the `id` is not specified, the other fields are used
/// to select a random proxy from the pool.
///
/// Filters can be combined to make combinations with special meaning.
/// E.g. `datacenter:true, residential:true` is essentially an ISP proxy.
///
/// ## Usage
///
/// - Use `HeaderConfigLayer` (`rama-http`) to have this proxy filter be given by the http request headers,
///   which will add the extracted and parsed [`ProxyFilter`] to the input [`Extensions`].
/// - Or extract yourself from the username/token validated in the `ProxyAuthLayer` (`rama-http`)
///   to add it manually to the input [`Extensions`].
///
/// [`Extensions`]: rama_core::extensions::Extensions
pub struct ProxyFilter {
    /// The ID of the proxy to select.
    pub id: Option<NonEmptyStr>,

    /// The ID of the pool from which to select the proxy.
    #[serde(alias = "pool")]
    pub pool_id: Option<Vec<StringFilter>>,

    /// The continent of the proxy.
    pub continent: Option<Vec<StringFilter>>,

    /// The country of the proxy.
    pub country: Option<Vec<StringFilter>>,

    /// The state of the proxy.
    pub state: Option<Vec<StringFilter>>,

    /// The city of the proxy.
    pub city: Option<Vec<StringFilter>>,

    /// Set explicitly to `true` to select a datacenter proxy.
    pub datacenter: Option<bool>,

    /// Set explicitly to `true` to select a residential proxy.
    pub residential: Option<bool>,

    /// Set explicitly to `true` to select a mobile proxy.
    pub mobile: Option<bool>,

    /// The mobile carrier desired.
    pub carrier: Option<Vec<StringFilter>>,

    ///  Autonomous System Number (ASN).
    pub asn: Option<Vec<Asn>>,
}

/// The trait to implement to provide a proxy database to other facilities,
/// such as connection pools, to provide a proxy based on the given
/// [`ProxyContext`] and [`ProxyFilter`].
pub trait ProxyDB: Send + Sync + 'static {
    /// The error type that can be returned by the proxy database
    ///
    /// Examples are generic I/O issues or
    /// even more common if no proxy match could be found.
    type Error: Send + 'static;

    /// Same as [`Self::get_proxy`] but with a predicate
    /// to filter out found proxies that do not match the given predicate.
    fn get_proxy_if(
        &self,
        ctx: ProxyContext,
        filter: ProxyFilter,
        predicate: impl ProxyQueryPredicate,
    ) -> impl Future<Output = Result<Proxy, Self::Error>> + Send + '_;

    /// Get a [`Proxy`] based on the given [`ProxyContext`] and [`ProxyFilter`],
    /// or return an error in case no [`Proxy`] could be returned.
    fn get_proxy(
        &self,
        ctx: ProxyContext,
        filter: ProxyFilter,
    ) -> impl Future<Output = Result<Proxy, Self::Error>> + Send + '_ {
        self.get_proxy_if(ctx, filter, true)
    }
}

impl ProxyDB for () {
    type Error = BoxError;

    #[inline]
    async fn get_proxy_if(
        &self,
        _ctx: ProxyContext,
        _filter: ProxyFilter,
        _predicate: impl ProxyQueryPredicate,
    ) -> Result<Proxy, Self::Error> {
        Err(BoxError::from("()::get_proxy_if: no ProxyDB defined"))
    }

    #[inline]
    async fn get_proxy(
        &self,
        _ctx: ProxyContext,
        _filter: ProxyFilter,
    ) -> Result<Proxy, Self::Error> {
        Err(BoxError::from("()::get_proxy: no ProxyDB defined"))
    }
}

impl<T> ProxyDB for Option<T>
where
    T: ProxyDB<Error: Into<BoxError>>,
{
    type Error = BoxError;

    #[inline]
    async fn get_proxy_if(
        &self,
        ctx: ProxyContext,
        filter: ProxyFilter,
        predicate: impl ProxyQueryPredicate,
    ) -> Result<Proxy, Self::Error> {
        match self {
            Some(db) => db
                .get_proxy_if(ctx, filter, predicate)
                .await
                .context("Some::get_proxy_if"),
            None => Err(BoxError::from("None::get_proxy_if: no ProxyDB defined")),
        }
    }

    #[inline]
    async fn get_proxy(
        &self,
        ctx: ProxyContext,
        filter: ProxyFilter,
    ) -> Result<Proxy, Self::Error> {
        match self {
            Some(db) => db.get_proxy(ctx, filter).await.context("Some::get_proxy"),
            None => Err(BoxError::from("None::get_proxy: no ProxyDB defined")),
        }
    }
}

impl<T> ProxyDB for std::sync::Arc<T>
where
    T: ProxyDB,
{
    type Error = T::Error;

    #[inline]
    fn get_proxy_if(
        &self,
        ctx: ProxyContext,
        filter: ProxyFilter,
        predicate: impl ProxyQueryPredicate,
    ) -> impl Future<Output = Result<Proxy, Self::Error>> + Send + '_ {
        (**self).get_proxy_if(ctx, filter, predicate)
    }

    #[inline]
    fn get_proxy(
        &self,
        ctx: ProxyContext,
        filter: ProxyFilter,
    ) -> impl Future<Output = Result<Proxy, Self::Error>> + Send + '_ {
        (**self).get_proxy(ctx, filter)
    }
}

macro_rules! impl_proxydb_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+> ProxyDB for rama_core::combinators::$id<$($param),+>
        where
            $(
                $param: ProxyDB<Error: Into<BoxError>>,
            )+
    {
        type Error = BoxError;

        #[inline]
        async fn get_proxy_if(
            &self,
            ctx: ProxyContext,
            filter: ProxyFilter,
            predicate: impl ProxyQueryPredicate,
        ) -> Result<Proxy, Self::Error> {
            match self {
                $(
                    rama_core::combinators::$id::$param(s) => s.get_proxy_if(ctx, filter, predicate).await.into_box_error(),
                )+
            }
        }

        #[inline]
        async fn get_proxy(
            &self,
            ctx: ProxyContext,
            filter: ProxyFilter,
        ) -> Result<Proxy, Self::Error> {
            match self {
                $(
                    rama_core::combinators::$id::$param(s) => s.get_proxy(ctx, filter).await.into_box_error(),
                )+
            }
        }
        }
    };
}

rama_core::combinators::impl_either!(impl_proxydb_either);

/// Trait that is used by the [`ProxyDB`] for providing an optional
/// filter predicate to rule out returned results.
pub trait ProxyQueryPredicate: Clone + Send + Sync + 'static {
    /// Execute the predicate.
    fn execute(&self, proxy: &Proxy) -> bool;
}

impl ProxyQueryPredicate for bool {
    fn execute(&self, _proxy: &Proxy) -> bool {
        *self
    }
}

impl<F> ProxyQueryPredicate for F
where
    F: Fn(&Proxy) -> bool + Clone + Send + Sync + 'static,
{
    fn execute(&self, proxy: &Proxy) -> bool {
        (self)(proxy)
    }
}

impl ProxyDB for Proxy {
    type Error = BoxError;

    async fn get_proxy_if(
        &self,
        ctx: ProxyContext,
        filter: ProxyFilter,
        predicate: impl ProxyQueryPredicate,
    ) -> Result<Self, Self::Error> {
        (self.is_match(&ctx, &filter) && predicate.execute(self))
            .then(|| self.clone())
            .context("hardcoded proxy no match")
    }
}

#[cfg(feature = "memory-db")]
mod memdb {
    use super::*;
    use crate::proxydb::internal::ProxyDBErrorKind;
    use rama_net::transport::TransportProtocol;

    /// A fast in-memory ProxyDatabase that is the default choice for Rama.
    #[derive(Debug)]
    pub struct MemoryProxyDB {
        data: internal::ProxyDB,
    }

    impl MemoryProxyDB {
        /// Create a new in-memory proxy database with the given proxies.
        pub fn try_from_rows(proxies: Vec<Proxy>) -> Result<Self, MemoryProxyDBInsertError> {
            Ok(Self {
                data: internal::ProxyDB::from_rows(proxies).map_err(|err| match err.kind() {
                    ProxyDBErrorKind::DuplicateKey => {
                        MemoryProxyDBInsertError::duplicate_key(err.into_input())
                    }
                    ProxyDBErrorKind::InvalidRow => {
                        MemoryProxyDBInsertError::invalid_proxy(err.into_input())
                    }
                })?,
            })
        }

        /// Create a new in-memory proxy database with the given proxies from an iterator.
        pub fn try_from_iter<I>(proxies: I) -> Result<Self, MemoryProxyDBInsertError>
        where
            I: IntoIterator<Item = Proxy>,
        {
            Ok(Self {
                data: internal::ProxyDB::from_iter(proxies).map_err(|err| match err.kind() {
                    ProxyDBErrorKind::DuplicateKey => {
                        MemoryProxyDBInsertError::duplicate_key(err.into_input())
                    }
                    ProxyDBErrorKind::InvalidRow => {
                        MemoryProxyDBInsertError::invalid_proxy(err.into_input())
                    }
                })?,
            })
        }

        /// Return the number of proxies in the database.
        #[must_use]
        pub fn len(&self) -> usize {
            self.data.len()
        }

        /// Rerturns if the database is empty.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.data.is_empty()
        }

        #[allow(clippy::needless_pass_by_value)]
        fn query_from_filter(
            &self,
            ctx: ProxyContext,
            filter: ProxyFilter,
        ) -> internal::ProxyDBQuery<'_> {
            let mut query = self.data.query();

            for pool_id in filter.pool_id.into_iter().flatten() {
                query.pool_id(pool_id);
            }
            for continent in filter.continent.into_iter().flatten() {
                query.continent(continent);
            }
            for country in filter.country.into_iter().flatten() {
                query.country(country);
            }
            for state in filter.state.into_iter().flatten() {
                query.state(state);
            }
            for city in filter.city.into_iter().flatten() {
                query.city(city);
            }
            for carrier in filter.carrier.into_iter().flatten() {
                query.carrier(carrier);
            }
            for asn in filter.asn.into_iter().flatten() {
                query.asn(asn);
            }

            if let Some(value) = filter.datacenter {
                query.datacenter(value);
            }
            if let Some(value) = filter.residential {
                query.residential(value);
            }
            if let Some(value) = filter.mobile {
                query.mobile(value);
            }

            match ctx.protocol {
                TransportProtocol::Tcp => {
                    query.tcp(true);
                }
                TransportProtocol::Udp => {
                    query.udp(true).socks5(true);
                }
            }

            query
        }
    }

    // TODO: custom query filters using ProxyQueryPredicate
    // might be a lot faster for cases where we want to filter a big batch of proxies,
    // in which case a bitmap could be supported by a future VennDB version...
    //
    // Would just need to figure out how to allow this to happen.

    impl ProxyDB for MemoryProxyDB {
        type Error = MemoryProxyDBQueryError;

        async fn get_proxy_if(
            &self,
            ctx: ProxyContext,
            filter: ProxyFilter,
            predicate: impl ProxyQueryPredicate,
        ) -> Result<Proxy, Self::Error> {
            if let Some(id) = &filter.id {
                match self.data.get_by_id(id) {
                    None => Err(MemoryProxyDBQueryError::not_found()),
                    Some(proxy) => {
                        if proxy.is_match(&ctx, &filter) && predicate.execute(proxy) {
                            Ok(proxy.clone())
                        } else {
                            Err(MemoryProxyDBQueryError::mismatch())
                        }
                    }
                }
            } else {
                let query = self.query_from_filter(ctx, filter);
                match query
                    .execute()
                    .and_then(|result| result.filter(|proxy| predicate.execute(proxy)))
                    .map(|result| result.any())
                {
                    None => Err(MemoryProxyDBQueryError::not_found()),
                    Some(proxy) => Ok(proxy.clone()),
                }
            }
        }
    }

    /// The error type that can be returned by [`MemoryProxyDB`] when some of the proxies
    /// could not be inserted due to a proxy that had a duplicate key or was invalid for some other reason.
    #[derive(Debug)]
    pub struct MemoryProxyDBInsertError {
        kind: MemoryProxyDBInsertErrorKind,
        proxies: Vec<Proxy>,
    }

    impl std::fmt::Display for MemoryProxyDBInsertError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self.kind {
                MemoryProxyDBInsertErrorKind::DuplicateKey => write!(
                    f,
                    "A proxy with the same key already exists in the database"
                ),
                MemoryProxyDBInsertErrorKind::InvalidProxy => {
                    write!(f, "A proxy in the list is invalid for some reason")
                }
            }
        }
    }

    impl std::error::Error for MemoryProxyDBInsertError {}

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    /// The kind of error that [`MemoryProxyDBInsertError`] represents.
    pub enum MemoryProxyDBInsertErrorKind {
        /// Duplicate key found in the proxies.
        DuplicateKey,
        /// Invalid proxy found in the proxies.
        ///
        /// This could be due to a proxy that is not valid for some reason.
        /// E.g. a proxy that neither supports http or socks5.
        InvalidProxy,
    }

    impl MemoryProxyDBInsertError {
        fn duplicate_key(proxies: Vec<Proxy>) -> Self {
            Self {
                kind: MemoryProxyDBInsertErrorKind::DuplicateKey,
                proxies,
            }
        }

        fn invalid_proxy(proxies: Vec<Proxy>) -> Self {
            Self {
                kind: MemoryProxyDBInsertErrorKind::InvalidProxy,
                proxies,
            }
        }

        /// Returns the kind of error that [`MemoryProxyDBInsertError`] represents.
        #[must_use]
        pub fn kind(&self) -> MemoryProxyDBInsertErrorKind {
            self.kind
        }

        /// Returns the proxies that were not inserted.
        #[must_use]
        pub fn proxies(&self) -> &[Proxy] {
            &self.proxies
        }

        /// Consumes the error and returns the proxies that were not inserted.
        #[must_use]
        pub fn into_proxies(self) -> Vec<Proxy> {
            self.proxies
        }
    }

    /// The error type that can be returned by [`MemoryProxyDB`] when no proxy could be returned.
    #[derive(Debug)]
    pub struct MemoryProxyDBQueryError {
        kind: MemoryProxyDBQueryErrorKind,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    /// The kind of error that [`MemoryProxyDBQueryError`] represents.
    pub enum MemoryProxyDBQueryErrorKind {
        /// No proxy match could be found.
        NotFound,
        /// A proxy looked up by key had a config that did not match the given filters/requirements.
        Mismatch,
    }

    impl std::fmt::Display for MemoryProxyDBQueryError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self.kind {
                MemoryProxyDBQueryErrorKind::NotFound => write!(f, "No proxy match could be found"),
                MemoryProxyDBQueryErrorKind::Mismatch => write!(
                    f,
                    "Proxy config did not match the given filters/requirements"
                ),
            }
        }
    }

    impl std::error::Error for MemoryProxyDBQueryError {}

    impl MemoryProxyDBQueryError {
        /// Create a new error that indicates no proxy match could be found.
        #[must_use]
        pub fn not_found() -> Self {
            Self {
                kind: MemoryProxyDBQueryErrorKind::NotFound,
            }
        }

        /// Create a new error that indicates a proxy looked up by key had a config that did not match the given filters/requirements.
        #[must_use]
        pub fn mismatch() -> Self {
            Self {
                kind: MemoryProxyDBQueryErrorKind::Mismatch,
            }
        }

        /// Returns the kind of error that [`MemoryProxyDBQueryError`] represents.
        #[must_use]
        pub fn kind(&self) -> MemoryProxyDBQueryErrorKind {
            self.kind
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use itertools::Itertools;
        use rama_net::address::ProxyAddress;
        use rama_utils::str::non_empty_str;
        use std::str::FromStr;

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
        async fn test_load_memproxydb_from_rows() {
            let db = memproxydb().await;
            assert_eq!(db.len(), 64);
        }

        fn h2_proxy_context() -> ProxyContext {
            ProxyContext {
                protocol: TransportProtocol::Tcp,
            }
        }

        #[tokio::test]
        async fn test_memproxydb_get_proxy_by_id_found() {
            let db = memproxydb().await;
            let ctx = h2_proxy_context();
            let filter = ProxyFilter {
                id: Some(non_empty_str!("3031533634")),
                ..Default::default()
            };
            let proxy = db.get_proxy(ctx, filter).await.unwrap();
            assert_eq!(proxy.id, "3031533634");
        }

        #[tokio::test]
        async fn test_memproxydb_get_proxy_by_id_found_correct_filters() {
            let db = memproxydb().await;
            let ctx = h2_proxy_context();
            let filter = ProxyFilter {
                id: Some(non_empty_str!("3031533634")),
                pool_id: Some(vec![StringFilter::new("poolF")]),
                country: Some(vec![StringFilter::new("JP")]),
                city: Some(vec![StringFilter::new("Yokohama")]),
                datacenter: Some(true),
                residential: Some(false),
                mobile: Some(true),
                carrier: Some(vec![StringFilter::new("Verizon")]),
                ..Default::default()
            };
            let proxy = db.get_proxy(ctx, filter).await.unwrap();
            assert_eq!(proxy.id, "3031533634");
        }

        #[tokio::test]
        async fn test_memproxydb_get_proxy_by_id_not_found() {
            let db = memproxydb().await;
            let ctx = h2_proxy_context();
            let filter = ProxyFilter {
                id: Some(non_empty_str!("notfound")),
                ..Default::default()
            };
            let err = db.get_proxy(ctx, filter).await.unwrap_err();
            assert_eq!(err.kind(), MemoryProxyDBQueryErrorKind::NotFound);
        }

        #[tokio::test]
        async fn test_memproxydb_get_proxy_by_id_mismatch_filter() {
            let db = memproxydb().await;
            let ctx = h2_proxy_context();
            let filters = [
                ProxyFilter {
                    id: Some(non_empty_str!("3031533634")),
                    pool_id: Some(vec![StringFilter::new("poolB")]),
                    ..Default::default()
                },
                ProxyFilter {
                    id: Some(non_empty_str!("3031533634")),
                    country: Some(vec![StringFilter::new("US")]),
                    ..Default::default()
                },
                ProxyFilter {
                    id: Some(non_empty_str!("3031533634")),
                    city: Some(vec![StringFilter::new("New York")]),
                    ..Default::default()
                },
                ProxyFilter {
                    id: Some(non_empty_str!("3031533634")),
                    continent: Some(vec![StringFilter::new("americas")]),
                    ..Default::default()
                },
                ProxyFilter {
                    id: Some(non_empty_str!("3732488183")),
                    state: Some(vec![StringFilter::new("Texas")]),
                    ..Default::default()
                },
                ProxyFilter {
                    id: Some(non_empty_str!("3031533634")),
                    datacenter: Some(false),
                    ..Default::default()
                },
                ProxyFilter {
                    id: Some(non_empty_str!("3031533634")),
                    residential: Some(true),
                    ..Default::default()
                },
                ProxyFilter {
                    id: Some(non_empty_str!("3031533634")),
                    mobile: Some(false),
                    ..Default::default()
                },
                ProxyFilter {
                    id: Some(non_empty_str!("3031533634")),
                    carrier: Some(vec![StringFilter::new("AT&T")]),
                    ..Default::default()
                },
                ProxyFilter {
                    id: Some(non_empty_str!("292096733")),
                    asn: Some(vec![Asn::from_static(1)]),
                    ..Default::default()
                },
            ];
            for filter in filters.iter() {
                let err = db.get_proxy(ctx.clone(), filter.clone()).await.unwrap_err();
                assert_eq!(err.kind(), MemoryProxyDBQueryErrorKind::Mismatch);
            }
        }

        fn h3_proxy_context() -> ProxyContext {
            ProxyContext {
                protocol: TransportProtocol::Udp,
            }
        }

        #[tokio::test]
        async fn test_memproxydb_get_proxy_by_id_mismatch_req_context() {
            let db = memproxydb().await;
            let ctx = h3_proxy_context();
            let filter = ProxyFilter {
                id: Some(non_empty_str!("3031533634")),
                ..Default::default()
            };
            // this proxy does not support socks5 UDP, which is what we need
            let err = db.get_proxy(ctx, filter).await.unwrap_err();
            assert_eq!(err.kind(), MemoryProxyDBQueryErrorKind::Mismatch);
        }

        #[tokio::test]
        async fn test_memorydb_get_h3_capable_proxies() {
            let db = memproxydb().await;
            let ctx = h3_proxy_context();
            let filter = ProxyFilter::default();
            let mut found_ids = Vec::new();
            for _ in 0..5000 {
                let proxy = db.get_proxy(ctx.clone(), filter.clone()).await.unwrap();
                if found_ids.contains(&proxy.id) {
                    continue;
                }
                assert!(proxy.udp);
                assert!(proxy.socks5);
                found_ids.push(proxy.id);
            }
            assert_eq!(found_ids.len(), 40);
            assert_eq!(
                found_ids.iter().sorted().join(","),
                r##"1125300915,1259341971,1316455915,153202126,1571861931,1684342915,1742367441,1844412609,1916851007,20647117,2107229589,2261612122,2497865606,2521901221,2560727338,2593294918,2596743625,2745456299,2880295577,2909724448,2950022859,2951529660,3187902553,3269411602,3269465574,3269921904,3481200027,3498810974,362091157,3679054656,3732488183,3836943127,39048766,3951672504,3976711563,4187178960,56402588,724884866,738626121,906390012"##
            );
        }

        #[tokio::test]
        async fn test_memorydb_get_h2_capable_proxies() {
            let db = memproxydb().await;
            let ctx = h2_proxy_context();
            let filter = ProxyFilter::default();
            let mut found_ids = Vec::new();
            for _ in 0..5000 {
                let proxy = db.get_proxy(ctx.clone(), filter.clone()).await.unwrap();
                if found_ids.contains(&proxy.id) {
                    continue;
                }
                assert!(proxy.tcp);
                found_ids.push(proxy.id);
            }
            assert_eq!(found_ids.len(), 50);
            assert_eq!(
                found_ids.iter().sorted().join(","),
                r#"1125300915,1259341971,1264821985,129108927,1316455915,1425588737,1571861931,1810781137,1836040682,1844412609,1885107293,2021561518,2079461709,2107229589,2141152822,2438596154,2497865606,2521901221,2551759475,2560727338,2593294918,2798907087,2854473221,2880295577,2909724448,2912880381,292096733,2951529660,3031533634,3187902553,3269411602,3269465574,339020035,3481200027,3498810974,3503691556,362091157,3679054656,371209663,3861736957,39048766,3976711563,4062553709,49590203,56402588,724884866,738626121,767809962,846528631,906390012"#,
            );
        }

        #[tokio::test]
        async fn test_memorydb_get_any_country_proxies() {
            let db = memproxydb().await;
            let ctx = h2_proxy_context();
            let filter = ProxyFilter {
                // there are no explicit BE proxies,
                // so these will only match the proxies that have a wildcard country
                country: Some(vec!["BE".into()]),
                ..Default::default()
            };
            let mut found_ids = Vec::new();
            for _ in 0..5000 {
                let proxy = db.get_proxy(ctx.clone(), filter.clone()).await.unwrap();
                if found_ids.contains(&proxy.id) {
                    continue;
                }
                found_ids.push(proxy.id);
            }
            assert_eq!(found_ids.len(), 5);
            assert_eq!(
                found_ids.iter().sorted().join(","),
                r#"2141152822,2593294918,2912880381,371209663,767809962"#,
            );
        }

        #[tokio::test]
        async fn test_memorydb_get_illinois_proxies() {
            let db = memproxydb().await;
            let ctx = h2_proxy_context();
            let filter = ProxyFilter {
                // this will also work for proxies that have 'any' state
                state: Some(vec!["illinois".into()]),
                ..Default::default()
            };
            let mut found_ids = Vec::new();
            for _ in 0..5000 {
                let proxy = db.get_proxy(ctx.clone(), filter.clone()).await.unwrap();
                if found_ids.contains(&proxy.id) {
                    continue;
                }
                found_ids.push(proxy.id);
            }
            assert_eq!(found_ids.len(), 9);
            assert_eq!(
                found_ids.iter().sorted().join(","),
                r#"2141152822,2521901221,2560727338,2593294918,2912880381,292096733,371209663,39048766,767809962"#,
            );
        }

        #[tokio::test]
        async fn test_memorydb_get_asn_proxies() {
            let db = memproxydb().await;
            let ctx = h2_proxy_context();
            let filter = ProxyFilter {
                // this will also work for proxies that have 'any' ASN
                asn: Some(vec![Asn::from_static(42)]),
                ..Default::default()
            };
            let mut found_ids = Vec::new();
            for _ in 0..5000 {
                let proxy = db.get_proxy(ctx.clone(), filter.clone()).await.unwrap();
                if found_ids.contains(&proxy.id) {
                    continue;
                }
                found_ids.push(proxy.id);
            }
            assert_eq!(found_ids.len(), 4);
            assert_eq!(
                found_ids.iter().sorted().join(","),
                r#"2141152822,2912880381,292096733,3481200027"#,
            );
        }

        #[tokio::test]
        async fn test_memorydb_get_h3_capable_mobile_residential_be_asterix_proxies() {
            let db = memproxydb().await;
            let ctx = h3_proxy_context();
            let filter = ProxyFilter {
                country: Some(vec!["BE".into()]),
                mobile: Some(true),
                residential: Some(true),
                ..Default::default()
            };
            for _ in 0..50 {
                let proxy = db.get_proxy(ctx.clone(), filter.clone()).await.unwrap();
                assert_eq!(proxy.id, "2593294918");
            }
        }

        #[tokio::test]
        async fn test_memorydb_get_blocked_proxies() {
            let db = memproxydb().await;
            let ctx = h2_proxy_context();
            let filter = ProxyFilter::default();

            let mut blocked_proxies = vec![
                "1125300915",
                "1259341971",
                "1264821985",
                "129108927",
                "1316455915",
                "1425588737",
                "1571861931",
                "1810781137",
                "1836040682",
                "1844412609",
                "1885107293",
                "2021561518",
                "2079461709",
                "2107229589",
                "2141152822",
                "2438596154",
                "2497865606",
                "2521901221",
                "2551759475",
                "2560727338",
                "2593294918",
                "2798907087",
                "2854473221",
                "2880295577",
                "2909724448",
                "2912880381",
                "292096733",
                "2951529660",
                "3031533634",
                "3187902553",
                "3269411602",
                "3269465574",
                "339020035",
                "3481200027",
                "3498810974",
                "3503691556",
                "362091157",
                "3679054656",
                "371209663",
                "3861736957",
                "39048766",
                "3976711563",
                "4062553709",
                "49590203",
                "56402588",
                "724884866",
                "738626121",
                "767809962",
                "846528631",
                "906390012",
            ];

            {
                let blocked_proxies = blocked_proxies.clone();

                assert_eq!(
                    MemoryProxyDBQueryErrorKind::NotFound,
                    db.get_proxy_if(ctx.clone(), filter.clone(), move |proxy: &Proxy| {
                        !blocked_proxies.contains(&proxy.id.as_ref())
                    })
                    .await
                    .unwrap_err()
                    .kind()
                );
            }

            let last_proxy_id = blocked_proxies.pop().unwrap();

            let proxy = db
                .get_proxy_if(ctx, filter.clone(), move |proxy: &Proxy| {
                    !blocked_proxies.contains(&proxy.id.as_ref())
                })
                .await
                .unwrap();
            assert_eq!(proxy.id, last_proxy_id);
        }

        #[tokio::test]
        async fn test_db_proxy_filter_any_use_filter_property() {
            let db = MemoryProxyDB::try_from_iter([Proxy {
                id: non_empty_str!("1"),
                address: ProxyAddress::from_str("example.com:80").unwrap(),
                tcp: true,
                udp: true,
                http: true,
                https: true,
                socks5: true,
                socks5h: true,
                datacenter: true,
                residential: true,
                mobile: true,
                pool_id: Some("*".into()),
                continent: Some("*".into()),
                country: Some("*".into()),
                state: Some("*".into()),
                city: Some("*".into()),
                carrier: Some("*".into()),
                asn: Some(Asn::unspecified()),
            }])
            .unwrap();

            let ctx = h2_proxy_context();

            for filter in [
                ProxyFilter {
                    id: Some(non_empty_str!("1")),
                    ..Default::default()
                },
                ProxyFilter {
                    pool_id: Some(vec![StringFilter::new("*")]),
                    ..Default::default()
                },
                ProxyFilter {
                    pool_id: Some(vec![StringFilter::new("hq")]),
                    ..Default::default()
                },
                ProxyFilter {
                    country: Some(vec![StringFilter::new("*")]),
                    ..Default::default()
                },
                ProxyFilter {
                    country: Some(vec![StringFilter::new("US")]),
                    ..Default::default()
                },
                ProxyFilter {
                    city: Some(vec![StringFilter::new("*")]),
                    ..Default::default()
                },
                ProxyFilter {
                    city: Some(vec![StringFilter::new("NY")]),
                    ..Default::default()
                },
                ProxyFilter {
                    carrier: Some(vec![StringFilter::new("*")]),
                    ..Default::default()
                },
                ProxyFilter {
                    carrier: Some(vec![StringFilter::new("Telenet")]),
                    ..Default::default()
                },
                ProxyFilter {
                    pool_id: Some(vec![StringFilter::new("hq")]),
                    country: Some(vec![StringFilter::new("US")]),
                    city: Some(vec![StringFilter::new("NY")]),
                    carrier: Some(vec![StringFilter::new("AT&T")]),
                    ..Default::default()
                },
            ] {
                let proxy = db.get_proxy(ctx.clone(), filter.clone()).await.unwrap();
                assert!(filter.id.map(|id| proxy.id == id).unwrap_or(true));
                assert!(
                    filter
                        .pool_id
                        .map(|pool_id| pool_id.contains(proxy.pool_id.as_ref().unwrap()))
                        .unwrap_or(true)
                );
                assert!(
                    filter
                        .country
                        .map(|country| country.contains(proxy.country.as_ref().unwrap()))
                        .unwrap_or(true)
                );
                assert!(
                    filter
                        .city
                        .map(|city| city.contains(proxy.city.as_ref().unwrap()))
                        .unwrap_or(true)
                );
                assert!(
                    filter
                        .carrier
                        .map(|carrier| carrier.contains(proxy.carrier.as_ref().unwrap()))
                        .unwrap_or(true)
                );
            }
        }

        #[tokio::test]
        async fn test_db_proxy_filter_any_only_matches_any_value() {
            let db = MemoryProxyDB::try_from_iter([Proxy {
                id: non_empty_str!("1"),
                address: ProxyAddress::from_str("example.com:80").unwrap(),
                tcp: true,
                udp: true,
                http: true,
                https: true,
                socks5: true,
                socks5h: true,
                datacenter: true,
                residential: true,
                mobile: true,
                pool_id: Some("hq".into()),
                continent: Some("americas".into()),
                country: Some("US".into()),
                state: Some("NY".into()),
                city: Some("NY".into()),
                carrier: Some("AT&T".into()),
                asn: Some(Asn::from_static(7018)),
            }])
            .unwrap();

            let ctx = h2_proxy_context();

            for filter in [
                ProxyFilter {
                    pool_id: Some(vec![StringFilter::new("*")]),
                    ..Default::default()
                },
                ProxyFilter {
                    continent: Some(vec![StringFilter::new("*")]),
                    ..Default::default()
                },
                ProxyFilter {
                    country: Some(vec![StringFilter::new("*")]),
                    ..Default::default()
                },
                ProxyFilter {
                    state: Some(vec![StringFilter::new("*")]),
                    ..Default::default()
                },
                ProxyFilter {
                    city: Some(vec![StringFilter::new("*")]),
                    ..Default::default()
                },
                ProxyFilter {
                    carrier: Some(vec![StringFilter::new("*")]),
                    ..Default::default()
                },
                ProxyFilter {
                    asn: Some(vec![Asn::unspecified()]),
                    ..Default::default()
                },
                ProxyFilter {
                    pool_id: Some(vec![StringFilter::new("*")]),
                    continent: Some(vec![StringFilter::new("*")]),
                    country: Some(vec![StringFilter::new("*")]),
                    state: Some(vec![StringFilter::new("*")]),
                    city: Some(vec![StringFilter::new("*")]),
                    carrier: Some(vec![StringFilter::new("*")]),
                    asn: Some(vec![Asn::unspecified()]),
                    ..Default::default()
                },
            ] {
                let err = match db.get_proxy(ctx.clone(), filter.clone()).await {
                    Ok(proxy) => {
                        panic!("expected error for filter {filter:?}, not found proxy: {proxy:?}");
                    }
                    Err(err) => err,
                };
                assert_eq!(
                    MemoryProxyDBQueryErrorKind::NotFound,
                    err.kind(),
                    "filter: {filter:?}",
                );
            }
        }

        #[tokio::test]
        async fn test_search_proxy_for_any_of_given_pools() {
            let db = MemoryProxyDB::try_from_iter([
                Proxy {
                    id: non_empty_str!("1"),
                    address: ProxyAddress::from_str("example.com:80").unwrap(),
                    tcp: true,
                    udp: true,
                    http: true,
                    https: true,
                    socks5: true,
                    socks5h: true,
                    datacenter: true,
                    residential: true,
                    mobile: true,
                    pool_id: Some("a".into()),
                    continent: Some("americas".into()),
                    country: Some("US".into()),
                    state: Some("NY".into()),
                    city: Some("NY".into()),
                    carrier: Some("AT&T".into()),
                    asn: Some(Asn::from_static(7018)),
                },
                Proxy {
                    id: non_empty_str!("2"),
                    address: ProxyAddress::from_str("example.com:80").unwrap(),
                    tcp: true,
                    udp: true,
                    http: true,
                    https: true,
                    socks5: true,
                    socks5h: true,
                    datacenter: true,
                    residential: true,
                    mobile: true,
                    pool_id: Some("b".into()),
                    continent: Some("americas".into()),
                    country: Some("US".into()),
                    state: Some("NY".into()),
                    city: Some("NY".into()),
                    carrier: Some("AT&T".into()),
                    asn: Some(Asn::from_static(7018)),
                },
                Proxy {
                    id: non_empty_str!("3"),
                    address: ProxyAddress::from_str("example.com:80").unwrap(),
                    tcp: true,
                    udp: true,
                    http: true,
                    https: true,
                    socks5: true,
                    socks5h: true,
                    datacenter: true,
                    residential: true,
                    mobile: true,
                    pool_id: Some("b".into()),
                    continent: Some("americas".into()),
                    country: Some("US".into()),
                    state: Some("NY".into()),
                    city: Some("NY".into()),
                    carrier: Some("AT&T".into()),
                    asn: Some(Asn::from_static(7018)),
                },
                Proxy {
                    id: non_empty_str!("4"),
                    address: ProxyAddress::from_str("example.com:80").unwrap(),
                    tcp: true,
                    udp: true,
                    http: true,
                    https: true,
                    socks5: true,
                    socks5h: true,
                    datacenter: true,
                    residential: true,
                    mobile: true,
                    pool_id: Some("c".into()),
                    continent: Some("americas".into()),
                    country: Some("US".into()),
                    state: Some("NY".into()),
                    city: Some("NY".into()),
                    carrier: Some("AT&T".into()),
                    asn: Some(Asn::from_static(7018)),
                },
            ])
            .unwrap();

            let ctx = h2_proxy_context();

            let filter = ProxyFilter {
                pool_id: Some(vec![StringFilter::new("a"), StringFilter::new("c")]),
                ..Default::default()
            };

            let mut seen_1 = false;
            let mut seen_4 = false;
            for _ in 0..100 {
                let proxy = db.get_proxy(ctx.clone(), filter.clone()).await.unwrap();
                match proxy.id.as_ref() {
                    "1" => seen_1 = true,
                    "4" => seen_4 = true,
                    _ => panic!("unexpected pool id"),
                }
            }
            assert!(seen_1);
            assert!(seen_4);
        }

        #[tokio::test]
        async fn test_deserialize_url_proxy_filter() {
            for (input, expected_output) in [
                (
                    "id=1",
                    ProxyFilter {
                        id: Some(non_empty_str!("1")),
                        ..Default::default()
                    },
                ),
                (
                    "pool=hq&country=us",
                    ProxyFilter {
                        pool_id: Some(vec![StringFilter::new("hq")]),
                        country: Some(vec![StringFilter::new("us")]),
                        ..Default::default()
                    },
                ),
                (
                    "pool=hq&country=us&country=be",
                    ProxyFilter {
                        pool_id: Some(vec![StringFilter::new("hq")]),
                        country: Some(vec![StringFilter::new("us"), StringFilter::new("be")]),
                        ..Default::default()
                    },
                ),
                (
                    "pool=a&country=uk&pool=b",
                    ProxyFilter {
                        pool_id: Some(vec![StringFilter::new("a"), StringFilter::new("b")]),
                        country: Some(vec![StringFilter::new("uk")]),
                        ..Default::default()
                    },
                ),
                (
                    "continent=europe&continent=asia",
                    ProxyFilter {
                        continent: Some(vec![
                            StringFilter::new("europe"),
                            StringFilter::new("asia"),
                        ]),
                        ..Default::default()
                    },
                ),
                (
                    "continent=americas&country=us&state=NY&city=buffalo&carrier=AT%26T&asn=7018",
                    ProxyFilter {
                        continent: Some(vec![StringFilter::new("americas")]),
                        country: Some(vec![StringFilter::new("us")]),
                        state: Some(vec![StringFilter::new("ny")]),
                        city: Some(vec![StringFilter::new("buffalo")]),
                        carrier: Some(vec![StringFilter::new("at&t")]),
                        asn: Some(vec![Asn::from_static(7018)]),
                        ..Default::default()
                    },
                ),
                (
                    "asn=1&asn=2",
                    ProxyFilter {
                        asn: Some(vec![Asn::from_static(1), Asn::from_static(2)]),
                        ..Default::default()
                    },
                ),
            ] {
                let filter: ProxyFilter = serde_html_form::from_str(input).unwrap();
                assert_eq!(filter, expected_output);
            }
        }
    }
}

#[cfg(feature = "memory-db")]
#[cfg_attr(docsrs, doc(cfg(feature = "memory-db")))]
pub use memdb::{
    MemoryProxyDB, MemoryProxyDBInsertError, MemoryProxyDBInsertErrorKind, MemoryProxyDBQueryError,
    MemoryProxyDBQueryErrorKind,
};
