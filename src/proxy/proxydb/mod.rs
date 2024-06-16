use crate::{
    http::{RequestContext, Version},
    utils::str::NonEmptyString,
};
use serde::Deserialize;
use std::future::Future;
use venndb::Any;

mod internal;
pub use internal::{Proxy, ProxyCsvRowReader, ProxyCsvRowReaderError, ProxyCsvRowReaderErrorKind};

pub mod layer;

mod str;
#[doc(inline)]
pub use str::StringFilter;

#[derive(Debug, Default, Clone, Deserialize, PartialEq, Eq, Hash)]
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
/// - Use [`HeaderConfigLayer`] to have this proxy filter be given by the [`Request`] headers,
///   which will add the extracted and parsed [`ProxyFilter`] to the [`Context`]'s [`Extensions`].
/// - Or extract yourself from the username/token validated in the [`ProxyAuthLayer`]
///   to add it manually to the [`Context`]'s [`Extensions`].
///
/// [`HeaderConfigLayer`]: crate::http::layer::header_config::HeaderConfigLayer
/// [`Request`]: crate::http::Request
/// [`ProxyAuthLayer`]: crate::http::layer::proxy_auth::ProxyAuthLayer
/// [`Context`]: crate::service::Context
/// [`Extensions`]: crate::service::context::Extensions
pub struct ProxyFilter {
    /// The ID of the proxy to select.
    pub id: Option<NonEmptyString>,

    /// The ID of the pool from which to select the proxy.
    #[serde(alias = "pool")]
    pub pool_id: Option<Vec<StringFilter>>,

    /// The country of the proxy.
    pub country: Option<Vec<StringFilter>>,

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
}

/// The trait to implement to provide a proxy database to other facilities,
/// such as connection pools, to provide a proxy based on the given
/// [`RequestContext`] and [`ProxyFilter`].
pub trait ProxyDB: Send + Sync + 'static {
    /// The error type that can be returned by the proxy database
    ///
    /// Examples are generic I/O issues or
    /// even more common if no proxy match could be found.
    type Error;

    /// Get a [`Proxy`] based on the given [`RequestContext`] and [`ProxyFilter`],
    /// or return an error in case no [`Proxy`] could be returned.
    fn get_proxy(
        &self,
        ctx: RequestContext,
        filter: ProxyFilter,
    ) -> impl Future<Output = Result<Proxy, Self::Error>> + Send + '_;

    /// Same as [`Self::get_proxy`] but with a predicate
    /// to filter out found proxies that do not match the given predicate.
    fn get_proxy_if(
        &self,
        ctx: RequestContext,
        filter: ProxyFilter,
        predicate: impl Fn(&Proxy) -> bool + Send + Sync + 'static,
    ) -> impl Future<Output = Result<Proxy, Self::Error>> + Send + '_;
}

impl<T> ProxyDB for std::sync::Arc<T>
where
    T: ProxyDB,
{
    type Error = T::Error;

    #[inline]
    fn get_proxy(
        &self,
        ctx: RequestContext,
        filter: ProxyFilter,
    ) -> impl Future<Output = Result<Proxy, Self::Error>> + Send + '_ {
        (**self).get_proxy(ctx, filter)
    }

    #[inline]
    fn get_proxy_if(
        &self,
        ctx: RequestContext,
        filter: ProxyFilter,
        predicate: impl Fn(&Proxy) -> bool + Send + Sync + 'static,
    ) -> impl Future<Output = Result<Proxy, Self::Error>> + Send + '_ {
        (**self).get_proxy_if(ctx, filter, predicate)
    }
}

/// A fast in-memory ProxyDatabase that is the default choice for Rama.
#[derive(Debug)]
pub struct MemoryProxyDB {
    data: internal::ProxyDB,
}

impl MemoryProxyDB {
    /// Create a new in-memory proxy database with the given proxies.
    pub fn try_from_rows(proxies: Vec<Proxy>) -> Result<Self, MemoryProxyDBInsertError> {
        Ok(MemoryProxyDB {
            data: internal::ProxyDB::from_rows(proxies).map_err(|err| match err.kind() {
                internal::ProxyDBErrorKind::DuplicateKey => {
                    MemoryProxyDBInsertError::duplicate_key(err.into_input())
                }
                internal::ProxyDBErrorKind::InvalidRow => {
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
        Ok(MemoryProxyDB {
            data: internal::ProxyDB::from_iter(proxies).map_err(|err| match err.kind() {
                internal::ProxyDBErrorKind::DuplicateKey => {
                    MemoryProxyDBInsertError::duplicate_key(err.into_input())
                }
                internal::ProxyDBErrorKind::InvalidRow => {
                    MemoryProxyDBInsertError::invalid_proxy(err.into_input())
                }
            })?,
        })
    }

    /// Return the number of proxies in the database.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Rerturns if the database is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    fn query_from_filter(
        &self,
        ctx: RequestContext,
        filter: ProxyFilter,
    ) -> internal::ProxyDBQuery {
        let mut query = self.data.query();

        for pool_id in filter.pool_id.into_iter().flatten() {
            query.pool_id(pool_id);
        }
        for country in filter.country.into_iter().flatten() {
            query.country(country);
        }
        for city in filter.city.into_iter().flatten() {
            query.city(city);
        }
        for carrier in filter.carrier.into_iter().flatten() {
            query.carrier(carrier);
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

        if ctx.http_version == Version::HTTP_3 {
            query.udp(true);
            query.socks5(true);
        } else {
            query.tcp(true);
        }

        query
    }
}

impl ProxyDB for MemoryProxyDB {
    type Error = MemoryProxyDBQueryError;

    async fn get_proxy(
        &self,
        ctx: RequestContext,
        filter: ProxyFilter,
    ) -> Result<Proxy, Self::Error> {
        match &filter.id {
            Some(id) => match self.data.get_by_id(id) {
                None => Err(MemoryProxyDBQueryError::not_found()),
                Some(proxy) => {
                    if proxy.is_match(&ctx, &filter) {
                        Ok(combine_proxy_filter(proxy, filter))
                    } else {
                        Err(MemoryProxyDBQueryError::mismatch())
                    }
                }
            },
            None => {
                let query = self.query_from_filter(ctx, filter.clone());
                match query.execute().map(|result| result.any()) {
                    None => Err(MemoryProxyDBQueryError::not_found()),
                    Some(proxy) => Ok(combine_proxy_filter(proxy, filter)),
                }
            }
        }
    }

    async fn get_proxy_if(
        &self,
        ctx: RequestContext,
        filter: ProxyFilter,
        predicate: impl Fn(&Proxy) -> bool + Send + Sync + 'static,
    ) -> Result<Proxy, Self::Error> {
        match &filter.id {
            Some(id) => match self.data.get_by_id(id) {
                None => Err(MemoryProxyDBQueryError::not_found()),
                Some(proxy) => {
                    if proxy.is_match(&ctx, &filter) && predicate(proxy) {
                        Ok(combine_proxy_filter(proxy, filter))
                    } else {
                        Err(MemoryProxyDBQueryError::mismatch())
                    }
                }
            },
            None => {
                let query = self.query_from_filter(ctx, filter.clone());
                match query
                    .execute()
                    .and_then(|result| result.filter(predicate))
                    .map(|result| result.any())
                {
                    None => Err(MemoryProxyDBQueryError::not_found()),
                    Some(proxy) => Ok(combine_proxy_filter(proxy, filter)),
                }
            }
        }
    }
}

fn combine_proxy_filter(proxy: &Proxy, filter: ProxyFilter) -> Proxy {
    Proxy {
        id: proxy.id.clone(),
        address: proxy.address.clone(),
        tcp: proxy.tcp,
        udp: proxy.udp,
        http: proxy.http,
        socks5: proxy.socks5,
        datacenter: proxy.datacenter,
        residential: proxy.residential,
        mobile: proxy.mobile,
        pool_id: use_preferred_string_filter(filter.pool_id, &proxy.pool_id),
        country: use_preferred_string_filter(filter.country, &proxy.country),
        city: use_preferred_string_filter(filter.city, &proxy.city),
        carrier: use_preferred_string_filter(filter.carrier, &proxy.carrier),
    }
}

/// - In case we only have a single non-any filter, we use that (no cloning needed)
/// - In case we have no filters or the proxy value is any, we use the filter value (cloning required)
/// - If multiple filters are defined but the proxy value is any we returned first filter, assuming it is the most important one
fn use_preferred_string_filter(
    filter: Option<Vec<StringFilter>>,
    returned_value: &Option<StringFilter>,
) -> Option<StringFilter> {
    let mut filter_values = filter.unwrap_or_default();
    match filter_values.len() {
        0 => returned_value.clone(),
        1 => match filter_values.pop() {
            Some(value) if !value.is_any() => Some(value),
            _ => returned_value.clone(),
        },
        _ => {
            if returned_value
                .as_ref()
                .map(|v| v.is_any())
                .unwrap_or_default()
            {
                filter_values.pop()
            } else {
                returned_value.clone()
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
        MemoryProxyDBInsertError {
            kind: MemoryProxyDBInsertErrorKind::DuplicateKey,
            proxies,
        }
    }

    fn invalid_proxy(proxies: Vec<Proxy>) -> Self {
        MemoryProxyDBInsertError {
            kind: MemoryProxyDBInsertErrorKind::InvalidProxy,
            proxies,
        }
    }

    /// Returns the kind of error that [`MemoryProxyDBInsertError`] represents.
    pub fn kind(&self) -> MemoryProxyDBInsertErrorKind {
        self.kind
    }

    /// Returns the proxies that were not inserted.
    pub fn proxies(&self) -> &[Proxy] {
        &self.proxies
    }

    /// Consumes the error and returns the proxies that were not inserted.
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
    pub fn not_found() -> Self {
        MemoryProxyDBQueryError {
            kind: MemoryProxyDBQueryErrorKind::NotFound,
        }
    }

    /// Create a new error that indicates a proxy looked up by key had a config that did not match the given filters/requirements.
    pub fn mismatch() -> Self {
        MemoryProxyDBQueryError {
            kind: MemoryProxyDBQueryErrorKind::Mismatch,
        }
    }

    /// Returns the kind of error that [`MemoryProxyDBQueryError`] represents.
    pub fn kind(&self) -> MemoryProxyDBQueryErrorKind {
        self.kind
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::{
        net::{address::ProxyAddress, Protocol},
        utils::str::NonEmptyString,
    };

    use super::*;
    use itertools::Itertools;

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

    fn h2_req_context() -> RequestContext {
        RequestContext {
            http_version: Version::HTTP_2,
            protocol: Protocol::Https,
            authority: Some("localhost:8443".try_into().unwrap()),
        }
    }

    #[tokio::test]
    async fn test_memproxydb_get_proxy_by_id_found() {
        let db = memproxydb().await;
        let ctx = h2_req_context();
        let filter = ProxyFilter {
            id: Some(NonEmptyString::from_static("3031533634")),
            ..Default::default()
        };
        let proxy = db.get_proxy(ctx, filter).await.unwrap();
        assert_eq!(proxy.id, "3031533634");
    }

    #[tokio::test]
    async fn test_memproxydb_get_proxy_by_id_found_correct_filters() {
        let db = memproxydb().await;
        let ctx = h2_req_context();
        let filter = ProxyFilter {
            id: Some(NonEmptyString::from_static("3031533634")),
            pool_id: Some(vec![StringFilter::new("poolF")]),
            country: Some(vec![StringFilter::new("JP")]),
            city: Some(vec![StringFilter::new("Yokohama")]),
            datacenter: Some(true),
            residential: Some(false),
            mobile: Some(true),
            carrier: Some(vec![StringFilter::new("Verizon")]),
        };
        let proxy = db.get_proxy(ctx, filter).await.unwrap();
        assert_eq!(proxy.id, "3031533634");
    }

    #[tokio::test]
    async fn test_memproxydb_get_proxy_by_id_not_found() {
        let db = memproxydb().await;
        let ctx = h2_req_context();
        let filter = ProxyFilter {
            id: Some(NonEmptyString::from_static("notfound")),
            ..Default::default()
        };
        let err = db.get_proxy(ctx, filter).await.unwrap_err();
        assert_eq!(err.kind(), MemoryProxyDBQueryErrorKind::NotFound);
    }

    #[tokio::test]
    async fn test_memproxydb_get_proxy_by_id_mismatch_filter() {
        let db = memproxydb().await;
        let ctx = h2_req_context();
        let filters = [
            ProxyFilter {
                id: Some(NonEmptyString::from_static("3031533634")),
                pool_id: Some(vec![StringFilter::new("poolB")]),
                ..Default::default()
            },
            ProxyFilter {
                id: Some(NonEmptyString::from_static("3031533634")),
                country: Some(vec![StringFilter::new("US")]),
                ..Default::default()
            },
            ProxyFilter {
                id: Some(NonEmptyString::from_static("3031533634")),
                city: Some(vec![StringFilter::new("New York")]),
                ..Default::default()
            },
            ProxyFilter {
                id: Some(NonEmptyString::from_static("3031533634")),
                datacenter: Some(false),
                ..Default::default()
            },
            ProxyFilter {
                id: Some(NonEmptyString::from_static("3031533634")),
                residential: Some(true),
                ..Default::default()
            },
            ProxyFilter {
                id: Some(NonEmptyString::from_static("3031533634")),
                mobile: Some(false),
                ..Default::default()
            },
            ProxyFilter {
                id: Some(NonEmptyString::from_static("3031533634")),
                carrier: Some(vec![StringFilter::new("AT&T")]),
                ..Default::default()
            },
        ];
        for filter in filters.iter() {
            let err = db.get_proxy(ctx.clone(), filter.clone()).await.unwrap_err();
            assert_eq!(err.kind(), MemoryProxyDBQueryErrorKind::Mismatch);
        }
    }

    fn h3_req_context() -> RequestContext {
        RequestContext {
            http_version: Version::HTTP_3,
            protocol: Protocol::Https,
            authority: Some("localhost:8443".try_into().unwrap()),
        }
    }

    #[tokio::test]
    async fn test_memproxydb_get_proxy_by_id_mismatch_req_context() {
        let db = memproxydb().await;
        let ctx = h3_req_context();
        let filter = ProxyFilter {
            id: Some(NonEmptyString::from_static("3031533634")),
            ..Default::default()
        };
        // this proxy does not support socks5 UDP, which is what we need
        let err = db.get_proxy(ctx, filter).await.unwrap_err();
        assert_eq!(err.kind(), MemoryProxyDBQueryErrorKind::Mismatch);
    }

    #[tokio::test]
    async fn test_memorydb_get_h3_capable_proxies() {
        let db = memproxydb().await;
        let ctx = h3_req_context();
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
        let ctx = h2_req_context();
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
        let ctx = h2_req_context();
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
    async fn test_memorydb_get_h3_capable_mobile_residential_be_asterix_proxies() {
        let db = memproxydb().await;
        let ctx = h3_req_context();
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
        let ctx = h2_req_context();
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
                db.get_proxy_if(ctx.clone(), filter.clone(), move |proxy| {
                    !blocked_proxies.contains(&proxy.id.as_str())
                })
                .await
                .unwrap_err()
                .kind()
            );
        }

        let last_proxy_id = blocked_proxies.pop().unwrap();

        let proxy = db
            .get_proxy_if(ctx, filter.clone(), move |proxy| {
                !blocked_proxies.contains(&proxy.id.as_str())
            })
            .await
            .unwrap();
        assert_eq!(proxy.id, last_proxy_id);
    }

    #[tokio::test]
    async fn test_db_proxy_filter_any_use_filter_property() {
        let db = MemoryProxyDB::try_from_iter([Proxy {
            id: NonEmptyString::from_static("1"),
            address: ProxyAddress::from_str("example.com").unwrap(),
            tcp: true,
            udp: true,
            http: true,
            socks5: true,
            datacenter: true,
            residential: true,
            mobile: true,
            pool_id: Some("*".into()),
            country: Some("*".into()),
            city: Some("*".into()),
            carrier: Some("*".into()),
        }])
        .unwrap();

        let ctx = h2_req_context();

        for filter in [
            ProxyFilter {
                id: Some(NonEmptyString::from_static("1")),
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
            assert!(filter
                .pool_id
                .map(|pool_id| pool_id.contains(proxy.pool_id.as_ref().unwrap()))
                .unwrap_or(true));
            assert!(filter
                .country
                .map(|country| country.contains(proxy.country.as_ref().unwrap()))
                .unwrap_or(true));
            assert!(filter
                .city
                .map(|city| city.contains(proxy.city.as_ref().unwrap()))
                .unwrap_or(true));
            assert!(filter
                .carrier
                .map(|carrier| carrier.contains(proxy.carrier.as_ref().unwrap()))
                .unwrap_or(true));
        }
    }

    #[tokio::test]
    async fn test_db_proxy_filter_any_only_matches_any_value() {
        let db = MemoryProxyDB::try_from_iter([Proxy {
            id: NonEmptyString::from_static("1"),
            address: ProxyAddress::from_str("example.com").unwrap(),
            tcp: true,
            udp: true,
            http: true,
            socks5: true,
            datacenter: true,
            residential: true,
            mobile: true,
            pool_id: Some("hq".into()),
            country: Some("US".into()),
            city: Some("NY".into()),
            carrier: Some("AT&T".into()),
        }])
        .unwrap();

        let ctx = h2_req_context();

        for filter in [
            ProxyFilter {
                pool_id: Some(vec![StringFilter::new("*")]),
                ..Default::default()
            },
            ProxyFilter {
                country: Some(vec![StringFilter::new("*")]),
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
                pool_id: Some(vec![StringFilter::new("*")]),
                country: Some(vec![StringFilter::new("*")]),
                city: Some(vec![StringFilter::new("*")]),
                carrier: Some(vec![StringFilter::new("*")]),
                ..Default::default()
            },
        ] {
            let err = match db.get_proxy(ctx.clone(), filter.clone()).await {
                Ok(proxy) => {
                    panic!(
                        "expected error for filter {:?}, not found proxy: {:?}",
                        filter, proxy
                    );
                }
                Err(err) => err,
            };
            assert_eq!(
                MemoryProxyDBQueryErrorKind::NotFound,
                err.kind(),
                "filter: {:?}",
                filter
            );
        }
    }

    #[tokio::test]
    async fn test_search_proxy_for_any_of_given_pools() {
        let db = MemoryProxyDB::try_from_iter([
            Proxy {
                id: NonEmptyString::from_static("1"),
                address: ProxyAddress::from_str("example.com").unwrap(),
                tcp: true,
                udp: true,
                http: true,
                socks5: true,
                datacenter: true,
                residential: true,
                mobile: true,
                pool_id: Some("a".into()),
                country: Some("US".into()),
                city: Some("NY".into()),
                carrier: Some("AT&T".into()),
            },
            Proxy {
                id: NonEmptyString::from_static("2"),
                address: ProxyAddress::from_str("example.com").unwrap(),
                tcp: true,
                udp: true,
                http: true,
                socks5: true,
                datacenter: true,
                residential: true,
                mobile: true,
                pool_id: Some("b".into()),
                country: Some("US".into()),
                city: Some("NY".into()),
                carrier: Some("AT&T".into()),
            },
            Proxy {
                id: NonEmptyString::from_static("3"),
                address: ProxyAddress::from_str("example.com").unwrap(),
                tcp: true,
                udp: true,
                http: true,
                socks5: true,
                datacenter: true,
                residential: true,
                mobile: true,
                pool_id: Some("b".into()),
                country: Some("US".into()),
                city: Some("NY".into()),
                carrier: Some("AT&T".into()),
            },
            Proxy {
                id: NonEmptyString::from_static("4"),
                address: ProxyAddress::from_str("example.com").unwrap(),
                tcp: true,
                udp: true,
                http: true,
                socks5: true,
                datacenter: true,
                residential: true,
                mobile: true,
                pool_id: Some("c".into()),
                country: Some("US".into()),
                city: Some("NY".into()),
                carrier: Some("AT&T".into()),
            },
        ])
        .unwrap();

        let ctx = h2_req_context();

        let filter = ProxyFilter {
            pool_id: Some(vec![StringFilter::new("a"), StringFilter::new("c")]),
            ..Default::default()
        };

        let mut seen_1 = false;
        let mut seen_4 = false;
        for _ in 0..100 {
            let proxy = db.get_proxy(ctx.clone(), filter.clone()).await.unwrap();
            match proxy.id.as_str() {
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
                    id: Some(NonEmptyString::from_static("1")),
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
        ] {
            let filter: ProxyFilter = serde_html_form::from_str(input).unwrap();
            assert_eq!(filter, expected_output);
        }
    }
}
