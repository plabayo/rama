use rama_core::error::BoxErrorExt as _;
use rama_core::error::{BoxError, ErrorContext};
use rama_core::extensions::Extension;
use rama_net::asn::Asn;
use rama_utils::collections::NonEmptyVec;
use rama_utils::str::NonEmptyStr;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::num::NonZeroUsize;

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
pub use internal::{Proxy, ProxyProtocols};

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

mod proxy_type;
#[doc(inline)]
pub use proxy_type::ProxyType;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Extension)]
#[extension(tags(proxy))]
/// ID of a proxy selected for a connection attempt.
///
/// In plural routing mode this is attached to the corresponding route and
/// installed on that route's isolated input by `ProxyRoutesConnector`.
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

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Extension)]
#[extension(tags(proxy))]
/// Filter to select a specific kind of proxy.
///
/// If the `id` is specified the other fields are used
/// as a validator to see if the only possible matching proxy
/// matches these fields.
///
/// If the `id` is not specified, the other fields select matching proxy
/// candidates. The database defines their preference order; [`MemoryProxyDB`]
/// randomizes its complete matching set.
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

    /// The types of proxy to select from.
    #[serde(rename = "type")]
    pub kind: Option<Vec<ProxyType>>,

    /// The mobile carrier desired.
    pub carrier: Option<Vec<StringFilter>>,

    ///  Autonomous System Number (ASN).
    pub asn: Option<Vec<Asn>>,
}

/// The trait to implement to provide a proxy database to other facilities,
/// such as connection pools, to provide proxy candidates based on the given
/// [`ProxyContext`] and [`ProxyFilter`].
pub trait ProxyDB: Send + Sync + 'static {
    /// The error type that can be returned by the proxy database
    ///
    /// Examples are generic I/O issues or
    /// even more common if no proxy match could be found.
    type Error: Send + 'static;

    /// Return matching [`Proxy`] values in database-defined preference order,
    /// after applying an additional predicate and optional result limit.
    fn get_proxies_if(
        &self,
        ctx: ProxyContext,
        filter: ProxyFilter,
        predicate: impl ProxyQueryPredicate,
        limit: Option<NonZeroUsize>,
    ) -> impl Future<Output = Result<NonEmptyVec<Proxy>, Self::Error>> + Send + '_;

    /// Return matching [`Proxy`] values in database-defined preference order,
    /// up to the optional result limit.
    fn get_proxies(
        &self,
        ctx: ProxyContext,
        filter: ProxyFilter,
        limit: Option<NonZeroUsize>,
    ) -> impl Future<Output = Result<NonEmptyVec<Proxy>, Self::Error>> + Send + '_ {
        self.get_proxies_if(ctx, filter, true, limit)
    }

    /// Return one matching proxy after applying an additional predicate.
    ///
    /// Implementations may override this to provide a more efficient random
    /// selection path. By default the first plural result is returned.
    fn get_proxy_if(
        &self,
        ctx: ProxyContext,
        filter: ProxyFilter,
        predicate: impl ProxyQueryPredicate,
    ) -> impl Future<Output = Result<Proxy, Self::Error>> + Send + '_ {
        async move {
            let proxies = self
                .get_proxies_if(ctx, filter, predicate, Some(NonZeroUsize::MIN))
                .await?;
            Ok(proxies.head)
        }
    }

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
    async fn get_proxies_if(
        &self,
        _ctx: ProxyContext,
        _filter: ProxyFilter,
        _predicate: impl ProxyQueryPredicate,
        _limit: Option<NonZeroUsize>,
    ) -> Result<NonEmptyVec<Proxy>, Self::Error> {
        Err(BoxError::from_static_str(
            "()::get_proxies_if: no ProxyDB defined",
        ))
    }

    #[inline]
    async fn get_proxy_if(
        &self,
        _ctx: ProxyContext,
        _filter: ProxyFilter,
        _predicate: impl ProxyQueryPredicate,
    ) -> Result<Proxy, Self::Error> {
        Err(BoxError::from_static_str(
            "()::get_proxy_if: no ProxyDB defined",
        ))
    }

    #[inline]
    async fn get_proxy(
        &self,
        _ctx: ProxyContext,
        _filter: ProxyFilter,
    ) -> Result<Proxy, Self::Error> {
        Err(BoxError::from_static_str(
            "()::get_proxy: no ProxyDB defined",
        ))
    }
}

impl<T> ProxyDB for Option<T>
where
    T: ProxyDB<Error: Into<BoxError>>,
{
    type Error = BoxError;

    #[inline]
    async fn get_proxies_if(
        &self,
        ctx: ProxyContext,
        filter: ProxyFilter,
        predicate: impl ProxyQueryPredicate,
        limit: Option<NonZeroUsize>,
    ) -> Result<NonEmptyVec<Proxy>, Self::Error> {
        match self {
            Some(db) => db
                .get_proxies_if(ctx, filter, predicate, limit)
                .await
                .context("Some::get_proxies_if"),
            None => Err(BoxError::from_static_str(
                "None::get_proxies_if: no ProxyDB defined",
            )),
        }
    }

    #[inline]
    async fn get_proxies(
        &self,
        ctx: ProxyContext,
        filter: ProxyFilter,
        limit: Option<NonZeroUsize>,
    ) -> Result<NonEmptyVec<Proxy>, Self::Error> {
        match self {
            Some(db) => db
                .get_proxies(ctx, filter, limit)
                .await
                .context("Some::get_proxies"),
            None => Err(BoxError::from_static_str(
                "None::get_proxies: no ProxyDB defined",
            )),
        }
    }

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
            None => Err(BoxError::from_static_str(
                "None::get_proxy_if: no ProxyDB defined",
            )),
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
            None => Err(BoxError::from_static_str(
                "None::get_proxy: no ProxyDB defined",
            )),
        }
    }
}

impl<T> ProxyDB for std::sync::Arc<T>
where
    T: ProxyDB,
{
    type Error = T::Error;

    #[inline]
    fn get_proxies_if(
        &self,
        ctx: ProxyContext,
        filter: ProxyFilter,
        predicate: impl ProxyQueryPredicate,
        limit: Option<NonZeroUsize>,
    ) -> impl Future<Output = Result<NonEmptyVec<Proxy>, Self::Error>> + Send + '_ {
        (**self).get_proxies_if(ctx, filter, predicate, limit)
    }

    #[inline]
    fn get_proxies(
        &self,
        ctx: ProxyContext,
        filter: ProxyFilter,
        limit: Option<NonZeroUsize>,
    ) -> impl Future<Output = Result<NonEmptyVec<Proxy>, Self::Error>> + Send + '_ {
        (**self).get_proxies(ctx, filter, limit)
    }

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
        async fn get_proxies_if(
            &self,
            ctx: ProxyContext,
            filter: ProxyFilter,
            predicate: impl ProxyQueryPredicate,
            limit: Option<NonZeroUsize>,
        ) -> Result<NonEmptyVec<Proxy>, Self::Error> {
            match self {
                $(
                    rama_core::combinators::$id::$param(s) => s.get_proxies_if(ctx, filter, predicate, limit).await.into_box_error(),
                )+
            }
        }

        #[inline]
        async fn get_proxies(
            &self,
            ctx: ProxyContext,
            filter: ProxyFilter,
            limit: Option<NonZeroUsize>,
        ) -> Result<NonEmptyVec<Proxy>, Self::Error> {
            match self {
                $(
                    rama_core::combinators::$id::$param(s) => s.get_proxies(ctx, filter, limit).await.into_box_error(),
                )+
            }
        }

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

    async fn get_proxies_if(
        &self,
        ctx: ProxyContext,
        filter: ProxyFilter,
        predicate: impl ProxyQueryPredicate,
        _limit: Option<NonZeroUsize>,
    ) -> Result<NonEmptyVec<Self>, Self::Error> {
        (self.is_match(&ctx, &filter) && predicate.execute(self))
            .then(|| NonEmptyVec::new(self.clone()))
            .context("hardcoded proxy no match")
    }

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

#[cfg(test)]
mod trait_tests {
    use super::*;
    use crate::ProxyProtocols;
    use rama_core::combinators::Either;
    use rama_net::address::ProxyProtocol;
    use rama_net::transport::TransportProtocol;
    use rama_utils::str::non_empty_str;
    use std::sync::Arc;

    fn proxy() -> Proxy {
        Proxy {
            id: non_empty_str!("proxy"),
            address: "proxy.example:8080".parse().unwrap(),
            credential: None,
            protocols: ProxyProtocols::from([ProxyProtocol::HTTP]),
            kind: ProxyType::Datacenter,
            pool_id: None,
            continent: None,
            country: None,
            state: None,
            city: None,
            carrier: None,
            asn: None,
        }
    }

    fn context() -> ProxyContext {
        ProxyContext {
            protocol: TransportProtocol::Tcp,
        }
    }

    #[tokio::test]
    async fn wrappers_forward_plural_queries() {
        let optional = Some(Arc::new(proxy()));
        let proxies = optional
            .get_proxies(context(), ProxyFilter::default(), None)
            .await
            .unwrap();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies.head.id, "proxy");

        let either: Either<Proxy, Proxy> = Either::B(proxy());
        let proxies = either
            .get_proxies_if(context(), ProxyFilter::default(), true, None)
            .await
            .unwrap();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies.head.id, "proxy");
    }

    #[tokio::test]
    async fn hardcoded_proxy_applies_plural_predicate() {
        let error = proxy()
            .get_proxies_if(context(), ProxyFilter::default(), false, None)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("hardcoded proxy no match"));
    }
}

#[cfg(feature = "memory-db")]
mod memdb {
    use super::*;
    use crate::proxydb::internal::ProxyDBErrorKind;
    use rama_net::transport::TransportProtocol;
    use rand::seq::{IteratorRandom as _, SliceRandom as _};
    use std::sync::Arc;
    use venndb::{Filter, RowSet, RuntimeColumn};

    /// A fast in-memory ProxyDatabase that is the default choice for Rama.
    ///
    /// Plural queries return a uniformly shuffled sample up to the requested
    /// limit, or every match when unbounded. Singular queries pick a random
    /// match without collecting the others first.
    ///
    /// Proxies can be flagged while the database is in use, e.g. to stop
    /// selecting a proxy that is blocked or unhealthy, through the
    /// [`ProxyRuntimeColumn`]s created with [`MemoryProxyDB::new_exclude_column`]
    /// and [`MemoryProxyDB::new_require_column`].
    #[derive(Debug)]
    pub struct MemoryProxyDB {
        inner: Arc<Inner>,
        /// Every query keeps only the proxies of which the row in the column has this value.
        runtime: Vec<(RuntimeColumn, bool)>,
    }

    #[derive(Debug)]
    struct Inner {
        data: internal::ProxyDB,
        /// The proxies that can carry TCP and UDP traffic: worked out once per proxy,
        /// as it depends on more than a single property of it.
        tcp: RowSet,
        udp: RowSet,
    }

    impl MemoryProxyDB {
        fn new(data: internal::ProxyDB) -> Self {
            Self {
                inner: Arc::new(Inner {
                    tcp: data.column(|proxy| proxy.supports_transport(TransportProtocol::Tcp)),
                    udp: data.column(|proxy| proxy.supports_transport(TransportProtocol::Udp)),
                    data,
                }),
                runtime: Vec::new(),
            }
        }

        /// Create a column of proxies that this database never selects,
        /// starting out empty.
        ///
        /// Insert a proxy in it to stop selecting it, e.g. once it is found
        /// to be blocked or unhealthy, and remove it to select it again.
        /// The column can be changed at any time and from any task,
        /// also after the database is handed to a [`ProxyDBLayer`](crate::ProxyDBLayer).
        pub fn new_exclude_column(&mut self) -> ProxyRuntimeColumn {
            self.new_runtime_column(false)
        }

        /// Create a column of proxies that this database is limited to,
        /// starting out empty.
        ///
        /// Only the proxies inserted in it can be selected: as long as it is empty
        /// no proxy is. The column can be changed at any time and from any task,
        /// also after the database is handed to a [`ProxyDBLayer`](crate::ProxyDBLayer).
        pub fn new_require_column(&mut self) -> ProxyRuntimeColumn {
            self.new_runtime_column(true)
        }

        fn new_runtime_column(&mut self, value: bool) -> ProxyRuntimeColumn {
            let rows = RuntimeColumn::new();
            self.runtime.push((rows.clone(), value));
            ProxyRuntimeColumn {
                db: self.inner.clone(),
                rows,
            }
        }

        /// Create a new in-memory proxy database with the given proxies.
        pub fn try_from_rows(proxies: Vec<Proxy>) -> Result<Self, MemoryProxyDBInsertError> {
            internal::ProxyDB::from_rows(proxies)
                .map(Self::new)
                .map_err(|err| match err.kind() {
                    ProxyDBErrorKind::DuplicateKey => {
                        MemoryProxyDBInsertError::duplicate_key(err.into_input())
                    }
                    ProxyDBErrorKind::InvalidRow => {
                        MemoryProxyDBInsertError::invalid_proxy(err.into_input())
                    }
                })
        }

        /// Create a new in-memory proxy database with the given proxies from an iterator.
        pub fn try_from_iter<I>(proxies: I) -> Result<Self, MemoryProxyDBInsertError>
        where
            I: IntoIterator<Item = Proxy>,
        {
            internal::ProxyDB::from_iter(proxies)
                .map(Self::new)
                .map_err(|err| match err.kind() {
                    ProxyDBErrorKind::DuplicateKey => {
                        MemoryProxyDBInsertError::duplicate_key(err.into_input())
                    }
                    ProxyDBErrorKind::InvalidRow => {
                        MemoryProxyDBInsertError::invalid_proxy(err.into_input())
                    }
                })
        }

        /// Return the number of proxies in the database.
        #[must_use]
        pub fn len(&self) -> usize {
            self.inner.data.len()
        }

        /// Returns if the database is empty.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.inner.data.is_empty()
        }

        /// Look up a proxy by id, which has to meet the filter, predicate and runtime columns.
        fn get_by_id(
            &self,
            id: &NonEmptyStr,
            ctx: &ProxyContext,
            filter: &ProxyFilter,
            predicate: &impl ProxyQueryPredicate,
        ) -> Result<&Proxy, MemoryProxyDBQueryError> {
            let data = &self.inner.data;
            let (index, proxy) = data
                .index_by_id(id)
                .and_then(|index| Some((index, data.get(index)?)))
                .ok_or_else(MemoryProxyDBQueryError::not_found)?;
            let allowed = self
                .runtime
                .iter()
                .all(|(rows, value)| rows.get(index) == *value);
            if allowed && proxy.is_match(ctx, filter) && predicate.execute(proxy) {
                Ok(proxy)
            } else {
                Err(MemoryProxyDBQueryError::mismatch())
            }
        }

        #[expect(clippy::needless_pass_by_value)]
        fn query_from_filter(
            &self,
            ctx: ProxyContext,
            filter: ProxyFilter,
        ) -> internal::ProxyDBQuery<'_> {
            let mut query = self.inner.data.query();

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

            for kind in filter.kind.into_iter().flatten() {
                query.kind(kind);
            }

            // Which proxy kinds carry the transport is known per proxy: see `supports_transport`.
            query.and(Filter::Is(match ctx.protocol {
                TransportProtocol::Tcp => &self.inner.tcp,
                TransportProtocol::Udp => &self.inner.udp,
            }));
            for (rows, value) in &self.runtime {
                query.and(Filter::Runtime(rows, *value));
            }

            query
        }
    }

    /// A set of proxies of one [`MemoryProxyDB`] that can be changed
    /// while the database is in use, from any task and without a lock.
    ///
    /// Created with [`MemoryProxyDB::new_exclude_column`], whose proxies are never
    /// selected, or [`MemoryProxyDB::new_require_column`], which limits the selection
    /// to its proxies. Every query of the database, including a lookup by
    /// [`ProxyFilter::id`], takes the column as it is at that moment into account.
    ///
    /// The column holds on to the proxies of its database, so it can be used on its own,
    /// e.g. once the database is handed to a [`ProxyDBLayer`](crate::ProxyDBLayer).
    /// Clones are cheap and share the same proxies.
    ///
    /// A column belongs to exactly one database. When that database is replaced,
    /// e.g. in a live update, create a column for the new database and carry the
    /// proxies over with [`ProxyRuntimeColumn::extend_from`].
    #[derive(Clone)]
    pub struct ProxyRuntimeColumn {
        db: Arc<Inner>,
        rows: RuntimeColumn,
    }

    impl fmt::Debug for ProxyRuntimeColumn {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("ProxyRuntimeColumn")
                .field("len", &self.len())
                .finish_non_exhaustive()
        }
    }

    impl ProxyRuntimeColumn {
        fn index_of(&self, id: &str) -> Option<usize> {
            self.db.data.index_by_id(id)
        }

        /// Insert the proxy with the given id.
        ///
        /// Returns `None` if the database has no proxy with that id,
        /// otherwise `Some(true)` if this call inserted it and `Some(false)`
        /// if it was already in the column. Of concurrent calls for the same proxy
        /// only one gets `Some(true)`, e.g. to make that caller the one that
        /// schedules its removal.
        #[must_use = "the result tells whether the proxy exists and if this call inserted it"]
        pub fn insert(&self, id: &str) -> Option<bool> {
            let index = self.index_of(id)?;
            Some(self.rows.claim(index))
        }

        /// Remove the proxy with the given id.
        ///
        /// Returns `None` if the database has no proxy with that id,
        /// otherwise whether it was in the column.
        pub fn remove(&self, id: &str) -> Option<bool> {
            let index = self.index_of(id)?;
            Some(self.rows.set(index, false))
        }

        /// Returns `true` if the proxy with the given id is in the column.
        #[must_use]
        pub fn contains(&self, id: &str) -> bool {
            self.index_of(id).is_some_and(|index| self.rows.get(index))
        }

        /// The number of proxies in the column.
        #[must_use]
        pub fn len(&self) -> usize {
            self.rows.count()
        }

        /// Returns `true` if no proxy is in the column.
        #[must_use]
        pub fn is_empty(&self) -> bool {
            self.rows.iter().next().is_none()
        }

        /// Remove all proxies from the column.
        pub fn clear(&self) {
            self.rows.clear();
        }

        /// Iterate over the proxies in the column.
        pub fn iter(&self) -> impl Iterator<Item = &Proxy> + '_ {
            self.rows.iter().filter_map(|index| self.db.data.get(index))
        }

        /// Insert every proxy of `other`, typically a column of the database
        /// this one replaces, that this column's database also has.
        ///
        /// Proxies are matched by id. Returns the number of proxies of `other`
        /// found in this column's database, all of which are in this column afterwards.
        ///
        /// A proxy inserted in `other` after this call is not carried over: in a live update,
        /// switch to the new column before `LiveUpdateProxyDBSetter::set`,
        /// or run this again afterwards.
        pub fn extend_from(&self, other: &Self) -> usize {
            let mut carried = 0;
            for index in other
                .iter()
                .filter_map(|proxy| self.db.data.index_by_id(&proxy.id))
            {
                self.rows.set(index, true);
                carried += 1;
            }
            carried
        }
    }

    impl ProxyDB for MemoryProxyDB {
        type Error = MemoryProxyDBQueryError;

        async fn get_proxies_if(
            &self,
            ctx: ProxyContext,
            filter: ProxyFilter,
            predicate: impl ProxyQueryPredicate,
            limit: Option<NonZeroUsize>,
        ) -> Result<NonEmptyVec<Proxy>, Self::Error> {
            if let Some(id) = &filter.id {
                self.get_by_id(id, &ctx, &filter, &predicate)
                    .map(|proxy| NonEmptyVec::new(proxy.clone()))
            } else {
                let query = self.query_from_filter(ctx, filter);
                let result = query
                    .execute()
                    .ok_or_else(MemoryProxyDBQueryError::not_found)?;
                // The predicate is only asked about the proxies that match the filter,
                // and none of them is copied unless it is returned.
                let matches = result.iter().filter(|proxy| predicate.execute(proxy));
                let mut rng = rand::rng();
                let mut proxies = if let Some(limit) = limit {
                    matches
                        .sample(&mut rng, limit.get())
                        .into_iter()
                        .cloned()
                        .collect()
                } else {
                    matches.cloned().collect::<Vec<_>>()
                };
                // a sample has its elements in database order, and callers try candidates in the returned order
                proxies.shuffle(&mut rng);
                NonEmptyVec::collect(proxies).ok_or_else(MemoryProxyDBQueryError::not_found)
            }
        }

        async fn get_proxy_if(
            &self,
            ctx: ProxyContext,
            filter: ProxyFilter,
            predicate: impl ProxyQueryPredicate,
        ) -> Result<Proxy, Self::Error> {
            if let Some(id) = &filter.id {
                self.get_by_id(id, &ctx, &filter, &predicate).cloned()
            } else {
                // A random match, found without working out all of them
                // if many proxies match the filter.
                self.query_from_filter(ctx, filter)
                    .any_where(|proxy| predicate.execute(proxy))
                    .cloned()
                    .ok_or_else(MemoryProxyDBQueryError::not_found)
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
    #[cfg(feature = "csv")]
    mod tests {
        use super::*;
        use crate::ProxyProtocols;
        use itertools::Itertools;
        use rama_net::address::ProxyProtocol;
        use rama_utils::str::non_empty_str;

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
            let proxies = db
                .get_proxies(ctx.clone(), filter.clone(), None)
                .await
                .unwrap();
            assert_eq!(proxies.len(), 1);
            assert_eq!(proxies.head.id, "3031533634");

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
                kind: Some(vec![ProxyType::Mobile]),
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
            let err = db
                .get_proxies(ctx.clone(), filter.clone(), None)
                .await
                .unwrap_err();
            assert_eq!(err.kind(), MemoryProxyDBQueryErrorKind::NotFound);

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
                    kind: Some(vec![ProxyType::Datacenter]),
                    ..Default::default()
                },
                ProxyFilter {
                    id: Some(non_empty_str!("3031533634")),
                    kind: Some(vec![ProxyType::Residential]),
                    ..Default::default()
                },
                ProxyFilter {
                    id: Some(non_empty_str!("3031533634")),
                    kind: Some(vec![ProxyType::Isp]),
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
                let err = db
                    .get_proxies(ctx.clone(), filter.clone(), None)
                    .await
                    .unwrap_err();
                assert_eq!(err.kind(), MemoryProxyDBQueryErrorKind::Mismatch);

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
            let err = db
                .get_proxies(ctx.clone(), filter.clone(), None)
                .await
                .unwrap_err();
            assert_eq!(err.kind(), MemoryProxyDBQueryErrorKind::Mismatch);

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
                assert!(proxy.protocols.iter().any(|protocol| matches!(
                    protocol,
                    ProxyProtocol::Socks5 {
                        transport: Some(TransportProtocol::Udp),
                        ..
                    }
                )));
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
                assert!(proxy.supports_transport(TransportProtocol::Tcp));
                found_ids.push(proxy.id);
            }
            assert_eq!(found_ids.len(), 64);
            assert_eq!(
                found_ids.iter().sorted().join(","),
                r#"1125300915,1259341971,1264821985,129108927,1316455915,1425588737,153202126,1571861931,1684342915,1742367441,1810781137,1836040682,1844412609,1885107293,1916851007,2021561518,20647117,2079461709,2107229589,2141152822,2261612122,2438596154,2497865606,2521901221,2551759475,2560727338,2593294918,2596743625,2745456299,2798907087,2854473221,2880295577,2909724448,2912880381,292096733,2950022859,2951529660,3031533634,3187902553,3269411602,3269465574,3269921904,339020035,3481200027,3498810974,3503691556,362091157,3679054656,371209663,3732488183,3836943127,3861736957,39048766,3951672504,3976711563,4062553709,4187178960,49590203,56402588,724884866,738626121,767809962,846528631,906390012"#,
            );
        }

        #[tokio::test]
        async fn plural_query_returns_every_matching_proxy_once() {
            let db = memproxydb().await;

            let proxies = db
                .get_proxies(h2_proxy_context(), ProxyFilter::default(), None)
                .await
                .unwrap();
            let ids = proxies
                .iter()
                .map(|proxy| proxy.id.as_ref())
                .sorted()
                .collect::<Vec<_>>();

            assert_eq!(ids.len(), 64);
            assert_eq!(ids.iter().unique().count(), ids.len());
            assert_eq!(
                ids.join(","),
                r#"1125300915,1259341971,1264821985,129108927,1316455915,1425588737,153202126,1571861931,1684342915,1742367441,1810781137,1836040682,1844412609,1885107293,1916851007,2021561518,20647117,2079461709,2107229589,2141152822,2261612122,2438596154,2497865606,2521901221,2551759475,2560727338,2593294918,2596743625,2745456299,2798907087,2854473221,2880295577,2909724448,2912880381,292096733,2950022859,2951529660,3031533634,3187902553,3269411602,3269465574,3269921904,339020035,3481200027,3498810974,3503691556,362091157,3679054656,371209663,3732488183,3836943127,3861736957,39048766,3951672504,3976711563,4062553709,4187178960,49590203,56402588,724884866,738626121,767809962,846528631,906390012"#,
            );
        }

        #[tokio::test]
        async fn plural_query_honors_result_limit() {
            let db = memproxydb().await;

            let proxies = db
                .get_proxies(
                    h2_proxy_context(),
                    ProxyFilter::default(),
                    NonZeroUsize::new(5),
                )
                .await
                .unwrap();

            assert_eq!(proxies.len(), 5);
            assert_eq!(proxies.iter().map(|proxy| &proxy.id).unique().count(), 5);
            assert!(
                proxies
                    .iter()
                    .all(|proxy| proxy.supports_transport(TransportProtocol::Tcp))
            );
        }

        #[tokio::test]
        async fn plural_query_applies_predicate_to_every_candidate() {
            let db = memproxydb().await;

            let proxies = db
                .get_proxies_if(
                    h2_proxy_context(),
                    ProxyFilter::default(),
                    |proxy: &Proxy| proxy.kind == ProxyType::Mobile,
                    None,
                )
                .await
                .unwrap();

            assert!(proxies.iter().all(|proxy| proxy.kind == ProxyType::Mobile));
            assert!(proxies.len() < 50);
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
            assert_eq!(found_ids.len(), 7);
            assert_eq!(
                found_ids.iter().sorted().join(","),
                r#"1742367441,2141152822,2593294918,2596743625,2912880381,371209663,767809962"#,
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
            assert_eq!(found_ids.len(), 12);
            assert_eq!(
                found_ids.iter().sorted().join(","),
                r#"1742367441,2141152822,2521901221,2560727338,2593294918,2596743625,2912880381,292096733,371209663,39048766,3951672504,767809962"#,
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
            assert_eq!(found_ids.len(), 6);
            assert_eq!(
                found_ids.iter().sorted().join(","),
                r#"2141152822,2596743625,2912880381,292096733,3481200027,3951672504"#,
            );
        }

        #[tokio::test]
        async fn test_memorydb_get_h3_capable_mobile_residential_be_asterix_proxies() {
            let db = memproxydb().await;
            let ctx = h3_proxy_context();
            let filter = ProxyFilter {
                country: Some(vec!["BE".into()]),
                kind: Some(vec![ProxyType::Mobile]),
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
                "153202126",
                "1571861931",
                "1684342915",
                "1742367441",
                "1810781137",
                "1836040682",
                "1844412609",
                "1885107293",
                "1916851007",
                "2021561518",
                "20647117",
                "2079461709",
                "2107229589",
                "2141152822",
                "2261612122",
                "2438596154",
                "2497865606",
                "2521901221",
                "2551759475",
                "2560727338",
                "2593294918",
                "2596743625",
                "2745456299",
                "2798907087",
                "2854473221",
                "2880295577",
                "2909724448",
                "2912880381",
                "292096733",
                "2950022859",
                "2951529660",
                "3031533634",
                "3187902553",
                "3269411602",
                "3269465574",
                "3269921904",
                "339020035",
                "3481200027",
                "3498810974",
                "3503691556",
                "362091157",
                "3679054656",
                "371209663",
                "3732488183",
                "3836943127",
                "3861736957",
                "39048766",
                "3951672504",
                "3976711563",
                "4062553709",
                "4187178960",
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
                address: "example.com:80".parse().unwrap(),
                credential: None,
                protocols: ProxyProtocols::from([
                    ProxyProtocol::Socks5 {
                        remote_dns: false,
                        transport: Some(TransportProtocol::Udp),
                        secure: false,
                    },
                    ProxyProtocol::Socks5 {
                        remote_dns: true,
                        transport: Some(TransportProtocol::Udp),
                        secure: false,
                    },
                    ProxyProtocol::HTTP,
                    ProxyProtocol::HTTPS,
                ]),
                kind: ProxyType::Mobile,
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
                assert!(proxy.is_match(&ctx, &filter));
            }
        }

        #[tokio::test]
        async fn test_db_proxy_filter_any_only_matches_any_value() {
            let db = MemoryProxyDB::try_from_iter([Proxy {
                id: non_empty_str!("1"),
                address: "example.com:80".parse().unwrap(),
                credential: None,
                protocols: ProxyProtocols::from([
                    ProxyProtocol::Socks5 {
                        remote_dns: false,
                        transport: Some(TransportProtocol::Udp),
                        secure: false,
                    },
                    ProxyProtocol::Socks5 {
                        remote_dns: true,
                        transport: Some(TransportProtocol::Udp),
                        secure: false,
                    },
                    ProxyProtocol::HTTP,
                    ProxyProtocol::HTTPS,
                ]),
                kind: ProxyType::Mobile,
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
                    address: "example.com:80".parse().unwrap(),
                    credential: None,
                    protocols: ProxyProtocols::from([
                        ProxyProtocol::Socks5 {
                            remote_dns: false,
                            transport: Some(TransportProtocol::Udp),
                            secure: false,
                        },
                        ProxyProtocol::Socks5 {
                            remote_dns: true,
                            transport: Some(TransportProtocol::Udp),
                            secure: false,
                        },
                        ProxyProtocol::HTTP,
                        ProxyProtocol::HTTPS,
                    ]),
                    kind: ProxyType::Mobile,
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
                    address: "example.com:80".parse().unwrap(),
                    credential: None,
                    protocols: ProxyProtocols::from([
                        ProxyProtocol::Socks5 {
                            remote_dns: false,
                            transport: Some(TransportProtocol::Udp),
                            secure: false,
                        },
                        ProxyProtocol::Socks5 {
                            remote_dns: true,
                            transport: Some(TransportProtocol::Udp),
                            secure: false,
                        },
                        ProxyProtocol::HTTP,
                        ProxyProtocol::HTTPS,
                    ]),
                    kind: ProxyType::Mobile,
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
                    address: "example.com:80".parse().unwrap(),
                    credential: None,
                    protocols: ProxyProtocols::from([
                        ProxyProtocol::Socks5 {
                            remote_dns: false,
                            transport: Some(TransportProtocol::Udp),
                            secure: false,
                        },
                        ProxyProtocol::Socks5 {
                            remote_dns: true,
                            transport: Some(TransportProtocol::Udp),
                            secure: false,
                        },
                        ProxyProtocol::HTTP,
                        ProxyProtocol::HTTPS,
                    ]),
                    kind: ProxyType::Mobile,
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
                    address: "example.com:80".parse().unwrap(),
                    credential: None,
                    protocols: ProxyProtocols::from([
                        ProxyProtocol::Socks5 {
                            remote_dns: false,
                            transport: Some(TransportProtocol::Udp),
                            secure: false,
                        },
                        ProxyProtocol::Socks5 {
                            remote_dns: true,
                            transport: Some(TransportProtocol::Udp),
                            secure: false,
                        },
                        ProxyProtocol::HTTP,
                        ProxyProtocol::HTTPS,
                    ]),
                    kind: ProxyType::Mobile,
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

    #[cfg(test)]
    mod runtime_column_tests {
        use super::*;
        use itertools::Itertools;
        use rama_net::address::ProxyProtocol;
        use std::collections::BTreeSet;

        fn proxy(id: &str) -> Proxy {
            Proxy {
                id: NonEmptyStr::try_from(id).unwrap(),
                address: "127.0.0.1:8080".parse().unwrap(),
                credential: None,
                protocols: ProxyProtocols::from([ProxyProtocol::HTTP]),
                kind: ProxyType::Datacenter,
                pool_id: None,
                continent: None,
                country: None,
                state: None,
                city: None,
                carrier: None,
                asn: None,
            }
        }

        fn db(ids: &[&str]) -> MemoryProxyDB {
            MemoryProxyDB::try_from_iter(ids.iter().map(|id| proxy(id))).unwrap()
        }

        fn tcp() -> ProxyContext {
            ProxyContext {
                protocol: TransportProtocol::Tcp,
            }
        }

        fn by_id(id: &str) -> ProxyFilter {
            ProxyFilter {
                id: Some(NonEmptyStr::try_from(id).unwrap()),
                ..Default::default()
            }
        }

        async fn selectable(db: &impl ProxyDB<Error = MemoryProxyDBQueryError>) -> Vec<Box<str>> {
            match db.get_proxies(tcp(), ProxyFilter::default(), None).await {
                Ok(proxies) => proxies
                    .iter()
                    .map(|proxy| Box::from(proxy.id.as_ref()))
                    .sorted()
                    .collect(),
                Err(err) => {
                    assert_eq!(err.kind(), MemoryProxyDBQueryErrorKind::NotFound);
                    Vec::new()
                }
            }
        }

        fn ids(column: &ProxyRuntimeColumn) -> BTreeSet<&str> {
            column.iter().map(|proxy| proxy.id.as_ref()).collect()
        }

        #[tokio::test]
        async fn excluded_proxy_is_never_selected() {
            let mut db = db(&["a", "b"]);
            let blocked = db.new_exclude_column();
            assert_eq!(selectable(&db).await, ["a", "b"].map(Box::from));

            assert_eq!(blocked.insert("a"), Some(true));
            for _ in 0..50 {
                let proxy = db.get_proxy(tcp(), ProxyFilter::default()).await.unwrap();
                assert_eq!(proxy.id, "b");
                let limited = db
                    .get_proxies(tcp(), ProxyFilter::default(), NonZeroUsize::new(2))
                    .await
                    .unwrap();
                assert_eq!(limited.len(), 1);
                assert_eq!(limited.head.id, "b");
            }
            assert_eq!(selectable(&db).await, ["b"].map(Box::from));

            let err = db.get_proxy(tcp(), by_id("a")).await.unwrap_err();
            assert_eq!(err.kind(), MemoryProxyDBQueryErrorKind::Mismatch);
            let err = db.get_proxies(tcp(), by_id("a"), None).await.unwrap_err();
            assert_eq!(err.kind(), MemoryProxyDBQueryErrorKind::Mismatch);
            assert_eq!(db.get_proxy(tcp(), by_id("b")).await.unwrap().id, "b");

            assert_eq!(blocked.remove("a"), Some(true));
            assert_eq!(selectable(&db).await, ["a", "b"].map(Box::from));
            assert_eq!(db.get_proxy(tcp(), by_id("a")).await.unwrap().id, "a");
        }

        #[tokio::test]
        async fn limited_plural_query_is_shuffled() {
            let db = db(&["a", "b"]);
            let mut firsts = BTreeSet::new();
            for _ in 0..200 {
                let proxies = db
                    .get_proxies(tcp(), ProxyFilter::default(), NonZeroUsize::new(5))
                    .await
                    .unwrap();
                assert_eq!(proxies.len(), 2);
                firsts.insert(proxies.head.id);
            }
            assert_eq!(firsts.len(), 2);
        }

        #[tokio::test]
        async fn required_column_limits_selection_to_its_proxies() {
            let mut db = db(&["a", "b", "c"]);
            let allowed = db.new_require_column();

            assert!(selectable(&db).await.is_empty());
            let err = db
                .get_proxy(tcp(), ProxyFilter::default())
                .await
                .unwrap_err();
            assert_eq!(err.kind(), MemoryProxyDBQueryErrorKind::NotFound);
            let err = db.get_proxy(tcp(), by_id("a")).await.unwrap_err();
            assert_eq!(err.kind(), MemoryProxyDBQueryErrorKind::Mismatch);

            assert_eq!(allowed.insert("b"), Some(true));
            assert_eq!(allowed.insert("c"), Some(true));
            assert_eq!(selectable(&db).await, ["b", "c"].map(Box::from));
            assert_eq!(db.get_proxy(tcp(), by_id("c")).await.unwrap().id, "c");
        }

        #[tokio::test]
        async fn exclude_and_require_columns_combine() {
            let mut db = db(&["a", "b", "c"]);
            let allowed = db.new_require_column();
            let blocked = db.new_exclude_column();
            assert_eq!(allowed.insert("a"), Some(true));
            assert_eq!(allowed.insert("b"), Some(true));
            assert_eq!(blocked.insert("b"), Some(true));
            assert_eq!(blocked.insert("c"), Some(true));

            assert_eq!(selectable(&db).await, ["a"].map(Box::from));
            for _ in 0..20 {
                let proxy = db.get_proxy(tcp(), ProxyFilter::default()).await.unwrap();
                assert_eq!(proxy.id, "a");
            }
        }

        #[tokio::test]
        async fn unknown_id_changes_nothing() {
            let mut db = db(&["a"]);
            let blocked = db.new_exclude_column();

            assert_eq!(blocked.insert("unknown"), None);
            assert_eq!(blocked.insert(""), None);
            assert_eq!(blocked.remove("unknown"), None);
            assert!(!blocked.contains("unknown"));
            assert!(blocked.is_empty());
            assert_eq!(selectable(&db).await, ["a"].map(Box::from));
        }

        #[test]
        fn insert_reports_the_call_that_inserted() {
            let mut db = db(&["a", "b"]);
            let blocked = db.new_exclude_column();

            assert!(!blocked.contains("a"));
            assert_eq!(blocked.insert("a"), Some(true));
            assert_eq!(blocked.insert("a"), Some(false));
            assert!(blocked.contains("a"));
            assert!(!blocked.contains("b"));
            assert_eq!(blocked.remove("a"), Some(true));
            assert_eq!(blocked.remove("a"), Some(false));
            assert_eq!(blocked.insert("a"), Some(true));
        }

        #[test]
        fn concurrent_inserts_are_claimed_once() {
            let mut db = db(&["a"]);
            let blocked = db.new_exclude_column();
            let claims = std::thread::scope(|scope| {
                let threads = (0..8)
                    .map(|_| scope.spawn(|| blocked.insert("a") == Some(true)))
                    .collect::<Vec<_>>();
                threads
                    .into_iter()
                    .map(|thread| thread.join().unwrap())
                    .filter(|claimed| *claimed)
                    .count()
            });
            assert_eq!(claims, 1);
        }

        #[test]
        fn len_iter_and_clear() {
            let mut db = db(&["a", "b", "c"]);
            let blocked = db.new_exclude_column();
            let clone = blocked.clone();
            assert_eq!(blocked.len(), 0);
            assert!(blocked.is_empty());
            assert!(blocked.iter().next().is_none());

            assert_eq!(clone.insert("c"), Some(true));
            assert_eq!(blocked.insert("a"), Some(true));
            assert_eq!(blocked.len(), 2);
            assert!(!blocked.is_empty());
            assert_eq!(ids(&blocked), BTreeSet::from(["a", "c"]));
            assert_eq!(ids(&clone), ids(&blocked));

            clone.clear();
            assert_eq!(blocked.len(), 0);
            assert!(blocked.is_empty());
            assert!(!blocked.contains("a"));
        }

        #[tokio::test]
        async fn extend_from_carries_over_the_shared_ids() {
            let mut old = db(&["a", "b", "c"]);
            let old_blocked = old.new_exclude_column();
            assert_eq!(old_blocked.insert("a"), Some(true));
            assert_eq!(old_blocked.insert("b"), Some(true));

            // the new database has its rows in another order, without "a" and with "d"
            let mut new = db(&["d", "c", "b"]);
            let new_blocked = new.new_exclude_column();
            assert_eq!(new_blocked.extend_from(&old_blocked), 1);
            assert_eq!(ids(&new_blocked), BTreeSet::from(["b"]));
            assert_eq!(selectable(&new).await, ["c", "d"].map(Box::from));

            // the columns stay independent of each other
            assert_eq!(old_blocked.remove("b"), Some(true));
            assert!(new_blocked.contains("b"));
            assert_eq!(new_blocked.extend_from(&old_blocked), 0);
            assert_eq!(new_blocked.len(), 1);
        }

        #[tokio::test]
        async fn column_changed_from_another_task_is_seen_by_shared_db() {
            let mut db = db(&["a", "b"]);
            let blocked = db.new_exclude_column();
            let db = Arc::new(db);

            tokio::spawn({
                let blocked = blocked.clone();
                async move { blocked.insert("b") }
            })
            .await
            .unwrap();
            for _ in 0..20 {
                let proxy = db.get_proxy(tcp(), ProxyFilter::default()).await.unwrap();
                assert_eq!(proxy.id, "a");
            }

            std::thread::spawn(move || blocked.remove("b"))
                .join()
                .unwrap();
            assert_eq!(selectable(&db).await, ["a", "b"].map(Box::from));
        }

        #[cfg(feature = "live-update")]
        #[tokio::test]
        async fn blocked_proxy_stays_blocked_across_live_update() {
            let (reader, writer) = crate::proxy_db_updater();

            let mut first = db(&["a", "b"]);
            let blocked = first.new_exclude_column();
            writer.set(first);
            assert_eq!(blocked.insert("a"), Some(true));
            for _ in 0..20 {
                let proxy = reader
                    .get_proxy(tcp(), ProxyFilter::default())
                    .await
                    .unwrap();
                assert_eq!(proxy.id, "b");
            }

            let mut second = db(&["c", "b", "a"]);
            let next_blocked = second.new_exclude_column();
            assert_eq!(next_blocked.extend_from(&blocked), 1);
            writer.set(second);

            let mut seen = BTreeSet::new();
            for _ in 0..100 {
                let proxy = reader
                    .get_proxy(tcp(), ProxyFilter::default())
                    .await
                    .unwrap();
                seen.insert(proxy.id);
            }
            assert_eq!(
                seen.iter().map(AsRef::as_ref).collect::<Vec<&str>>(),
                ["b", "c"]
            );
            reader.get_proxy(tcp(), by_id("a")).await.unwrap_err();

            assert_eq!(next_blocked.remove("a"), Some(true));
            assert_eq!(reader.get_proxy(tcp(), by_id("a")).await.unwrap().id, "a");
        }
    }
}

#[cfg(feature = "memory-db")]
#[cfg_attr(docsrs, doc(cfg(feature = "memory-db")))]
pub use memdb::{
    MemoryProxyDB, MemoryProxyDBInsertError, MemoryProxyDBInsertErrorKind, MemoryProxyDBQueryError,
    MemoryProxyDBQueryErrorKind, ProxyRuntimeColumn,
};
