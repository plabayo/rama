use super::ProxyDB;
use arc_swap::ArcSwap;
use rama_core::error::{BoxError, ErrorContext};
use std::{fmt, ops::Deref, sync::Arc};

/// Create a new [`ProxyDB`] updater which allows you to have a (typically in-memory) [`ProxyDB`]
/// which you can update live.
///
/// This construct returns a pair of:
///
/// - [`LiveUpdateProxyDB`]: to be used as the [`ProxyDB`] instead of the inner `T`, dubbed the "reader";
/// - [`LiveUpdateProxyDBSetter`]: to be used as the _only_ way to set the inner `T` as many time as you wish, dubbed the "writer".
///
/// Note that the inner `T` is not yet created when this construct returns this pair.
/// Until you actually called [`LiveUpdateProxyDBSetter::set`] with the inner `T` [`ProxyDB`],
/// any [`ProxyDB`] trait method call to [`LiveUpdateProxyDB`] will fail.
///
/// It is therefore recommended that you immediately set the inner `T` [`ProxyDB`] upon
/// receiving the reader/writer pair, prior to starting to actually use the [`ProxyDB`]
/// in your rama service stack.
///
/// This goal of this updater is to be fast for reading (getting proxies),
/// and slow for the infrequent updates (setting the proxy db). As such it is recommended
/// to not update the [`ProxyDB`] to frequent. An example use case for this updater
/// could be to update your in-memory proxy database every 15 minutes, by populating it from
/// a shared external database (e.g. MySQL`). Failures to create a new `T` ProxyDB should be handled
/// by the Writer, and can be as simple as just logging it and move on without an update.
pub fn proxy_db_updater<T>() -> (LiveUpdateProxyDB<T>, LiveUpdateProxyDBSetter<T>)
where
    T: ProxyDB<Error: Into<BoxError>>,
{
    let data = Arc::new(ArcSwap::from_pointee(None));
    let reader = LiveUpdateProxyDB(data.clone());
    let writer = LiveUpdateProxyDBSetter(data);
    (reader, writer)
}

/// A wrapper around a `T` [`ProxyDB`] which can be updated
/// through the _only_ linked writer [`LiveUpdateProxyDBSetter`].
///
/// See [`proxy_db_updater`] for more details.
pub struct LiveUpdateProxyDB<T>(Arc<ArcSwap<Option<T>>>);

impl<T: fmt::Debug> fmt::Debug for LiveUpdateProxyDB<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LiveUpdateProxyDB").field(&self.0).finish()
    }
}

impl<T> Clone for LiveUpdateProxyDB<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> ProxyDB for LiveUpdateProxyDB<T>
where
    T: ProxyDB<Error: Into<BoxError>>,
{
    type Error = BoxError;

    async fn get_proxy_if(
        &self,
        ctx: super::ProxyContext,
        filter: super::ProxyFilter,
        predicate: impl super::ProxyQueryPredicate,
    ) -> Result<super::Proxy, Self::Error> {
        match self.0.load().deref().deref() {
            Some(db) => db
                .get_proxy_if(ctx, filter, predicate)
                .await
                .into_box_error(),
            None => Err(BoxError::from(
                "live proxy db: proxy db is None: get_proxy_if unable to proceed",
            )),
        }
    }

    async fn get_proxy(
        &self,
        ctx: super::ProxyContext,
        filter: super::ProxyFilter,
    ) -> Result<super::Proxy, Self::Error> {
        match self.0.load().deref().deref() {
            Some(db) => db.get_proxy(ctx, filter).await.into_box_error(),
            None => Err(BoxError::from(
                "live proxy db: proxy db is None: get_proxy unable to proceed",
            )),
        }
    }
}

/// Writer to set a new [`ProxyDB`] in the linked [`LiveUpdateProxyDB`].
///
/// There can only be one writer [`LiveUpdateProxyDBSetter`] for each
/// collection of [`LiveUpdateProxyDB`] linked to the same internal data `T`.
///
/// See [`proxy_db_updater`] for more details.
pub struct LiveUpdateProxyDBSetter<T>(Arc<ArcSwap<Option<T>>>);

impl<T> LiveUpdateProxyDBSetter<T> {
    /// Set the new `T` [`ProxyDB`] to be used for future [`ProxyDB`]
    /// calls made to the linked [`LiveUpdateProxyDB`] instances.
    pub fn set(&self, db: T) {
        self.0.store(Arc::new(Some(db)))
    }
}

impl<T: fmt::Debug> fmt::Debug for LiveUpdateProxyDBSetter<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LiveUpdateProxyDBSetter")
            .field(&self.0)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Proxy, ProxyFilter, proxydb::ProxyContext};
    use rama_net::{asn::Asn, transport::TransportProtocol};
    use rama_utils::str::non_empty_str;

    use super::*;

    #[tokio::test]
    async fn test_empty_live_update_db() {
        let (reader, _) = proxy_db_updater::<Proxy>();
        assert!(
            reader
                .get_proxy(
                    ProxyContext {
                        protocol: TransportProtocol::Tcp,
                    },
                    ProxyFilter::default(),
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_live_update_db_updated() {
        let (reader, writer) = proxy_db_updater();

        assert!(
            reader
                .get_proxy(
                    ProxyContext {
                        protocol: TransportProtocol::Tcp,
                    },
                    ProxyFilter::default(),
                )
                .await
                .is_err()
        );

        writer.set(Proxy {
            id: non_empty_str!("id"),
            address: "authority:80".parse().unwrap(),
            tcp: true,
            udp: false,
            http: false,
            https: true,
            socks5: false,
            socks5h: false,
            datacenter: true,
            residential: false,
            mobile: true,
            pool_id: Some("pool_id".into()),
            continent: Some("continent".into()),
            country: Some("country".into()),
            state: Some("state".into()),
            city: Some("city".into()),
            carrier: Some("carrier".into()),
            asn: Some(Asn::from_static(1)),
        });

        assert_eq!(
            "id",
            reader
                .get_proxy(
                    ProxyContext {
                        protocol: TransportProtocol::Tcp,
                    },
                    ProxyFilter::default(),
                )
                .await
                .unwrap()
                .id
        );

        assert!(
            reader
                .get_proxy(
                    ProxyContext {
                        protocol: TransportProtocol::Udp,
                    },
                    ProxyFilter::default(),
                )
                .await
                .is_err()
        );

        assert_eq!(
            "id",
            reader
                .get_proxy(
                    ProxyContext {
                        protocol: TransportProtocol::Tcp,
                    },
                    ProxyFilter::default(),
                )
                .await
                .unwrap()
                .id
        );
    }
}
