use rama_core::extensions::Extensions;

use super::{DialedProxyConnection, proxy_request};
use crate::client::{
    ProxyRoute,
    pool::{ConnectionReuse, ConnectionReusePolicy, PoolPartition, ReuseKey},
};

/// The reuse rules of a connection to a proxy, for the connection that carries
/// origin requests over it: a tunnel through it, or that connection itself for a
/// forwarding proxy. `None` if `connection` is not a connection to a proxy.
///
/// Its rules describe that connection, so a pool checks them against each
/// origin request as [`proxy_request`] turns it into a request to the proxy.
/// The pool partition of the connection to the proxy is one of them.
#[must_use]
pub fn proxy_connection_reuse(connection: &Extensions) -> Option<ConnectionReuse> {
    let marker = connection.get_ref::<DialedProxyConnection>()?;
    Some(ConnectionReuse::restriction(ProxyConnectionReuse {
        rules: connection.get_ref::<ConnectionReuse>().cloned(),
        partition: marker.partition.clone(),
    }))
}

/// The rules a connection to a proxy was published with, and the pool partition it
/// was dialed under, checked against each origin request as [`proxy_request`] turns
/// it into a request to that proxy.
#[derive(Debug)]
struct ProxyConnectionReuse {
    rules: Option<ConnectionReuse>,
    partition: Option<PoolPartition>,
}

impl ProxyConnectionReuse {
    fn partition_key(partition: Option<&PoolPartition>) -> ReuseKey {
        match partition {
            Some(partition) => ReuseKey::of::<Self>().and(partition.key().clone()),
            None => ReuseKey::of::<Self>(),
        }
    }
}

impl ConnectionReusePolicy for ProxyConnectionReuse {
    fn classifier(&self) -> ReuseKey {
        match &self.rules {
            Some(rules) => rules.classifier().clone().and(ReuseKey::of::<Self>()),
            None => ReuseKey::of::<Self>(),
        }
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        let partition = Self::partition_key(self.partition.as_ref());
        match &self.rules {
            Some(rules) => Some(partition.and(rules.key()?.clone())),
            None => Some(partition),
        }
    }

    fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
        let proxy = input.get_ref::<ProxyRoute>()?.proxy_address()?;
        let view = proxy_request(proxy, input).extensions;
        let partition = Self::partition_key(view.get_ref::<PoolPartition>());
        match &self.rules {
            Some(rules) => Some(partition.and(rules.request_key(&view)?)),
            None => Some(partition),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        address::{HostWithPort, ProxyAddress},
        client::{
            ConnectRequest, ConnectorService as _, EstablishedClientConnection,
            ProxyConnectionExtensions, ProxyDialRequest, ProxyDialer,
            pool::{BasicConnIdentifier, LruDropPool, PooledConnector},
        },
        stream::DefaultExtensionsTransfer,
    };
    use rama_core::{Service as _, ServiceInput, extensions::ExtensionsRef, service::service_fn};
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    fn socks_proxy() -> ProxyAddress {
        "socks5://user:secret@proxy.example:1080".parse().unwrap()
    }

    fn tunnel_over(proxy: &ProxyAddress, origin: &Extensions) -> ConnectionReuse {
        let leg = proxy_request(proxy, origin).extensions;
        let connection = Extensions::new();
        connection.insert(DialedProxyConnection {
            partition: leg.get_ref::<PoolPartition>().cloned(),
        });
        proxy_connection_reuse(&connection).expect("a connection to a proxy")
    }

    fn routed_with_hop_partition(
        proxy: &ProxyAddress,
        partition: Option<PoolPartition>,
    ) -> Extensions {
        let origin = Extensions::new();
        let bag = Extensions::new();
        if let Some(partition) = partition {
            bag.insert(partition);
        }
        origin.insert(ProxyConnectionExtensions(bag));
        origin.insert(ProxyRoute::Proxy(proxy.clone()));
        origin
    }

    #[test]
    fn a_hop_partition_scopes_the_connection_identity() {
        let proxy = socks_proxy();
        let origin = |partition| routed_with_hop_partition(&proxy, partition);
        let u8 = || Some(PoolPartition::of::<u8>());

        assert!(tunnel_over(&proxy, &origin(u8())).matches(&origin(u8())));
        assert!(
            !tunnel_over(&proxy, &origin(u8())).matches(&origin(Some(PoolPartition::of::<u16>())))
        );
        assert!(!tunnel_over(&proxy, &origin(u8())).matches(&origin(None)));
        assert!(tunnel_over(&proxy, &origin(None)).matches(&origin(None)));
    }

    #[tokio::test]
    async fn a_pool_dials_once_per_hop_partition() {
        #[derive(Debug, ExtensionsRef)]
        struct Tunnel {
            extensions: Extensions,
        }

        let dialer = ProxyDialer::new(service_fn(|input: ConnectRequest| async move {
            Ok::<_, Infallible>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(()),
            })
        }));
        let dials = Arc::new(AtomicUsize::new(0));
        let inner = service_fn({
            let dials = dials.clone();
            move |input: ConnectRequest| {
                dials.fetch_add(1, Ordering::Relaxed);
                let dialer = dialer.clone();
                async move {
                    let proxy = input
                        .extensions
                        .get_ref::<ProxyRoute>()
                        .and_then(ProxyRoute::proxy_address)
                        .cloned()
                        .unwrap();
                    let connection = dialer
                        .connect(ProxyDialRequest {
                            proxy,
                            origin: input.extensions.clone(),
                        })
                        .await
                        .unwrap()
                        .conn;
                    let conn = Tunnel {
                        extensions: connection
                            .extensions()
                            .fork_connection(&DefaultExtensionsTransfer),
                    };
                    Ok::<_, Infallible>(EstablishedClientConnection { input, conn })
                }
            }
        });
        let pool = LruDropPool::try_new(1, 4)
            .unwrap()
            .with_drop_connection_if_no_response(false);
        let connector = PooledConnector::new(inner, pool, BasicConnIdentifier::new());

        let proxy = "http://proxy.example:8080".parse::<ProxyAddress>().unwrap();
        let request = |partition: Option<PoolPartition>| {
            let input = ConnectRequest::new(HostWithPort::example_domain_https());
            let bag = Extensions::new();
            if let Some(partition) = partition {
                bag.insert(partition);
            }
            input.extensions.insert(ProxyConnectionExtensions(bag));
            input.extensions.insert(ProxyRoute::Proxy(proxy.clone()));
            input
        };

        for (hop, expected) in [
            (Some(PoolPartition::of::<u8>()), 1),
            (Some(PoolPartition::of::<u8>()), 1),
            (Some(PoolPartition::of::<u16>()), 2),
            (Some(PoolPartition::of::<u16>()), 2),
            (None, 3),
            (None, 3),
        ] {
            drop(connector.serve(request(hop)).await.unwrap().conn);
            assert_eq!(dials.load(Ordering::Relaxed), expected);
        }
    }

    #[test]
    fn a_tunnel_over_a_proxy_never_serves_a_direct_request() {
        let proxy = socks_proxy();
        let tunnel = tunnel_over(&proxy, &routed_with_hop_partition(&proxy, None));

        let direct = Extensions::new();
        direct.insert(ProxyRoute::Direct);
        assert!(!tunnel.matches(&direct));
        assert!(!tunnel.matches(&Extensions::new()));
    }
}
