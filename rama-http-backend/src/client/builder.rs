use std::{fmt, marker::PhantomData};

use rama_core::{
    Context, Service,
    error::{BoxError, ErrorContext, OpaqueError},
    inspect::RequestInspector,
};
use rama_http_types::{Request, Response, Version, dep::http_body};
use rama_net::client::{
    EitherConn, EstablishedClientConnection,
    pool::{
        NoPool, Pool, PooledConnector,
        http::{BasicHttpConId, BasicHttpConnIdentifier},
    },
};
use rama_tcp::client::service::TcpConnector;

#[cfg(feature = "boring")]
use rama_net::tls::client::{ClientConfig, ProxyClientConfig, extract_client_config_from_ctx};

#[cfg(feature = "boring")]
use rama_tls_boring::client::{
    TlsConnector as BoringTlsConnector, TlsConnectorData as BoringTlsConnectorData,
    TunnelTlsConnector,
};

#[cfg(feature = "rustls")]
use rama_tls_rustls::client::{
    TlsConnector as RustlsTlsConnector, TlsConnectorData as RustlsTlsConnectorData,
};

use super::{HttpConnector, proxy::layer::HttpProxyConnector};

// #[cfg(any(feature = "rustls", feature = "boring"))]
// use http_inspector::HttpsAlpnModifier;

// #[cfg(any(feature = "rustls", feature = "boring"))]
// use rama_net::client::EitherConn;

pub struct ConnectorBuilder<C, S> {
    connector: C,
    _phantom: PhantomData<S>,
}

struct Transport;
struct Proxy;
struct Tls;
struct Http;

impl ConnectorBuilder<(), ()> {
    pub fn new() -> ConnectorBuilder<TcpConnector, Transport> {
        ConnectorBuilder {
            connector: TcpConnector::new(),
            _phantom: PhantomData,
        }
    }
}

impl<T, S> ConnectorBuilder<T, S> {
    pub fn build(self) -> T {
        self.connector
    }
}

impl<T> ConnectorBuilder<T, Transport> {
    pub fn with_proxy_and_boring_tls(
        self,
        config: ClientConfig,
    ) -> ConnectorBuilder<HttpProxyConnector<TunnelTlsConnector<T>>, Proxy> {
        let connector = BoringTlsConnector::tunnel(self.connector, None)
            .with_connector_data(config.try_into().unwrap());
        let connector = HttpProxyConnector::optional(connector);
        ConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    pub fn with_proxy_and_no_tls(self) -> ConnectorBuilder<HttpProxyConnector<T>, Proxy> {
        let connector = HttpProxyConnector::optional(self.connector);
        ConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    pub fn without_proxy(self) -> ConnectorBuilder<HttpProxyConnector<T>, Proxy> {
        let connector = HttpProxyConnector::optional(self.connector);
        ConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }
}

impl<T> ConnectorBuilder<T, Proxy> {
    pub fn with_boring_tls(
        self,
        config: ClientConfig,
    ) -> ConnectorBuilder<BoringTlsConnector<T>, Tls> {
        let connector = BoringTlsConnector::auto(self.connector)
            .with_connector_data(config.try_into().unwrap());
        ConnectorBuilder {
            connector,
            _phantom: PhantomData,
        }
    }

    pub fn without_tls(self) -> ConnectorBuilder<T, Tls> {
        ConnectorBuilder {
            connector: self.connector,
            _phantom: PhantomData,
        }
    }
}

impl<T> ConnectorBuilder<T, Tls> {
    pub fn with_http(self) -> ConnectorBuilder<HttpConnector<T>, Http> {
        ConnectorBuilder {
            connector: HttpConnector::new(self.connector),
            _phantom: PhantomData,
        }
    }
}

impl<T, I1, I2> ConnectorBuilder<HttpConnector<T, I1, I2>, Http> {
    pub fn with_jit_req_inspector<I>(
        self,
        http_req_inspector: I,
    ) -> ConnectorBuilder<HttpConnector<T, I, I2>, Http> {
        ConnectorBuilder {
            connector: self.connector.with_jit_req_inspector(http_req_inspector),
            _phantom: PhantomData,
        }
    }

    pub fn with_svc_req_inspector<I>(
        self,
        http_req_inspector: I,
    ) -> ConnectorBuilder<HttpConnector<T, I1, I>, Http> {
        ConnectorBuilder {
            connector: self.connector.with_svc_req_inspector(http_req_inspector),
            _phantom: PhantomData,
        }
    }
}

fn test() {
    let x = ConnectorBuilder::new()
        .with_proxy_and_boring_tls(config)
        .with_boring_tls(config)
        .with_http()
        .with_jit_req_inspector(config)
        .build();
}
