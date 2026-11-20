//! This example demonstrates an HTTP client that selects its upstream proxy
//! from a [`MemoryProxyDB`] and stops selecting a proxy once a connection through it fails.
//!
//! Two local SOCKS5 proxies are listed in the database, of which one is broken:
//! nothing listens on its address. The [`ProxyDBLayer`] publishes the matching proxies
//! as candidate routes for each request. When a connection attempt through a proxy fails,
//! the [`ProxyID`] of that attempt is inserted in an exclude column of the database
//! and the client falls back to the next candidate. From then on the broken proxy
//! is no longer selected, until it is removed from the column again.
//!
//! ```sh
//! cargo run -p rama-examples --bin http_proxy_db_exclude_broken --features=http-full,proxy-full
//! ```
//!
//! # Expected output
//!
//! Every request succeeds. You should see a warning once, for the request of which
//! the broken proxy was tried first, after which only the healthy proxy is selected.

#![expect(
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use rama::{
    Service,
    extensions::ExtensionsRef,
    graceful::WeakScope,
    http::{
        BodyExtractExt,
        client::EasyHttpWebClient,
        server::HttpServer,
        service::{client::HttpClientExt, web::WebService},
    },
    layer::Layer,
    net::{address::ProxyProtocol, transport::TransportProtocol},
    proxy::{
        MemoryProxyDB, Proxy, ProxyContext, ProxyDB, ProxyDBLayer, ProxyFilter, ProxyFilterMode,
        ProxyID, ProxyProtocols, ProxyRuntimeColumn, ProxyType, socks5::Socks5Acceptor,
    },
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    utils::str::{NonEmptyStr, non_empty_str},
};

use std::sync::Arc;

const TARGET_ADDRESS: &str = "127.0.0.1:12090";
const HEALTHY_PROXY_ADDRESS: &str = "127.0.0.1:12091";
// nothing listens here, so every connection through this proxy fails
const BROKEN_PROXY_ADDRESS: &str = "127.0.0.1:12092";

#[tokio::main]
async fn main() {
    setup_tracing();
    spawn_target_server().await;
    spawn_healthy_proxy().await;

    let mut db = MemoryProxyDB::try_from_iter([
        socks5_proxy(non_empty_str!("healthy"), HEALTHY_PROXY_ADDRESS),
        socks5_proxy(non_empty_str!("broken"), BROKEN_PROXY_ADDRESS),
    ])
    .expect("create proxy db");
    let excluded = db.new_exclude_column();
    let db = Arc::new(db);

    let client = EasyHttpWebClient::connector_builder(WeakScope::detached())
        .with_default_tcp_connector()
        .with_default_dns_connector()
        .with_default_proxy_support()
        .map_connector(|inner| ExcludeOnFailure {
            inner,
            excluded: excluded.clone(),
        })
        .without_tls_support()
        .with_default_http_connector()
        .without_connection_pool()
        .build_client();
    let client = ProxyDBLayer::new(db.clone())
        .with_filter_mode(ProxyFilterMode::Default)
        .into_layer(client);

    // the order of the candidates is random: keep going until the broken one was tried
    for _ in 0..64 {
        if excluded.contains("broken") {
            break;
        }
        let body = client
            .get(format!("http://{TARGET_ADDRESS}/"))
            .send()
            .await
            .expect("request falls back to the healthy proxy")
            .try_into_string()
            .await
            .expect("read response body");
        tracing::info!("response: {body}");
    }
    assert!(excluded.contains("broken"));

    let selectable = db
        .get_proxies(
            ProxyContext {
                protocol: TransportProtocol::Tcp,
            },
            ProxyFilter::default(),
            None,
        )
        .await
        .expect("healthy proxy is still selectable");
    assert_eq!(selectable.len(), 1);
    assert_eq!(selectable.head.id, "healthy");
    tracing::info!("only the healthy proxy is selected from now on");
}

/// Puts the proxy of a failed connection attempt in the exclude column.
#[derive(Debug, Clone)]
struct ExcludeOnFailure<S> {
    inner: S,
    excluded: ProxyRuntimeColumn,
}

impl<S, Input> Service<Input> for ExcludeOnFailure<S>
where
    S: Service<Input>,
    Input: ExtensionsRef + Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let id = input.extensions().get_ref::<ProxyID>().cloned();
        let result = self.inner.serve(input).await;
        if result.is_err()
            && let Some(id) = id
            && self.excluded.insert(id.as_str()) == Some(true)
        {
            tracing::warn!(proxy.id = %id, "connection through proxy failed: no longer selected");
        }
        result
    }
}

fn socks5_proxy(id: NonEmptyStr, address: &str) -> Proxy {
    Proxy {
        id,
        address: address.parse().expect("valid proxy address"),
        credential: None,
        protocols: ProxyProtocols::from([
            ProxyProtocol::try_from_scheme("socks5+tcp").expect("valid proxy scheme")
        ]),
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

async fn spawn_target_server() {
    let listener = TcpListener::bind_address(TARGET_ADDRESS, WeakScope::detached())
        .await
        .expect("bind target server");
    let server = HttpServer::default()
        .service(WebService::default().with_get("/", "Hello through a healthy proxy"));
    tokio::spawn(listener.serve(server));
}

async fn spawn_healthy_proxy() {
    let listener = TcpListener::bind_address(HEALTHY_PROXY_ADDRESS, WeakScope::detached())
        .await
        .expect("bind healthy proxy");
    tokio::spawn(listener.serve(Socks5Acceptor::default()));
}

fn setup_tracing() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
}
