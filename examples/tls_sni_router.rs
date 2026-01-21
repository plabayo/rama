//! This example demonstrates how to make a proxy acting like a SNI-based proxy router.
//!
//! Which can be useful in case you want to expose several TLS processes
//! over a single (network) interface.
//!
//! This example uses BoringSSL because it is our primary TLS backend,
//! but it would work just as well with Rustls or any other TLS implementation for that matter.
//! The SSL usage here is only for the webservers which isn't even the focus of this example.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example tls_sni_router --features=boring,http-full
//! ```
//!
//! # Expected output
//!
//! The foo.local server will start and listen on `:63804`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -k https://127.0.0.1:63804  # outputs foo
//! ```
//!
//! The bar.local server will start and listen on `:63805`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -k https://127.0.0.1:63805  # outputs bar
//! ```
//! The no SNI server will start and listen on `:63806`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -k https://127.0.0.1:63806  # outputs baz
//! ```
//!
//! Those services are available in a single interface (exposed by this example as `:62026`),
//! routed to the correct backend service based on its TLS SNI value or lack of:
//!
//! ```sh
//! curl -k --resolve foo.local:62026:127.0.0.1 https://foo.local:62026  # outputs foo
//! curl -k --resolve bar.local:62026:127.0.0.1 https://bar.local:62026  # outputs bar
//! curl -k https://127.0.0.1:62026  # outputs baz
//! ```

// rama provides everything out of the box to build a TLS termination proxy
use rama::{
    Layer, Service,
    error::OpaqueError,
    extensions::ExtensionsMut,
    graceful::{Shutdown, ShutdownGuard},
    http::{layer::trace::TraceLayer, server::HttpServer, service::web::Router},
    net::{
        address::{Domain, SocketAddress},
        tls::server::{SelfSignedData, ServerAuth, ServerConfig, SniRequest, SniRouter},
    },
    rt::Executor,
    stream::Stream,
    tcp::{client::service::Forwarder, server::TcpListener},
    telemetry::tracing::{
        self, Instrument as _,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer},
};

// everything else is provided by the standard library, community crates or tokio

use std::{sync::Arc, time::Duration};

#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let shutdown = Shutdown::default();

    spawn_https_server(shutdown.guard(), NAME_FOO, INTERFACE_FOO);
    spawn_https_server(shutdown.guard(), NAME_BAR, INTERFACE_BAR);
    spawn_https_server(shutdown.guard(), NAME_BAZ, INTERFACE_BAZ);

    shutdown.spawn_task_fn(async move |guard| {
        let interface = SocketAddress::default_ipv4(62026);
        tracing::info!(
            network.local.address = %interface.ip_addr,
            network.local.port = %interface.port,
            "[tcp] spawn sni router: bind and go",
        );
        TcpListener::bind(interface, Executor::graceful(guard.clone()))
            .await
            .expect("bind TCP Listener for SNI router")
            .serve(SniRouter::new(SniRouterSvc {
                exec: Executor::graceful(guard.clone()),
            }))
            .await;
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

const NAME_FOO: &str = "foo";
const HOST_FOO: Domain = Domain::from_static("foo.local");
const INTERFACE_FOO: SocketAddress = SocketAddress::local_ipv4(63804);

const NAME_BAR: &str = "bar";
const HOST_BAR: Domain = Domain::from_static("bar.local");
const INTERFACE_BAR: SocketAddress = SocketAddress::local_ipv4(63805);

const NAME_BAZ: &str = "baz";
const INTERFACE_BAZ: SocketAddress = SocketAddress::local_ipv4(63806);

#[derive(Debug, Clone)]
struct SniRouterSvc {
    exec: Executor,
}

impl<S> Service<SniRequest<S>> for SniRouterSvc
where
    S: Stream + ExtensionsMut + Unpin,
{
    type Output = ();
    type Error = OpaqueError;

    async fn serve(
        &self,
        SniRequest { stream, sni }: SniRequest<S>,
    ) -> Result<Self::Output, Self::Error> {
        // NOTE: for production settings you probably want to use a tri-like structure,
        // rama provided or bring your own
        let fwd_interface = match sni {
            None => INTERFACE_BAZ,
            Some(ref sni) => {
                if *sni == HOST_FOO {
                    INTERFACE_FOO
                } else if *sni == HOST_BAR {
                    INTERFACE_BAR
                } else {
                    tracing::debug!(
                        server.address = %sni,
                        "block connection for unknown destination",
                    );
                    return Err(OpaqueError::from_display("unknown destination"));
                }
            }
        };

        tracing::debug!(
            server.address = %sni.as_ref().map(|s| s.as_str()).unwrap_or_default(),
            network.local.address = %fwd_interface.ip_addr,
            network.local.port = %fwd_interface.port,
            "forward incoming connection",
        );

        Forwarder::new(self.exec.clone(), fwd_interface)
            .serve(stream)
            .await
            .map_err(OpaqueError::from_boxed)
    }
}

fn spawn_https_server(guard: ShutdownGuard, name: &'static str, interface: SocketAddress) {
    let tls_server_config = ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData {
        common_name: Some(format!("{name}.local").parse().expect("encode common name")),
        ..Default::default()
    }));
    let acceptor_data = TlsAcceptorData::try_from(tls_server_config).expect("create acceptor data");

    guard.into_spawn_task_fn(async move |guard| {
        tracing::info!(
            host.name = %name,
            network.local.address = %interface.ip_addr,
            network.local.port = %interface.port,
            "[tcp] spawn https server: bind and go",
        );
        TcpListener::bind(interface, Executor::graceful(guard.clone()))
            .await
            .expect("bind TCP Listener for web server")
            .serve(TlsAcceptorLayer::new(acceptor_data).into_layer(
                HttpServer::auto(Executor::graceful(guard)).service(Arc::new(
                    TraceLayer::new_for_http().into_layer(Router::new().with_get("/", name)),
                )),
            ))
            .instrument(tracing::debug_span!(
                "tcp::serve(https)",
                server.service.name = %name,
                otel.kind = "server",
            ))
            .await;
    });
}
