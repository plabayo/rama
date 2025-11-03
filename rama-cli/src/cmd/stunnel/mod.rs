//! ## Server Mode
//!
//! Accepts TLS connections and forwards plain TCP to a backend:
//!
//! ## Quick Test
//!
//! # 1. Generate a self-signed certificate
//! openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"
//!
//! # 2. Start backend
//! nc -l localhost 8080
//!
//! # 3. Start stunnel server
//! rama stunnel server --listen 127.0.0.1:8443 \
//! --forward 127.0.0.1:8080 \
//! --cert cert.pem \
//! --key key.pem
//!
//! You should see:
//! INFO tokio_graceful::shutdown: ::shutdown: waiting for signal to trigger (read: to be cancelled)!
//! INFO rama::cmd::stunnel: Stunnel server is running...
//! INFO rama::cmd::stunnel: Listening on 127.0.0.1:8443 and forwarding to 127.0.0.1:8080
//!
//! ## 4. Test the Connection
//! openssl s_client -connect 127.0.0.1:8443 -CAfile cert.pem
//!
//! ## Client Mode
//! TODO

use clap::{Args, Subcommand};

use rama::{
    Layer,
    error::BoxError,
    graceful::Shutdown,
    net::{
        address::{Authority, Host},
        socket::Interface,
        tls::{
            DataEncoding,
            server::{ServerAuth, ServerAuthData, ServerConfig},
        },
    },
    tcp::{
        client::service::{Forwarder, TcpConnector},
        server::TcpListener,
    },
    telemetry::tracing::{self, level_filters::LevelFilter},
    tls::boring::{
        client::{TlsConnectorDataBuilder, TlsConnectorLayer},
        core::x509::{X509, store::X509StoreBuilder},
        server::{TlsAcceptorData, TlsAcceptorLayer},
    },
    utils::str::NonEmptyString,
};

use std::{path::PathBuf, sync::Arc, time::Duration};

#[derive(Debug, Args)]
/// rama stunnel service
pub struct StunnelCommand {
    #[command(subcommand)]
    pub commands: StunnelSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum StunnelSubcommand {
    Server(ServerArgs),
    Client(ClientArgs),
}

#[derive(Debug, Args)]
pub struct ServerArgs {
    // Address and port to listen on
    #[arg(long, default_value = "127.0.0.1:8443")]
    pub listen: Interface,
    // Address to forward connections to
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub forward: Interface,
    // Path to certificate private key
    #[arg(long)]
    pub key: PathBuf,
    // Path to certificate
    #[arg(long)]
    pub cert: PathBuf,
}

#[derive(Debug, Args)]
pub struct ClientArgs {
    // Address and port to listen on
    #[arg(long, default_value = "127.0.0.1:8003")]
    pub listen: Interface,
    // Address to connect to
    #[arg(long, default_value = "127.0.0.1:8002")]
    pub connect: Interface,
    #[arg(long)]
    // Path to CA bundle file (PEM/X509). Uses system trust store by default.
    pub cacert: Option<PathBuf>,
}

pub async fn run(cmd: StunnelCommand) -> Result<(), BoxError> {
    crate::trace::init_tracing(LevelFilter::INFO);

    match cmd.commands {
        StunnelSubcommand::Server(args) => {
            let shutdown = Shutdown::default();

            let cert_data = NonEmptyString::try_from(std::fs::read_to_string(&args.cert)?)?;
            let key_data = NonEmptyString::try_from(std::fs::read_to_string(&args.key)?)?;

            let server_config = ServerConfig::new(ServerAuth::Single(ServerAuthData {
                cert_chain: DataEncoding::Pem(cert_data),
                private_key: DataEncoding::Pem(key_data),
                ocsp: None,
            }));

            let acceptor_data = TlsAcceptorData::try_from(server_config)?;

            let listener = TcpListener::bind(args.listen.clone())
                .await
                .expect("Failed to bind stunnel server");

            let forward_authority = match &args.forward {
                Interface::Address(socket_addr) => {
                    Authority::new(Host::Address(socket_addr.ip_addr()), socket_addr.port())
                }
                Interface::Socket(_) => {
                    return Err("Socket options not supported for forwarding".into());
                }
            };

            let listen_addr = args.listen.clone();
            let forward_addr = args.forward.clone();

            shutdown.spawn_task_fn(async move |guard| {
                tracing::info!("Stunnel server is running...");
                tracing::info!(
                    "Listening on {} and forwarding to {}",
                    listen_addr,
                    forward_addr
                );
                let tcp_service =
                    TlsAcceptorLayer::new(acceptor_data).layer(Forwarder::new(forward_authority));
                listener.serve_graceful(guard, tcp_service).await;
            });

            shutdown
                .shutdown_with_limit(Duration::from_secs(30))
                .await
                .expect("graceful shutdown");

            Ok(())
        }

        StunnelSubcommand::Client(args) => {
            let shutdown = Shutdown::default();

            let connect_authority = match &args.connect {
                Interface::Address(socket_addr) => {
                    Authority::new(Host::Address(socket_addr.ip_addr()), socket_addr.port())
                }
                Interface::Socket(_) => {
                    return Err("Socket options not supported for connect target".into());
                }
            };

            let mut tls_builder = TlsConnectorDataBuilder::new();

            if let Host::Name(domain) = connect_authority.host() {
                tls_builder = tls_builder.with_server_name(domain.clone());
            }

            if let Some(cacert_path) = &args.cacert {
                let ca_pem = std::fs::read_to_string(cacert_path)?;
                let ca_cert = X509::from_pem(ca_pem.as_bytes())
                    .map_err(|e| format!("Failed to parse CA certificate: {e}"))?;

                let mut store_builder = X509StoreBuilder::new()
                    .map_err(|e| format!("Failed to create X509 store builder: {e}"))?;
                store_builder
                    .add_cert(ca_cert)
                    .map_err(|e| format!("Failed to add CA certificate to store: {e}"))?;

                tls_builder = tls_builder.with_server_verify_cert_store(store_builder.build());
            }

            let tls_client_data_builder = Arc::new(tls_builder);

            let listener = TcpListener::bind(args.listen.clone())
                .await
                .expect("Failed to bind stunnel client");

            let listen_addr = args.listen.clone();
            let connect_addr = args.connect.clone();

            shutdown.spawn_task_fn(async move |guard| {
                tracing::info!("Stunnel client is running...");
                tracing::info!(
                    "Listening on {} and connecting to {}",
                    listen_addr,
                    connect_addr
                );

                let tcp_service = Forwarder::new(connect_authority).connector(
                    TlsConnectorLayer::secure()
                        .with_connector_data(tls_client_data_builder)
                        .into_layer(TcpConnector::new()),
                );

                listener.serve_graceful(guard, tcp_service).await;
            });

            shutdown
                .shutdown_with_limit(Duration::from_secs(30))
                .await
                .expect("graceful shutdown");

            Ok(())
        }
    }
}
