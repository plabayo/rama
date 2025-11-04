//! Stunnel for Rama
//!
//! # With auto-generated self-signed certificate (development & testing only)
//! 1. rama echo echo --bind 127.0.0.1:8001 --mode http
//! 2. rama stunnel server --listen 127.0.0.1:8002 --forward 127.0.0.1:8001
//! 3. rama stunnel client --listen 127.0.0.1:8003 --connect 127.0.0.1:8002 --insecure
//! # Test
//! 4. curl http://127.0.0.1:8003
//!
//! # Explicitily provided certificates
//! 1. rama echo echo --bind 127.0.0.1:8001 --mode http
//! 2. rama stunnel server --listen 0.0.0.0:8002 \
//!    --forward 127.0.0.1:8001 \
//!    --cert server-cert.pem \
//!    --key server-key.pem
//! 3. rama stunnel client --listen 127.0.0.1:8003 \
//!    --connect 127.0.0.1:8002 \
//!    --cacert cacert.pem
//! # Test
//! 4. curl -v http://127.0.0.1:8003

use rama::{
    Layer,
    error::BoxError,
    graceful::Shutdown,
    net::{
        address::{Authority, SocketAddress},
        socket::Interface,
        tls::{
            DataEncoding,
            client::ServerVerifyMode,
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

use clap::{Args, Subcommand};
use std::{path::PathBuf, sync::Arc, time::Duration};

use crate::utils::tls::new_server_config;

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
    #[arg(long, default_value = "127.0.0.1:8002")]
    /// address and port to listen on for incoming TLS connections
    pub listen: Interface,

    #[arg(long, default_value = "127.0.0.1:8001")]
    /// backend address to forward decrypted connections to
    pub forward: SocketAddress,

    #[arg(long, requires = "key")]
    /// path to TLS certificate file (PEM format)
    ///
    /// if not provided, a self-signed certificate will be auto-generated.
    /// can also be set via RAMA_TLS_CRT environment variable (base64-encoded).
    pub cert: Option<PathBuf>,

    #[arg(long, requires = "cert")]
    /// path to TLS private key file (PEM format)
    ///
    /// if not provided, a private key will be auto-generated.
    /// can also be set via RAMA_TLS_KEY environment variable (base64-encoded).
    pub key: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ClientArgs {
    #[arg(long, default_value = "127.0.0.1:8003")]
    /// address and port to listen on
    pub listen: Interface,

    #[arg(long, default_value = "127.0.0.1:8002", value_name = "HOST:PORT")]
    /// server to connect to (port is REQUIRED)
    ///
    /// examples:
    ///   localhost:8443
    ///   example.com:8443
    ///   192.168.1.100:8443
    ///
    /// port must be explicitly specified (e.g., :8443, :443)
    pub connect: Authority,

    #[arg(long, conflicts_with = "insecure")]
    /// path to CA certificate bundle for server verification (PEM format)
    ///
    /// use this to trust a specific CA or self-signed certificate.
    /// if not provided, the system trust store will be used.
    pub cacert: Option<PathBuf>,

    #[arg(short = 'k', long)]
    /// skip TLS certificate verification (INSECURE - testing only!)
    ///
    /// this disables all certificate validation and should NEVER be used
    /// in production. Use --cacert instead for self-signed certificates.
    pub insecure: bool,
}

pub async fn run(cmd: StunnelCommand) -> Result<(), BoxError> {
    crate::trace::init_tracing(LevelFilter::INFO);

    match cmd.commands {
        StunnelSubcommand::Server(args) => {
            let shutdown = Shutdown::default();

            let server_config = if let (Some(cert_path), Some(key_path)) = (&args.cert, &args.key) {
                tracing::info!(
                    cert.path = ?cert_path,
                    key.path = ?key_path,
                    "Loading TLS certificate from files"
                );

                let cert_data = NonEmptyString::try_from(std::fs::read_to_string(cert_path)?)
                    .map_err(|e| format!("Failed to read certificate file: {e}"))?;
                let key_data = NonEmptyString::try_from(std::fs::read_to_string(key_path)?)
                    .map_err(|e| format!("Failed to read key file: {e}"))?;

                ServerConfig::new(ServerAuth::Single(ServerAuthData {
                    cert_chain: DataEncoding::Pem(cert_data),
                    private_key: DataEncoding::Pem(key_data),
                    ocsp: None,
                }))
            } else {
                tracing::info!("Using auto-generated self-signed certificate");
                new_server_config(None)
            };

            let acceptor_data = TlsAcceptorData::try_from(server_config)?;

            let listener = TcpListener::bind(args.listen.clone())
                .await
                .expect("Failed to bind stunnel server");

            let listen_addr = args.listen.clone();
            let forward_addr = args.forward;

            shutdown.spawn_task_fn(async move |guard| {
                tracing::info!("Stunnel server is running...");
                tracing::info!(
                    "Listening on {} and forwarding to {}",
                    listen_addr,
                    forward_addr
                );
                let tcp_service =
                    TlsAcceptorLayer::new(acceptor_data).layer(Forwarder::new(forward_addr));
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

            let mut tls_builder = TlsConnectorDataBuilder::new();

            // Configure certificate verification
            if args.insecure {
                tls_builder = tls_builder.with_server_verify_mode(ServerVerifyMode::Disable);
                tracing::warn!("TLS certificate verification disabled (--insecure flag)");
                tracing::warn!("This is insecure and should only be used for testing!");
            } else if let Some(cacert_path) = &args.cacert {
                tracing::info!(
                    cacert.path = ?cacert_path,
                    "Loading CA certificate for server verification"
                );

                let ca_pem = std::fs::read_to_string(cacert_path)
                    .map_err(|e| format!("Failed to read CA certificate file: {e}"))?;

                let ca_cert = X509::from_pem(ca_pem.as_bytes())
                    .map_err(|e| format!("Failed to parse CA certificate: {e}"))?;

                let mut store_builder = X509StoreBuilder::new()
                    .map_err(|e| format!("Failed to create certificate store: {e}"))?;
                store_builder
                    .add_cert(ca_cert)
                    .map_err(|e| format!("Failed to add CA certificate to store: {e}"))?;

                tls_builder =
                    tls_builder.with_server_verify_cert_store(store_builder.build().into());
                tracing::info!("CA certificate loaded and added to trust store");
            } else {
                tracing::info!("Using system trust store for certificate verification");
            }

            let tls_client_data_builder = Arc::new(tls_builder);

            let listener = TcpListener::bind(args.listen.clone())
                .await
                .expect("Failed to bind stunnel client");

            let listen_addr = args.listen.clone();
            let connect_authority = args.connect;

            shutdown.spawn_task_fn(async move |guard| {
                tracing::info!("Stunnel client is running...");
                tracing::info!(
                    "Listening on {} and connecting to {}",
                    listen_addr,
                    connect_authority
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
