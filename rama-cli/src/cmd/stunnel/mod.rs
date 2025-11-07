//! Stunnel for Rama
//!
//! # With auto-generated self-signed certificate (development & testing only)
//! 1. rama echo echo
//! 2. rama stunnel server --listen 127.0.0.1:8002 --forward 127.0.0.1:8080
//! 3. rama stunnel client --listen 127.0.0.1:8003 --connect (127.0.0.1 | localhost):8002 --insecure
//! # Test
//! 4. rama http 127.0.0.1:8003
//!
//! # Explicitily provided certificates
//! 1. rama echo
//! 2. rama stunnel server --listen 127.0.0.1:8002 \
//!    --forward 127.0.0.1:8080 \
//!    --cert server-cert.pem \
//!    --key server-key.pem
//! 3. rama stunnel client --listen 127.0.0.1:8003 \
//!    --connect (127.0.0.1 | localhost):8002 \
//!    --cacert cacert.pem
//! # Test
//! 4. rama http 127.0.0.1:8003

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
    // --server (server mode), --client (client mode)
    pub commands: StunnelSubcommand,

    #[arg(long, default_value_t = 5)]
    /// the graceful shutdown timeout in seconds (0 = no timeout)
    graceful: u64,
}

#[derive(Debug, Subcommand)]
pub enum StunnelSubcommand {
    /// run as TLS termination proxy (decrypt incoming TLS and forward plaintext)
    Server(ServerArgs),

    /// run as TLS origination proxy (encrypt outgoing connections)
    Client(ClientArgs),
}

#[derive(Debug, Args)]
pub struct ServerArgs {
    #[arg(long, default_value = "127.0.0.1:8002")]
    /// address and port to listen on for incoming TLS connections
    pub listen: Interface,

    #[arg(long, default_value = "127.0.0.1:8080")]
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
    /// this disables all certificate validation and should NEVER be use in production.
    /// use --cacert instead for self-signed certificates
    /// or ensure that your system keychain has the cert or one of its root certs as a trusted cert.
    pub insecure: bool,
}

pub async fn run(cfg: StunnelCommand) -> Result<(), BoxError> {
    crate::trace::init_tracing(LevelFilter::INFO);

    let graceful_timeout = parse_graceful_timeout(cfg.graceful);

    match cfg.commands {
        StunnelSubcommand::Server(args) => run_server(args, graceful_timeout).await,
        StunnelSubcommand::Client(args) => run_client(args, graceful_timeout).await,
    }
}

async fn run_server(args: ServerArgs, graceful_timeout: Option<Duration>) -> Result<(), BoxError> {
    let graceful = Shutdown::default();
    let server_config = load_server_config(args.cert.as_ref(), args.key.as_ref())?;
    let acceptor_data = TlsAcceptorData::try_from(server_config)?;

    let tcp_listener = TcpListener::bind(args.listen.clone())
        .await
        .expect("bind stunnel server");

    let listen_addr = args.listen;
    let forward_addr = args.forward;

    graceful.spawn_task_fn(async move |guard| {
        tracing::info!("Stunnel server is running...");
        tracing::info!(
            "Listening on {} and forwarding to {}",
            listen_addr,
            forward_addr
        );

        let tcp_service =
            TlsAcceptorLayer::new(acceptor_data).into_layer(Forwarder::new(forward_addr));
        tcp_listener.serve_graceful(guard, tcp_service).await;
    });

    shutdown_gracefully(graceful, graceful_timeout, "server").await
}

async fn run_client(args: ClientArgs, graceful_timeout: Option<Duration>) -> Result<(), BoxError> {
    let graceful = Shutdown::default();
    let tls_connector_data = build_tls_connector(&args)?;

    let tcp_listener = TcpListener::bind(args.listen.clone())
        .await
        .expect("bind stunnel client");

    let listen_addr = args.listen;
    let connect_authority = args.connect;

    graceful.spawn_task_fn(async move |guard| {
        tracing::info!("Stunnel client is running...");
        tracing::info!(
            "Listening on {} and connecting to {}",
            listen_addr,
            connect_authority
        );

        let tcp_service = Forwarder::new(connect_authority).connector(
            TlsConnectorLayer::secure()
                .with_connector_data(tls_connector_data)
                .into_layer(TcpConnector::new()),
        );

        tcp_listener.serve_graceful(guard, tcp_service).await;
    });

    shutdown_gracefully(graceful, graceful_timeout, "client").await
}

fn build_tls_connector(args: &ClientArgs) -> Result<Arc<TlsConnectorDataBuilder>, BoxError> {
    let mut tls_builder = TlsConnectorDataBuilder::new();

    if args.insecure {
        tls_builder.set_server_verify_mode(ServerVerifyMode::Disable);
        tracing::warn!("TLS certificate verification disabled (--insecure flag)");
        tracing::warn!("This is insecure and should only be used for testing!");
    } else if let Some(cacert_path) = &args.cacert {
        load_ca_certificate(&mut tls_builder, cacert_path)?;
    } else {
        tracing::info!("Using system trust store for certificate verification");
    }

    Ok(Arc::new(tls_builder))
}

fn load_ca_certificate(
    tls_builder: &mut TlsConnectorDataBuilder,
    cacert_path: &PathBuf,
) -> Result<(), BoxError> {
    tracing::info!(
        cacert.path = ?cacert_path,
        "Loading CA certificate for server verification"
    );

    let ca_pem = std::fs::read_to_string(cacert_path)
        .map_err(|e| format!("Failed to read CA certificate file: {e}"))?;

    let ca_cert = X509::from_pem(ca_pem.as_bytes())
        .map_err(|e| format!("Failed to parse CA certificate: {e}"))?;

    let mut store_builder =
        X509StoreBuilder::new().map_err(|e| format!("Failed to create certificate store: {e}"))?;

    store_builder
        .add_cert(ca_cert)
        .map_err(|e| format!("Failed to add CA certificate to store: {e}"))?;

    tls_builder.set_server_verify_cert_store(store_builder.build().into());
    tracing::info!("CA certificate loaded and added to trust store");

    Ok(())
}

fn load_server_config(
    cert_path: Option<&PathBuf>,
    key_path: Option<&PathBuf>,
) -> Result<ServerConfig, BoxError> {
    match (cert_path, key_path) {
        (Some(cert), Some(key)) => {
            tracing::info!(
                cert.path = ?cert,
                key.path = ?key,
                "Loading TLS certificate from files"
            );

            let cert_data = read_pem_file(cert, "certificate")?;
            let key_data = read_pem_file(key, "key")?;

            Ok(ServerConfig::new(ServerAuth::Single(ServerAuthData {
                cert_chain: DataEncoding::Pem(cert_data),
                private_key: DataEncoding::Pem(key_data),
                ocsp: None,
            })))
        }
        (None, None) => Ok(new_server_config(None)),
        _ => Err("Both certificate and key must be provided together, or neither".into()),
    }
}

fn read_pem_file(path: &PathBuf, file_type: &str) -> Result<NonEmptyString, BoxError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {file_type} file: {e}"))?;

    NonEmptyString::try_from(content)
        .map_err(|e| format!("Failed to parse {file_type} file: {e}").into())
}

fn parse_graceful_timeout(seconds: u64) -> Option<Duration> {
    (seconds > 0).then(|| Duration::from_secs(seconds))
}

async fn shutdown_gracefully(
    graceful: Shutdown,
    timeout: Option<Duration>,
    service_type: &str,
) -> Result<(), BoxError> {
    let delay = match timeout {
        Some(duration) => graceful.shutdown_with_limit(duration).await?,
        None => graceful.shutdown().await,
    };

    tracing::info!("stunnel {service_type} gracefully shutdown with a delay of: {delay:?}");
    Ok(())
}
