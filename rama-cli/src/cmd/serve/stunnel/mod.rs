//! # Stunnel for Rama
//!
//! ## With auto-generated self-signed certificate (development & testing only)
//!
//! 1. rama serve echo
//! 2. rama serve stunnel exit --bind 127.0.0.1:8002 --forward 127.0.0.1:8080
//! 3. rama serve stunnel entry --bind 127.0.0.1:8003 --connect 127.0.0.1:8002 --insecure
//!
//! Test:
//!
//! 4. rama :8003
//!
//! ## Explicitily provided certificates
//!
//! 1. rama serve echo
//! 2. rama serve stunnel exit --bind 127.0.0.1:8002 \
//!    --forward 127.0.0.1:8080 \
//!    --cert server-cert.pem \
//!    --key server-key.pem
//! 3. rama serve stunnel entry --bind 127.0.0.1:8003 \
//!    --connect 127.0.0.1:8002 \
//!    --cacert cacert.pem
//!
//! Test:
//!
//! 4. rama :8003

use rama::{
    Layer,
    error::{BoxError, ErrorContext as _},
    graceful::ShutdownGuard,
    net::{
        address::{HostWithPort, SocketAddress},
        socket::Interface,
        tls::{
            DataEncoding,
            client::ServerVerifyMode,
            server::{ServerAuth, ServerAuthData, ServerConfig},
        },
    },
    rt::Executor,
    tcp::{
        client::service::{Forwarder, TcpConnector},
        server::TcpListener,
    },
    telemetry::tracing,
    tls::boring::{
        client::{TlsConnectorDataBuilder, TlsConnectorLayer},
        core::x509::{X509, store::X509StoreBuilder},
        server::{TlsAcceptorData, TlsAcceptorLayer},
    },
    utils::str::NonEmptyStr,
};

use clap::{Args, Subcommand};
use std::{path::PathBuf, sync::Arc};

use crate::utils::tls::try_new_server_config;

#[derive(Debug, Args)]
/// rama stunnel service
pub struct StunnelCommand {
    #[command(subcommand)]
    pub commands: StunnelSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum StunnelSubcommand {
    /// run as TLS exit node (decrypt incoming TLS and forward plaintext)
    Exit(ExitNodeArgs),

    /// run as TLS entry node (encrypt outgoing connections)
    Entry(EntryNodeArgs),
}

#[derive(Debug, Args)]
pub struct ExitNodeArgs {
    #[arg(long, default_value = "127.0.0.1:8002")]
    /// address and port to listen on for incoming TLS connections
    pub bind: Interface,

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
pub struct EntryNodeArgs {
    #[arg(long, default_value = "127.0.0.1:8003")]
    /// address and port to listen on
    pub bind: Interface,

    #[arg(long, default_value = "127.0.0.1:8002", value_name = "HOST:PORT")]
    /// server to connect to
    ///
    /// examples:
    ///   localhost:8443
    ///   example.com:8443
    ///   192.168.1.100:8443
    pub connect: HostWithPort,

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

pub async fn run(guard: ShutdownGuard, cfg: StunnelCommand) -> Result<(), BoxError> {
    match cfg.commands {
        StunnelSubcommand::Exit(cfg) => run_exit_node(guard, cfg).await,
        StunnelSubcommand::Entry(cfg) => run_entry_node(guard, cfg).await,
    }
}

async fn run_exit_node(graceful: ShutdownGuard, cfg: ExitNodeArgs) -> Result<(), BoxError> {
    let server_config = load_server_config(
        cfg.cert.as_ref(),
        cfg.key.as_ref(),
        Executor::graceful(graceful.clone()),
    )?;
    let acceptor_data = TlsAcceptorData::try_from(server_config)?;

    let exec = Executor::graceful(graceful);

    let tcp_listener = TcpListener::bind(cfg.bind.clone(), exec.clone())
        .await
        .context("bind stunnel exit node")?;

    let bind_address = tcp_listener
        .local_addr()
        .context("get local addr of tcp listener")?;
    let forward_addr = cfg.forward;

    exec.clone().into_spawn_task(async move {
        tracing::info!("Stunnel exit node is running...");
        tracing::info!(
            "Listening on {} and forwarding to {}",
            bind_address,
            forward_addr
        );

        let tcp_service =
            TlsAcceptorLayer::new(acceptor_data).into_layer(Forwarder::new(exec, forward_addr));
        tcp_listener.serve(tcp_service).await;
    });

    Ok(())
}

async fn run_entry_node(graceful: ShutdownGuard, cfg: EntryNodeArgs) -> Result<(), BoxError> {
    let tls_connector_data = build_tls_connector(&cfg)?;

    let exec = Executor::graceful(graceful);
    let tcp_listener = TcpListener::bind(cfg.bind.clone(), exec.clone())
        .await
        .context("bind stunnel entry node")?;

    let bind_address = tcp_listener
        .local_addr()
        .context("get local addr of tcp listener")?;
    let connect_authority = cfg.connect;

    exec.clone().into_spawn_task(async move {
        tracing::info!("Stunnel entry node is running...");
        tracing::info!(
            "Listening on {} and connecting to {}",
            bind_address,
            connect_authority
        );

        let tcp_service = Forwarder::new(exec.clone(), connect_authority).with_connector(
            TlsConnectorLayer::secure()
                .with_connector_data(tls_connector_data)
                .into_layer(TcpConnector::new(exec)),
        );

        tcp_listener.serve(tcp_service).await;
    });

    Ok(())
}

fn build_tls_connector(cfg: &EntryNodeArgs) -> Result<Arc<TlsConnectorDataBuilder>, BoxError> {
    let mut tls_builder = TlsConnectorDataBuilder::new();

    if cfg.insecure {
        tls_builder.set_server_verify_mode(ServerVerifyMode::Disable);
        tracing::warn!("TLS certificate verification disabled (--insecure flag)");
        tracing::warn!("This is insecure and should only be used for testing!");
    } else if let Some(cacert_path) = &cfg.cacert {
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
    exec: Executor,
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
        (None, None) => Ok(try_new_server_config(None, exec)?),
        _ => Err("Both certificate and key must be provided together, or neither".into()),
    }
}

fn read_pem_file(path: &PathBuf, file_type: &str) -> Result<NonEmptyStr, BoxError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {file_type} file: {e}"))?;

    NonEmptyStr::try_from(content)
        .map_err(|e| format!("Failed to parse {file_type} file: {e}").into())
}
