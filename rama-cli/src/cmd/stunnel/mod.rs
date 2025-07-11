use std::{io::BufReader, path::PathBuf, time::Duration};

use clap::{Args, Subcommand};
use rama::{
    Layer,
    error::{BoxError, ErrorContext, OpaqueError},
    graceful::Shutdown,
    service::service_fn,
    tcp::{TcpStream, server::TcpListener},
    telemetry::tracing,
    tls::rustls::{
        dep::{
            pemfile,
            pki_types::{CertificateDer, PrivateKeyDer},
        },
        server::{TlsAcceptorDataBuilder, TlsAcceptorLayer},
    },
};
use tokio::io::copy_bidirectional;
use tracing_subscriber::{
    EnvFilter, filter::LevelFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt,
};

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
    #[arg(long)]
    pub listen: String,
    #[arg(long)]
    pub forward: String,
    #[arg(long)]
    pub cert: PathBuf,
    #[arg(long)]
    pub key: PathBuf,
}

#[derive(Debug, Args)]
pub struct ClientArgs {
    #[arg(long)]
    pub listen: String,
    #[arg(long)]
    pub connect: String,
    #[arg(long)]
    pub cacert: PathBuf,
}

pub async fn run(cmd: StunnelCommand) -> Result<(), BoxError> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    match cmd.commands {
        StunnelSubcommand::Server(args) => {
            let shutdown = Shutdown::default();

            let (certs, key) = load_cert_and_key(
                &std::fs::read(&args.cert).context("failed to read certificate")?,
                &std::fs::read(&args.key).context("failed to read private key")?,
            )?;

            let acceptor_data = TlsAcceptorDataBuilder::new(certs, key)?
                .with_env_key_logger()
                .expect("with env keylogger")
                .build();

            shutdown.spawn_task_fn(async move |guard| {
                tracing::info!("Stunnel server is running...");

                tracing::info!(
                    "Listening on {} and forwarding to {}",
                    args.listen,
                    args.forward
                );

                let tcp_service = TlsAcceptorLayer::new(acceptor_data).layer(service_fn(
                    move |mut tls_stream| {
                        let forward = args.forward.clone();

                        async move {
                            let mut backend = TcpStream::connect(forward)
                                .await
                                .context("failed to connect to backend")?;

                            copy_bidirectional(&mut tls_stream, &mut backend)
                                .await
                                .context("failed to relay data")?;

                            Ok::<_, BoxError>(())
                        }
                    },
                ));

                TcpListener::bind(&args.listen)
                    .await
                    .expect("Failed to bind stunnel server")
                    .serve_graceful(guard, tcp_service)
                    .await;
            });

            shutdown
                .shutdown_with_limit(Duration::from_secs(30))
                .await
                .expect("graceful shutdown");

            Ok(())
        }

        StunnelSubcommand::Client(args) => {
            todo!()
        }
    }
}

pub fn load_cert_and_key(
    cert_bytes: &[u8],
    key_bytes: &[u8],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), OpaqueError> {
    let cert_chain = pemfile::certs(&mut BufReader::new(cert_bytes))
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse certificate chain")?;

    let private_key = pemfile::private_key(&mut BufReader::new(key_bytes))
        .context("failed to parse private key")?
        .context("no private key found")?;

    Ok((cert_chain, private_key))
}
