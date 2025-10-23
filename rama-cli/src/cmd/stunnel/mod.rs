use clap::{Args, Subcommand};

use rama::{
    Layer,
    error::BoxError,
    graceful::Shutdown,
    net::{
        socket::Interface,
        tls::{
            DataEncoding,
            server::{ServerAuth, ServerAuthData, ServerConfig},
        },
    },
    tcp::{client::service::Forwarder, server::TcpListener},
    telemetry::tracing::{self, level_filters::LevelFilter},
    tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer},
    utils::str::NonEmptyString,
};

use std::{path::PathBuf, time::Duration};

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
    // Path to certificate
    #[arg(long)]
    pub cert: PathBuf,
    // Path to certificate private key
    #[arg(long)]
    pub key: PathBuf,
}

#[derive(Debug, Args)]
pub struct ClientArgs {
    // Address and port to listen on
    #[arg(long, default_value = "127.0.0.1:8003")]
    pub listen: Interface,
    // Address to forward connections to
    #[arg(long, default_value = "127.0.0.1:8002")]
    pub target: Interface,
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

            shutdown.spawn_task_fn(async move |guard| {
                tracing::info!("Stunnel server is running...");

                tracing::info!(
                    "Listening on {} and forwarding to {}",
                    args.listen,
                    args.forward
                );

                let tcp_service = TlsAcceptorLayer::new(acceptor_data)
                    // TODO: use args.forward here
                    .layer(Forwarder::new(([127, 0, 0, 1], 8080)));

                listener.serve_graceful(guard, tcp_service).await;
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
