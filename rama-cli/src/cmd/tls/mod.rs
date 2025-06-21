#![allow(clippy::print_stdout)]

use clap::Args;
use rama::{
    Context, Layer, Service,
    error::{BoxError, ErrorContext},
    net::{
        address::Authority,
        client::{ConnectorService, EstablishedClientConnection},
        tls::{
            DataEncoding,
            client::{NegotiatedTlsParameters, ServerVerifyMode},
        },
    },
    tcp::client::{Request, service::TcpConnector},
    telemetry::tracing::{self, level_filters::LevelFilter},
    tls::boring::{
        client::{TlsConnectorDataBuilder, TlsConnectorLayer},
        core::x509::X509,
    },
};
use tokio::net::TcpStream;

#[derive(Args, Debug, Clone)]
/// rama tls support
pub struct CliCommandTls {
    /// The address to connect to
    /// e.g. "example.com" or "example.com:8443"
    /// if no port is provided, the default port 443 will be used
    address: String,

    #[arg(long, short = 'k')]
    /// Wether to skip certificate verification
    insecure: bool,
}

/// Run the tls command
pub async fn run(cfg: CliCommandTls) -> Result<(), BoxError> {
    crate::trace::init_tracing(LevelFilter::INFO);

    let address = cfg.address.trim();
    let authority = if cfg.address.contains(':') {
        address
            .parse()
            .context("parse config address as authority")?
    } else {
        let host = address.parse().context("parse config address as host")?;
        Authority::new(host, 443)
    };

    tracing::info!(
        server.address = %authority.host(),
        server.port = %authority.port(),
        "connecting to server",
    );

    let tls_conn_data = TlsConnectorDataBuilder::new()
        .maybe_with_server_verify_mode(cfg.insecure.then_some(ServerVerifyMode::Disable))
        .with_store_server_certificate_chain(true)
        .into_shared_builder();

    let tcp_connector = TcpConnector::new();
    let loggin_service = LoggingLayer.layer(tcp_connector);

    let tls_connector = TlsConnectorLayer::secure()
        .with_connector_data(tls_conn_data)
        .layer(loggin_service);

    let EstablishedClientConnection { ctx, .. } = tls_connector
        .connect(Context::default(), Request::new(authority))
        .await?;

    let params = ctx
        .get::<NegotiatedTlsParameters>()
        .expect("NegotiatedTlsParameters to be available in connector context");

    if let Some(cert_chain) = params.peer_certificate_chain.clone() {
        match cert_chain {
            DataEncoding::Der(raw_data) => log_cert(&raw_data, 1),
            DataEncoding::DerStack(raw_data_list) => {
                for (i, raw_data) in raw_data_list.iter().enumerate() {
                    log_cert(raw_data, i + 1);
                }
            }
            DataEncoding::Pem(raw_data) => {
                println!("PEM certificate: {:?}", raw_data);
            }
        }
    }

    Ok(())
}

fn log_cert(raw_data: &[u8], index: usize) {
    match X509::from_der(raw_data) {
        Ok(cert) => {
            println!("Certificate #{}:", index);
            println!("Subject: {:?}", cert.subject_name());
            println!("Issuer: {:?}", cert.issuer_name());
        }
        Err(err) => {
            eprintln!("Failed to decode certificate #{}: {:?}", index, err);
        }
    }
}

struct LoggingService<S> {
    inner: S,
}

impl<S, State, Req> Service<State, Req> for LoggingService<S>
where
    S: Service<State, Req, Response = EstablishedClientConnection<TcpStream, State, Req>>,
    S::Error: Send + 'static,
    State: Send + Sync + 'static,
    Req: Send + 'static,
{
    type Response = EstablishedClientConnection<TcpStream, State, Req>;
    type Error = S::Error;

    async fn serve(&self, ctx: Context<State>, req: Req) -> Result<Self::Response, Self::Error> {
        let result = self.inner.serve(ctx, req).await;

        if let Ok(ref established_conn) = result {
            if let Ok(Some(peer_addr)) = established_conn.conn.peer_addr().map(Some) {
                tracing::info!(
                    network.peer.address = %peer_addr.ip(),
                    network.peer.port = %peer_addr.port(),
                    "TCP connection established",
                );
            }
        }

        result
    }
}

struct LoggingLayer;

impl<S> Layer<S> for LoggingLayer {
    type Service = LoggingService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        LoggingService { inner }
    }
}
