use clap::Args;
use rama::{
    Context, Layer, Service,
    error::BoxError,
    net::{
        address::Authority,
        client::{ConnectorService, EstablishedClientConnection},
        tls::{
            DataEncoding,
            client::{ClientConfig, NegotiatedTlsParameters, ServerVerifyMode},
        },
    },
    tcp::client::{Request, service::TcpConnector},
    tls::{
        rustls::client::{TlsConnectorData, TlsConnectorLayer},
        std::dep::boring::x509::X509,
    },
};
use tokio::net::TcpStream;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

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
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let authority = match Authority::try_from(cfg.address.clone()) {
        Ok(authority) => authority,
        // if missing port, we can try to add the default port
        Err(err) if err.to_string().contains("missing port") => {
            let authority = format!("{}:443", cfg.address);
            Authority::try_from(authority)?
        }
        Err(err) => return Err(err.into()),
    };

    tracing::info!("Connecting to: {}", authority);

    let tls_client_data = TlsConnectorData::try_from(ClientConfig {
        store_server_certificate_chain: true,
        server_verify_mode: if cfg.insecure {
            Some(ServerVerifyMode::Disable)
        } else {
            Some(ServerVerifyMode::Auto)
        },
        ..Default::default()
    })
    .expect("create tls connector data for client");

    let tcp_connector = TcpConnector::new();
    let loggin_service = LoggingLayer.layer(tcp_connector);

    let tls_connector = TlsConnectorLayer::secure()
        .with_connector_data(tls_client_data)
        .layer(loggin_service);

    let EstablishedClientConnection {
        ctx,
        req: _,
        conn: _,
    } = tls_connector
        .connect(Context::default(), Request::new(authority))
        .await?;

    let params = ctx.get::<NegotiatedTlsParameters>().unwrap();

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
            _ => {
                println!("No peer certificate chain available");
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
    S::Error: Send + Sync + 'static,
    State: Send + Sync + 'static,
    Req: Send + 'static,
{
    type Response = EstablishedClientConnection<TcpStream, State, Req>;
    type Error = S::Error;

    async fn serve(&self, ctx: Context<State>, req: Req) -> Result<Self::Response, Self::Error> {
        let result = self.inner.serve(ctx, req).await;

        if let Ok(ref established_conn) = result {
            if let Ok(Some(peer_addr)) = established_conn.conn.peer_addr().map(Some) {
                tracing::info!("TCP connection established to IP: {}", peer_addr);
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
