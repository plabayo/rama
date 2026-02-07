#![allow(clippy::print_stdout)]

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsRef,
    net::{
        Protocol,
        address::{HostWithOptPort, HostWithPort},
        client::{ConnectorService, EstablishedClientConnection},
        stream::Socket,
        tls::{
            DataEncoding,
            client::{NegotiatedTlsParameters, ServerVerifyMode},
        },
    },
    rt::Executor,
    tcp::{
        TcpStream,
        client::{Request, service::TcpConnector},
    },
    telemetry::tracing,
    tls::boring::{
        client::{TlsConnectorDataBuilder, TlsConnectorLayer},
        core::x509::X509,
    },
};

use clap::Args;

#[derive(Args, Debug, Clone)]
/// rama tls probe command
pub struct CliCommandTls {
    /// The address to connect to
    /// e.g. "example.com" or "example.com:8443"
    /// if no port is provided, the default port 443 will be used
    address: HostWithOptPort,

    #[arg(long, short = 'k')]
    /// Wether to skip certificate verification
    insecure: bool,
}

/// Run the tls command
pub async fn run(cfg: CliCommandTls) -> Result<(), BoxError> {
    let HostWithOptPort {
        host,
        port: maybe_port,
    } = cfg.address;
    let port = maybe_port.unwrap_or(Protocol::HTTPS_DEFAULT_PORT);
    let authority = HostWithPort { host, port };

    tracing::info!(
        server.address = %authority.host,
        server.port = authority.port,
        "connecting to server",
    );

    let tls_conn_data = TlsConnectorDataBuilder::new()
        .maybe_with_server_verify_mode(cfg.insecure.then_some(ServerVerifyMode::Disable))
        .with_store_server_certificate_chain(true)
        .into_shared_builder();

    let tcp_connector = TcpConnector::new(Executor::default());
    let loggin_service = LoggingLayer.layer(tcp_connector);

    let tls_connector = TlsConnectorLayer::secure()
        .with_connector_data(tls_conn_data)
        .layer(loggin_service);

    let EstablishedClientConnection { conn, .. } =
        tls_connector.connect(Request::new(authority)).await?;

    let params = conn
        .extensions()
        .get::<NegotiatedTlsParameters>()
        .context("NegotiatedTlsParameters missing connector context")?;

    if let Some(ref raw_pem_data) = params.peer_certificate_chain {
        let x509_stack = match raw_pem_data {
            DataEncoding::Der(raw_data) => {
                vec![X509::from_der(raw_data.as_slice()).context("decode DER-encoded TLS cert")?]
            }
            DataEncoding::DerStack(raw_data_slice) => {
                if raw_data_slice.is_empty() {
                    return Err(BoxError::from(
                        "DER-encoded stack byte slice for TLS cert is empty",
                    ));
                } else {
                    vec![
                        X509::from_der(raw_data_slice[0].as_slice())
                            .context("decode DER-stack-encoded TLS cert")?,
                    ]
                }
            }
            DataEncoding::Pem(raw_data) => X509::stack_from_pem(raw_data.as_bytes())
                .context("decode PEM-encoded TLS cert")?
                .into_iter()
                .collect(),
        };

        for (index, x509) in x509_stack.iter().enumerate() {
            println!("Certificate #{}:", index + 1);
            println!();
            crate::utils::tls::write_cert_info(x509, "* ", &mut std::io::stdout())
                .context("write certificate info to stdout")?;
            println!();
        }
    } else {
        return Err(BoxError::from("no peer cert information found"));
    }

    Ok(())
}

struct LoggingService<S> {
    inner: S,
}

impl<S, Input> Service<Input> for LoggingService<S>
where
    S: Service<Input, Output = EstablishedClientConnection<TcpStream, Input>>,
    S::Error: Send + 'static,
    Input: Send + 'static,
{
    type Output = EstablishedClientConnection<TcpStream, Input>;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let result = self.inner.serve(input).await;

        if let Ok(ref established_conn) = result
            && let Ok(Some(peer_addr)) = established_conn.conn.peer_addr().map(Some)
        {
            tracing::info!(
                network.peer.address = %peer_addr.ip_addr,
                network.peer.port = %peer_addr.port,
                "TCP connection established",
            );
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
