#![allow(clippy::print_stdout)]

use rama::{
    Layer, Service,
    dns::client::DnsConnector,
    error::{BoxError, BoxErrorExt, ErrorContext},
    extensions::ExtensionsRef,
    net::{
        Protocol,
        address::{HostWithOptPort, HostWithPort},
        client::{ConnectorService, EstablishedClientConnection, Request},
        stream::Socket,
    },
    tcp::{TcpStream, client::service::TcpConnector},
    telemetry::tracing,
    tls::boring::{client::TlsConnectorLayer, core::x509::X509},
    tls::client::{NegotiatedTlsParameters, ServerVerifyMode, TlsClientConfig},
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
    let port = maybe_port.as_u16().unwrap_or(Protocol::HTTPS_DEFAULT_PORT);
    let authority = HostWithPort { host, port };

    tracing::info!(
        server.address = %authority.host,
        server.port = authority.port,
        "connecting to server",
    );

    let mut tls_config = TlsClientConfig::new().with_store_server_cert_chain(true);
    if cfg.insecure {
        tls_config.set_server_verify(ServerVerifyMode::Disable);
    }

    let tcp_connector = DnsConnector::new(TcpConnector::new());
    let loggin_service = LoggingLayer.layer(tcp_connector);

    let tls_connector = TlsConnectorLayer::secure()
        .with_base_config(tls_config)
        .layer(loggin_service);

    let EstablishedClientConnection { conn, .. } =
        tls_connector.connect(Request::new(authority)).await?;

    let params = conn
        .extensions()
        .get_ref::<NegotiatedTlsParameters>()
        .context("NegotiatedTlsParameters missing connector context")?;

    if let Some(ref cert_chain) = params.peer_certificate_chain {
        let x509_stack = if cert_chain.is_empty() {
            return Err(BoxError::from_static_str(
                "DER-encoded stack byte slice for TLS cert is empty",
            ));
        } else {
            vec![
                X509::from_der(cert_chain[0].as_ref())
                    .context("decode DER-stack-encoded TLS cert")?,
            ]
        };

        for (index, x509) in x509_stack.iter().enumerate() {
            println!("Certificate #{}:", index + 1);
            println!();
            crate::utils::tls::write_cert_info(x509, "* ", &mut std::io::stdout())
                .context("write certificate info to stdout")?;
            println!();
        }
    } else {
        return Err(BoxError::from_static_str("no peer cert information found"));
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
