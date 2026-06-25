use rama::{
    Service,
    extensions::ExtensionsRef,
    net::client::{ConnectorService, EstablishedClientConnection},
    telemetry::tracing,
    tls::boring::core::x509::X509,
    tls::{TlsAlpn, client::NegotiatedTlsParameters},
};

use super::VerboseLogs;

#[derive(Debug)]
pub(super) struct TlsInfoLogger<C>(pub(super) C);

impl<Input, C> Service<Input> for TlsInfoLogger<C>
where
    Input: Send + ExtensionsRef + 'static,
    C: ConnectorService<Input>,
{
    type Error = C::Error;
    type Output = EstablishedClientConnection<C::Connection, Input>;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let ec = self.0.connect(input).await?;
        if ec.input.extensions().contains::<VerboseLogs>() {
            if let Some(alpn) = ec.input.extensions().get_ref::<TlsAlpn>() {
                let protocols: Vec<String> = alpn.0.iter().map(|p| p.to_string()).collect();
                eprintln!("* ALPN: rama offers {}", protocols.join(","));
            }
            if let Some(server_tls_data) = ec.conn.extensions().get_ref::<NegotiatedTlsParameters>()
            {
                eprintln!(
                    "* TLS Connection using version {:?}",
                    server_tls_data.protocol_version
                );
                if let Some(ref alpn) = server_tls_data.application_layer_protocol {
                    eprintln!("* ALPN: server selected {alpn}");
                }
                if let Some(ref cert_chain) = server_tls_data.peer_certificate_chain
                    && let Some(x509) = if cert_chain.is_empty() {
                        tracing::error!(
                            "decode DER-stack-encoded TLS peer cert bytes was empty (BUG?)"
                        );
                        None
                    } else {
                        X509::from_der(cert_chain[0].as_ref())
                            .inspect_err(|err| {
                                tracing::error!(
                                    "failed to decode DER-stack-encoded TLS peer cert: {err}"
                                );
                            })
                            .ok()
                    }
                {
                    eprintln!("* Server Certificate:");
                    if let Err(err) =
                        crate::utils::tls::write_cert_info(&x509, "*  ", &mut std::io::stderr())
                    {
                        tracing::error!(
                            "failed to write server TLS certificate information to STDERR: {err}"
                        );
                    }
                }
            }
        }
        Ok(ec)
    }
}
