use rama::{
    Service,
    extensions::ExtensionsRef,
    net::{
        client::{ConnectorService, EstablishedClientConnection},
        tls::{ApplicationProtocol, DataEncoding, client::NegotiatedTlsParameters},
    },
    telemetry::tracing,
    tls::boring::{client::TlsConnectorDataBuilder, core::x509::X509},
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
            if let Some(client_tls_data) = ec.input.extensions().get::<TlsConnectorDataBuilder>()
                && let Some(alpn) = client_tls_data.alpn_protos()
            {
                let mut protocols = Vec::new();
                let mut reader = std::io::Cursor::new(&alpn[..]);
                while let Ok(protocol) = ApplicationProtocol::decode_wire_format(&mut reader) {
                    protocols.push(protocol.to_string());
                }
                eprintln!("* ALPN: rama offers {}", protocols.join(","));
            }
            if let Some(server_tls_data) = ec.conn.extensions().get::<NegotiatedTlsParameters>() {
                eprintln!(
                    "* TLS Connection using version {:?}",
                    server_tls_data.protocol_version
                );
                if let Some(ref alpn) = server_tls_data.application_layer_protocol {
                    eprintln!("* ALPN: server selected {alpn}");
                }
                if let Some(ref raw_pem_data) = server_tls_data.peer_certificate_chain
                    && let Some(x509) = match raw_pem_data {
                        DataEncoding::Der(raw_data) => X509::from_der(raw_data.as_slice())
                            .inspect_err(|err| {
                                tracing::error!(
                                    "failed to decode DER-encoded TLS peer cert: {err}"
                                );
                            })
                            .ok(),
                        DataEncoding::DerStack(raw_data_slice) => {
                            if raw_data_slice.is_empty() {
                                tracing::error!(
                                    "decode DER-stack-encoded TLS peer cert bytes was empty (BUG?)"
                                );
                                None
                            } else {
                                X509::from_der(raw_data_slice[0].as_slice()).inspect_err(|err| {
                                    tracing::error!(
                                        "failed to decode DER-stack-encoded TLS peer cert: {err}"
                                    );
                                }).ok()
                            }
                        }
                        DataEncoding::Pem(raw_data) => X509::stack_from_pem(raw_data.as_bytes())
                            .inspect_err(|err| {
                                tracing::error!(
                                    "failed to decode PEM-encoded TLS peer cert: {err}"
                                );
                            })
                            .ok()
                            .and_then(|v| v.into_iter().next()),
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
