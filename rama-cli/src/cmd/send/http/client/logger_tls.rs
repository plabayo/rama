use rama::{
    Service,
    extensions::ExtensionsRef,
    net::{
        client::{ConnectorService, EstablishedClientConnection},
        tls::{ApplicationProtocol, DataEncoding, client::NegotiatedTlsParameters},
    },
    tls::boring::{client::TlsConnectorDataBuilder, core::x509::X509},
};

use itertools::Itertools as _;

use super::VerboseLogs;

#[derive(Debug)]
pub(super) struct TlsInfoLogger<C>(pub(super) C);

impl<R, C> Service<R> for TlsInfoLogger<C>
where
    R: Send + ExtensionsRef + 'static,
    C: ConnectorService<R>,
{
    type Error = C::Error;
    type Response = EstablishedClientConnection<C::Connection, R>;

    async fn serve(&self, request: R) -> Result<Self::Response, Self::Error> {
        let ec = self.0.connect(request).await?;
        if ec.req.extensions().contains::<VerboseLogs>() {
            if let Some(client_tls_data) = ec.req.extensions().get::<TlsConnectorDataBuilder>()
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
                        DataEncoding::Der(raw_data) => X509::from_der(raw_data.as_slice()).ok(),
                        DataEncoding::DerStack(raw_data_slice) => {
                            if raw_data_slice.is_empty() {
                                None
                            } else {
                                X509::from_der(raw_data_slice[0].as_slice()).ok()
                            }
                        }
                        DataEncoding::Pem(raw_data) => X509::stack_from_pem(raw_data.as_bytes())
                            .ok()
                            .and_then(|v| v.into_iter().next()),
                    }
                {
                    // TOOD: improve verbose logging in future (performance + print race conditions)
                    eprintln!("* Server Certificate:");
                    eprintln!("*  subject: {}", fmt_crt_name(x509.subject_name()));
                    let alt_names = x509
                        .subject_alt_names()
                        .iter()
                        .flatten()
                        .filter_map(|n| n.dnsname())
                        .join(", ");
                    eprintln!("*  start date: {}", x509.not_before());
                    eprintln!("*  expire date: {}", x509.not_after());
                    if !alt_names.is_empty() {
                        eprintln!("*  subjectAltNames: {alt_names}");
                    }
                    eprintln!("*  issuer: {}", fmt_crt_name(x509.issuer_name()));
                }
            }
        }
        Ok(ec)
    }
}

fn fmt_crt_name(x: &rama::tls::boring::core::x509::X509NameRef) -> String {
    // Similar to OpenSSL one line, but stable ordering by entry index
    let mut parts = Vec::new();
    for e in x.entries() {
        let obj = e.object();
        let short = obj.nid().short_name().unwrap_or("OBJ");
        let val = e
            .data()
            .as_utf8()
            .map(|s| s.to_string())
            .unwrap_or_else(|_| fmt_hex(e.data().as_slice(), ":"));
        parts.push(format!("{short}={val}"));
    }
    parts.join(", ")
}

fn fmt_hex(bytes: &[u8], sep: &str) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push_str(sep);
        }
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02X}");
    }
    s
}
