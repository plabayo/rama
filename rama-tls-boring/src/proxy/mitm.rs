use rama_core::{
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions,
    stream::Stream,
    telemetry::tracing,
};
use rama_net::proxy::StreamBridge;
use rama_net::tls::ApplicationProtocol;
use std::{
    fmt,
    io::{Cursor, ErrorKind},
};

use crate::{client, server};
use crate::{
    core::ssl::{AlpnError, SslAcceptor, SslMethod, SslRef},
    core::{pkey::PKey, pkey::Private, x509::X509},
};

#[derive(Clone)]
/// A utility that can be used by MITM services such as transparent proxies,
/// in order to relay (and MITM a TLS connection between a client and server,
/// as part of a deep protocol inspection protocol (DPI) flow.
pub struct TlsMitmRelay {
    ca_cert: X509,
    ca_privkey: PKey<Private>,
    grease_enabled: bool,
}

// TODO: support cert storage for re-use, also support dynamic issuer...

impl fmt::Debug for TlsMitmRelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsMitmRelay")
            .field("ca_cert", &self.ca_cert)
            .field("ca_privkey", &"PKey<Private>")
            .field("grease_enabled", &self.grease_enabled)
            .finish()
    }
}

impl TlsMitmRelay {
    #[inline(always)]
    /// Create a new [`TlsMitmRelay`].
    pub fn new(ca_cert: X509, ca_privkey: PKey<Private>) -> Self {
        Self {
            ca_cert,
            ca_privkey,
            grease_enabled: true,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set whether GREASE should be enabled for the ingress-side TLS acceptor.
        ///
        /// By default is is enabled (true).
        pub fn grease_enabled(mut self, enabled: bool) -> Self {
            self.grease_enabled = enabled;
            self
        }
    }
}

impl TlsMitmRelay {
    /// Establish and MITM an handshake between the client (left) and server (right).
    pub async fn handshake<Left, Right>(
        &self,
        StreamBridge {
            left: ingress_stream,
            right: egress_stream,
        }: StreamBridge<Left, Right>,
        connector_data: Option<client::TlsConnectorData>,
    ) -> Result<StreamBridge<server::TlsStream<Left>, client::TlsStream<Right>>, BoxError>
    where
        Left: Stream + Unpin + extensions::ExtensionsMut,
        Right: Stream + Unpin + extensions::ExtensionsMut,
    {
        let egress_tls_stream = crate::client::tls_connect(egress_stream, connector_data).await?;

        let egress_ssl_ref = egress_tls_stream.ssl_ref();
        let source_cert = egress_ssl_ref
            .peer_certificate()
            .ok_or_else(|| BoxError::from("tls mitm relay: egress tls stream has no peer cert"))?;

        let (mirrored_leaf_cert, mirrored_leaf_key) =
            server::utils::self_signed_server_auth_mirror_cert(
                source_cert.as_ref(),
                &self.ca_cert,
                &self.ca_privkey,
            )
            .context("tls mitm relay: mirror server certificate")?;

        let mut acceptor_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
            .context("tls mitm relay: create boring ssl acceptor")?;
        acceptor_builder.set_grease_enabled(self.grease_enabled);
        acceptor_builder
            .set_default_verify_paths()
            .context("tls mitm relay: set default verify paths")?;
        acceptor_builder
            .set_certificate(mirrored_leaf_cert.as_ref())
            .context("tls mitm relay: set mirrored leaf cert")?;
        acceptor_builder
            .set_private_key(mirrored_leaf_key.as_ref())
            .context("tls mitm relay: set mirrored leaf private key")?;
        acceptor_builder
            .check_private_key()
            .context("tls mitm relay: check mirrored private key")?;

        if let Some(version) = egress_ssl_ref
            .session()
            .map(|session| session.protocol_version())
        {
            acceptor_builder
                .set_min_proto_version(Some(version))
                .context("tls mitm relay: set mirrored min protocol version")?;
            acceptor_builder
                .set_max_proto_version(Some(version))
                .context("tls mitm relay: set mirrored max protocol version")?;
        }

        if let Some(selected_alpn_protocol) = egress_ssl_ref
            .selected_alpn_protocol()
            .map(ApplicationProtocol::from)
        {
            acceptor_builder.set_alpn_select_callback(
                move |_: &mut SslRef, client_alpns: &[u8]| {
                    let mut reader = Cursor::new(client_alpns);
                    loop {
                        let n = reader.position() as usize;
                        match ApplicationProtocol::decode_wire_format(&mut reader) {
                            Ok(proto) => {
                                if proto == selected_alpn_protocol {
                                    let m = reader.position() as usize;
                                    return Ok(&client_alpns[n + 1..m]);
                                }
                            }
                            Err(error) => {
                                return Err(if error.kind() == ErrorKind::UnexpectedEof {
                                    AlpnError::NOACK
                                } else {
                                    AlpnError::ALERT_FATAL
                                });
                            }
                        }
                    }
                },
            );
        }

        // TODO: also insert selected ALPN in both egress and ingress....
        // Perhaps also negotiated parameters....

        tracing::trace!(
            protocol = ?egress_ssl_ref.version(),
            has_alpn = egress_ssl_ref.selected_alpn_protocol().is_some(),
            "tls mitm relay: accepting ingress tls handshake with mirrored server hints",
        );
        let acceptor = acceptor_builder.build();
        let ingress_tls_stream = rama_boring_tokio::accept(&acceptor, ingress_stream)
            .await
            .map_err(|err| {
                let maybe_ssl_code = err.code();
                if let Some(io_err) = err.as_io_error() {
                    BoxError::from(format!(
                        "tls mitm relay: ingress tls accept failed with io error: {io_err}"
                    ))
                } else if let Some(err) = err.as_ssl_error_stack() {
                    BoxError::from(err).context("tls mitm relay: ingress tls accept ssl error")
                } else {
                    BoxError::from("tls mitm relay: ingress tls accept failed")
                }
                .context_debug_field("code", maybe_ssl_code)
            })?;

        Ok(StreamBridge {
            left: server::TlsStream::new(ingress_tls_stream),
            right: egress_tls_stream,
        })
    }
}
