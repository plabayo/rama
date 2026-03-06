use rama_core::{
    conversion::RamaTryInto as _,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::{self, ExtensionsMut as _},
    stream::Stream,
    telemetry::tracing,
};
use rama_net::tls::{ApplicationProtocol, client::NegotiatedTlsParameters, server::SelfSignedData};
use rama_net::{proxy::StreamBridge, tls::KeyLogIntent};
use std::io::{Cursor, ErrorKind};

use crate::core::ssl::{AlpnError, SslAcceptor, SslMethod, SslRef};
use crate::{TlsStream, client, keylog::try_new_key_log_file_handle};

pub mod issuer;

#[derive(Debug, Clone)]
/// A utility that can be used by MITM services such as transparent proxies,
/// in order to relay (and MITM a TLS connection between a client and server,
/// as part of a deep protocol inspection protocol (DPI) flow.
pub struct TlsMitmRelay<Issuer> {
    issuer: Issuer,
    grease_enabled: bool,
    keylog_intent: KeyLogIntent,
}

impl<Issuer> TlsMitmRelay<Issuer> {
    #[inline(always)]
    /// Create a new [`TlsMitmRelay`].
    pub fn new(issuer: Issuer) -> Self {
        Self {
            issuer,
            grease_enabled: true,
            keylog_intent: KeyLogIntent::Environment,
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

    rama_utils::macros::generate_set_and_with! {
        /// Set the [`keylog_intent`].
        ///
        /// By default [`KeyLogIntent::Environment`] is used.
        pub fn keylog_intent(mut self, intent: KeyLogIntent) -> Self {
            self.keylog_intent = intent;
            self
        }
    }
}

impl<Issuer> TlsMitmRelay<self::issuer::CachedBoringMitmCertIssuer<Issuer>> {
    #[inline(always)]
    /// Create a new [`TlsMitmRelay`],
    /// with a cache layer on top top of the provided issuer
    /// toprovide reuse functionality of previously issued certs.
    pub fn new_with_cached_issuer(issuer: Issuer) -> Self {
        Self::new(self::issuer::CachedBoringMitmCertIssuer::new(issuer))
    }

    #[inline(always)]
    /// Create a new [`TlsMitmRelay`],
    /// with a cache layer (created by given config)
    /// on top of the provided issuer to provide reuse functionality of previously issued certs.
    pub fn new_with_cached_issuer_and_config(
        issuer: Issuer,
        cfg: self::issuer::BoringMitmCertIssuerCacheConfig,
    ) -> Self {
        Self::new(self::issuer::CachedBoringMitmCertIssuer::new_with_config(
            issuer, cfg,
        ))
    }
}

impl TlsMitmRelay<self::issuer::InMemoryBoringMitmCertIssuer> {
    #[inline(always)]
    /// Create a new [`TlsMitmRelay`] with self-signed CA using the given data.
    pub fn try_new_with_self_signed_issuer(data: &SelfSignedData) -> Result<Self, BoxError> {
        let issuer = self::issuer::InMemoryBoringMitmCertIssuer::try_new_self_signed(data)?;
        Ok(Self::new(issuer))
    }
}

impl
    TlsMitmRelay<
        self::issuer::CachedBoringMitmCertIssuer<self::issuer::InMemoryBoringMitmCertIssuer>,
    >
{
    #[inline(always)]
    /// Create a new [`TlsMitmRelay`] with self-signed CA using the given data,
    /// with a cache layer on top to provide reuse functionality of previously issued certs.
    pub fn try_new_with_cached_self_signed_issuer(data: &SelfSignedData) -> Result<Self, BoxError> {
        let issuer = self::issuer::InMemoryBoringMitmCertIssuer::try_new_self_signed(data)?;
        Ok(Self::new_with_cached_issuer(issuer))
    }

    #[inline(always)]
    /// Create a new [`TlsMitmRelay`] with self-signed CA using the given data,
    /// with a cache layer (created by given config)
    /// on top to provide reuse functionality of previously issued certs.
    pub fn try_new_with_cached_self_signed_issuer_and_config(
        data: &SelfSignedData,
        cfg: self::issuer::BoringMitmCertIssuerCacheConfig,
    ) -> Result<Self, BoxError> {
        let issuer = self::issuer::InMemoryBoringMitmCertIssuer::try_new_self_signed(data)?;
        Ok(Self::new_with_cached_issuer_and_config(issuer, cfg))
    }
}

impl<Issuer> TlsMitmRelay<Issuer>
where
    Issuer: self::issuer::BoringMitmCertIssuer<Error: Into<BoxError>>,
{
    /// Establish and MITM an handshake between the client (left) and server (right).
    pub async fn handshake<Left, Right>(
        &self,
        StreamBridge {
            left: ingress_stream,
            right: egress_stream,
        }: StreamBridge<Left, Right>,
        connector_data: Option<client::TlsConnectorData>,
    ) -> Result<StreamBridge<TlsStream<Left>, TlsStream<Right>>, BoxError>
    where
        Left: Stream + Unpin + extensions::ExtensionsMut,
        Right: Stream + Unpin + extensions::ExtensionsMut,
    {
        let store_server_certificate_chain = connector_data
            .as_ref()
            .map(|cd| cd.store_server_certificate_chain)
            .unwrap_or_default();

        let mut egress_tls_stream =
            crate::client::tls_connect(egress_stream, connector_data).await?;

        let egress_ssl_ref = egress_tls_stream.ssl_ref();
        let source_cert = egress_ssl_ref
            .peer_certificate()
            .ok_or_else(|| BoxError::from("tls mitm relay: egress tls stream has no peer cert"))?;

        let (mirrored_leaf_cert_chain, mirrored_leaf_key) = self
            .issuer
            .issue_mitm_x509_cert(source_cert)
            .await
            .context("tls mitm relay: mirror server certificate")?;

        let mut acceptor_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
            .context("tls mitm relay: create boring ssl acceptor")?;
        acceptor_builder.set_grease_enabled(self.grease_enabled);
        acceptor_builder
            .set_default_verify_paths()
            .context("tls mitm relay: set default verify paths")?;
        for (i, crt) in mirrored_leaf_cert_chain.into_iter().enumerate() {
            if i == 0 {
                acceptor_builder
                    .set_certificate(crt.as_ref())
                    .context("tls mitm relay: set certificate")?;
            } else {
                acceptor_builder
                    .add_extra_chain_cert(crt)
                    .context("tls mitm relay: add chain certificate")?;
            }
        }
        acceptor_builder
            .set_private_key(mirrored_leaf_key.as_ref())
            .context("tls mitm relay: set mirrored leaf private key")?;
        acceptor_builder
            .check_private_key()
            .context("tls mitm relay: check mirrored private key")?;

        let maybe_negotiated_params = if let Some(ssl_session) = egress_ssl_ref.session() {
            let protocol_version = ssl_session.protocol_version();

            acceptor_builder
                .set_min_proto_version(Some(protocol_version))
                .context("tls mitm relay: set min tls proto version")
                .context_field("protocol_version", protocol_version)?;
            acceptor_builder
                .set_max_proto_version(Some(protocol_version))
                .context("tls mitm relay: set max tls proto version")
                .context_field("protocol_version", protocol_version)?;

            let protocol_version = protocol_version.rama_try_into().map_err(|v| {
                BoxError::from("boring ssl connector: cast min proto version")
                    .context_field("protocol_version", v)
            })?;

            tracing::debug!(
                "boring client (connector) protocol version: {protocol_version} (set as min/max)"
            );

            let application_layer_protocol = egress_ssl_ref
                .selected_alpn_protocol()
                .map(ApplicationProtocol::from);

            if let Some(selected_alpn_protocol) = application_layer_protocol.clone() {
                tracing::debug!(
                    "boring client (connector) has selected ALPN {selected_alpn_protocol}"
                );

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
                                        tracing::debug!(
                                            "failed to find ALPN (Unexpected EOF): {error}; NOACK"
                                        );
                                        AlpnError::NOACK
                                    } else {
                                        tracing::debug!(
                                            "failed to decode ALPN: {error}; ALERT_FATAL"
                                        );
                                        AlpnError::ALERT_FATAL
                                    });
                                }
                            }
                        }
                    },
                );
            }

            let server_certificate_chain = match store_server_certificate_chain
                .then(|| egress_ssl_ref.peer_cert_chain())
                .flatten()
            {
                Some(chain) => Some(chain.rama_try_into()?),
                None => None,
            };

            Some(NegotiatedTlsParameters {
                protocol_version,
                application_layer_protocol,
                peer_certificate_chain: server_certificate_chain,
            })
        } else {
            None
        };

        if let Some(keylog_filename) = self.keylog_intent.file_path().as_deref() {
            let handle = try_new_key_log_file_handle(keylog_filename)?;
            acceptor_builder.set_keylog_callback(move |_, line| {
                let line = format!("{line}\n");
                handle.write_log_line(line);
            });
        }

        tracing::debug!(
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

        if let Some(negotiated_params) = maybe_negotiated_params {
            #[cfg(feature = "http")]
            if let Some(proto) = negotiated_params.application_layer_protocol.as_ref()
                && let Ok(neg_version) = rama_http_types::Version::try_from(proto)
            {
                egress_tls_stream
                    .extensions_mut()
                    .insert(rama_http_types::conn::TargetHttpVersion(neg_version));
            }

            egress_tls_stream.extensions_mut().insert(negotiated_params);
        }

        Ok(StreamBridge {
            left: TlsStream::new(ingress_tls_stream),
            right: egress_tls_stream,
        })
    }
}
