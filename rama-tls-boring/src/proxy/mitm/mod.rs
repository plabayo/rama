use rama_boring::{
    pkey::{PKey, Private},
    ssl::ErrorCode,
    x509::X509,
};
use rama_boring_tokio::SslErrorStack;
use rama_core::{
    Layer,
    conversion::RamaTryInto as _,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::{self, ExtensionsMut as _},
    io::{BridgeIo, Io},
    telemetry::tracing,
};
use rama_net::{
    address::{Domain, HostWithPort},
    tls::{ApplicationProtocol, client::NegotiatedTlsParameters, server::SelfSignedData},
};
use rama_net::{proxy::ProxyTarget, tls::KeyLogIntent};
use rama_utils::str::any_submatch_ignore_ascii_case;
use std::{
    fmt,
    io::{Cursor, ErrorKind},
};

use crate::core::ssl::{AlpnError, SslAcceptor, SslMethod, SslRef};
use crate::{TlsStream, client, keylog::try_new_key_log_file_handle};

pub mod issuer;

mod service;
pub use self::service::TlsMitmRelayService;

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

    #[inline(always)]
    /// Create a new [`TlsMitmRelay`] with the provided CA pair.
    pub fn new_in_memory(crt: X509, key: PKey<Private>) -> Self {
        let issuer = self::issuer::InMemoryBoringMitmCertIssuer::new(crt, key);
        Self::new(issuer)
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

    #[inline(always)]
    /// Create a new [`TlsMitmRelay`] with the provided CA pair,
    /// with a cache layer on top to provide reuse functionality of previously issued certs.
    pub fn new_cached_in_memory(crt: X509, key: PKey<Private>) -> Self {
        let issuer = self::issuer::InMemoryBoringMitmCertIssuer::new(crt, key);
        Self::new_with_cached_issuer(issuer)
    }

    #[inline(always)]
    /// Create a new [`TlsMitmRelay`] with the provided CA pair,
    /// with a cache layer (created by given config)
    /// on top to provide reuse functionality of previously issued certs.
    pub fn new_cached_in_memory_with_config(
        crt: X509,
        key: PKey<Private>,
        cfg: self::issuer::BoringMitmCertIssuerCacheConfig,
    ) -> Self {
        let issuer = self::issuer::InMemoryBoringMitmCertIssuer::new(crt, key);
        Self::new_with_cached_issuer_and_config(issuer, cfg)
    }
}

#[derive(Debug)]
/// Error type for [`TlsMitmRelay::handshake`] and the
/// service using it. Can be used to filter out cert-related issues
/// due to the relay.
pub struct TlsMitmRelayError {
    kind: TlsMitmRelayErrorKind,
    proxy_target: Option<ProxyTarget>,
    sni: Option<Domain>,
    inner: BoxError,
}

impl TlsMitmRelayError {
    #[inline(always)]
    fn config(error: impl Into<BoxError>) -> Self {
        Self {
            kind: TlsMitmRelayErrorKind::Config,
            proxy_target: None,
            sni: None,
            inner: error.into(),
        }
    }

    #[inline(always)]
    fn egress(error: impl Into<BoxError>) -> Self {
        Self {
            kind: TlsMitmRelayErrorKind::Egress,
            proxy_target: None,
            sni: None,
            inner: error.into(),
        }
    }

    #[inline(always)]
    fn ingress(error: impl Into<BoxError>, ssl_code: Option<ErrorCode>) -> Self {
        let cert_related = ssl_code
            .map(|code| code == ErrorCode::SYSCALL)
            .unwrap_or_default();

        Self {
            kind: TlsMitmRelayErrorKind::Ingress { cert_related },
            proxy_target: None,
            sni: None,
            inner: error.into(),
        }
    }

    #[inline(always)]
    fn ingress_io(error: impl Into<BoxError>) -> Self {
        Self {
            kind: TlsMitmRelayErrorKind::Ingress {
                cert_related: false,
            },
            proxy_target: None,
            sni: None,
            inner: error.into(),
        }
    }

    #[inline(always)]
    fn ingress_ssl(err: SslErrorStack, ssl_code: Option<ErrorCode>) -> Self {
        let ssl_err = err.first();
        let cert_related = ssl_code
            .map(|code| code == ErrorCode::SYSCALL)
            .unwrap_or_default()
            || ssl_err
                .reason()
                .map(|s| any_submatch_ignore_ascii_case(s, ["unknown_ca", "certificate"]))
                .unwrap_or_default();

        Self {
            kind: TlsMitmRelayErrorKind::Ingress { cert_related },
            proxy_target: None,
            sni: None,
            inner: BoxError::from(err).context("tls mitm relay: ingress tls accept ssl error"),
        }
    }

    #[inline(always)]
    fn tls_serve(error: impl Into<BoxError>) -> Self {
        Self {
            kind: TlsMitmRelayErrorKind::TlsServe,
            proxy_target: None,
            sni: None,
            inner: error.into(),
        }
    }

    #[inline(always)]
    pub fn proxy_target(&self) -> Option<&HostWithPort> {
        self.proxy_target.as_ref().map(|t| &t.0)
    }

    #[inline(always)]
    pub fn sni(&self) -> Option<&Domain> {
        self.sni.as_ref()
    }

    #[inline(always)]
    /// Returns true in case the error can be classified as a certificate
    /// related relay issue. In which case you probably want to filter out this
    /// traffic in your MITM flows.
    pub fn is_relay_cert_issue(&self) -> bool {
        matches!(
            self.kind,
            TlsMitmRelayErrorKind::Config | TlsMitmRelayErrorKind::Ingress { cert_related: true }
        )
    }

    rama_utils::macros::generate_set_and_with! {
        fn proxy_target(mut self, proxy_target: Option<ProxyTarget>) -> Self {
            self.proxy_target = proxy_target;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        fn sni(mut self, sni: Option<Domain>) -> Self {
            self.sni = sni;
            self
        }
    }
}

impl fmt::Display for TlsMitmRelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}: {} (proxy-target={:?}; sni={:?})",
            self.kind, self.inner, self.proxy_target, self.sni
        )
    }
}

impl std::error::Error for TlsMitmRelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.inner.as_ref())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsMitmRelayErrorKind {
    Config,
    Egress,
    Ingress { cert_related: bool },
    TlsServe,
}

impl<Issuer> TlsMitmRelay<Issuer>
where
    Issuer: self::issuer::BoringMitmCertIssuer<Error: Into<BoxError>>,
{
    /// Establish and MITM an handshake between the client (ingress) and server (egress).
    pub async fn handshake<Ingress, Egress>(
        &self,
        BridgeIo(ingress_stream, egress_stream): BridgeIo<Ingress, Egress>,
        connector_data: Option<client::TlsConnectorData>,
    ) -> Result<BridgeIo<TlsStream<Ingress>, TlsStream<Egress>>, TlsMitmRelayError>
    where
        Ingress: Io + Unpin + extensions::ExtensionsMut,
        Egress: Io + Unpin + extensions::ExtensionsMut,
    {
        let store_server_certificate_chain = connector_data
            .as_ref()
            .map(|cd| cd.store_server_certificate_chain)
            .unwrap_or_default();

        let mut egress_tls_stream = crate::client::tls_connect(egress_stream, connector_data)
            .await
            .map_err(TlsMitmRelayError::egress)?;

        let egress_ssl_ref = egress_tls_stream.ssl_ref();
        let source_cert = egress_ssl_ref
            .peer_certificate()
            .ok_or_else(|| BoxError::from("tls mitm relay: egress tls stream has no peer cert"))
            .map_err(TlsMitmRelayError::config)?;

        let (mirrored_leaf_cert_chain, mirrored_leaf_key) = self
            .issuer
            .issue_mitm_x509_cert(source_cert)
            .await
            .context("tls mitm relay: mirror server certificate")
            .map_err(TlsMitmRelayError::config)?;

        let mut acceptor_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
            .context("tls mitm relay: create boring ssl acceptor")
            .map_err(TlsMitmRelayError::config)?;
        acceptor_builder.set_grease_enabled(self.grease_enabled);
        acceptor_builder
            .set_default_verify_paths()
            .context("tls mitm relay: set default verify paths")
            .map_err(TlsMitmRelayError::config)?;
        for (i, crt) in mirrored_leaf_cert_chain.into_iter().enumerate() {
            if i == 0 {
                acceptor_builder
                    .set_certificate(crt.as_ref())
                    .context("tls mitm relay: set certificate")
                    .map_err(TlsMitmRelayError::config)?;
            } else {
                acceptor_builder
                    .add_extra_chain_cert(crt)
                    .context("tls mitm relay: add chain certificate")
                    .map_err(TlsMitmRelayError::config)?;
            }
        }
        acceptor_builder
            .set_private_key(mirrored_leaf_key.as_ref())
            .context("tls mitm relay: set mirrored leaf private key")
            .map_err(TlsMitmRelayError::config)?;
        acceptor_builder
            .check_private_key()
            .context("tls mitm relay: check mirrored private key")
            .map_err(TlsMitmRelayError::config)?;

        let maybe_negotiated_params = if let Some(ssl_session) = egress_ssl_ref.session() {
            let protocol_version = ssl_session.protocol_version();

            acceptor_builder
                .set_min_proto_version(Some(protocol_version))
                .context("tls mitm relay: set min tls proto version")
                .context_field("protocol_version", protocol_version)
                .map_err(TlsMitmRelayError::config)?;
            acceptor_builder
                .set_max_proto_version(Some(protocol_version))
                .context("tls mitm relay: set max tls proto version")
                .context_field("protocol_version", protocol_version)
                .map_err(TlsMitmRelayError::config)?;

            let protocol_version = protocol_version
                .rama_try_into()
                .map_err(|v| {
                    BoxError::from("boring ssl connector: cast min proto version")
                        .context_field("protocol_version", v)
                })
                .map_err(TlsMitmRelayError::config)?;

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
                Some(chain) => Some(chain.rama_try_into().map_err(TlsMitmRelayError::config)?),
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
            let handle =
                try_new_key_log_file_handle(keylog_filename).map_err(TlsMitmRelayError::config)?;
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
        let ingress_boring_ssl_stream = rama_boring_tokio::accept(&acceptor, ingress_stream)
            .await
            .map_err(|err| {
                let maybe_ssl_code = err.code();
                if let Some(io_err) = err.as_io_error() {
                    TlsMitmRelayError::ingress_io(
                        BoxError::from(format!(
                            "tls mitm relay: ingress tls accept failed with io error: {io_err}"
                        ))
                        .context_debug_field("code", maybe_ssl_code),
                    )
                } else if let Some(err) = err.as_ssl_error_stack() {
                    TlsMitmRelayError::ingress_ssl(err, maybe_ssl_code)
                } else {
                    TlsMitmRelayError::ingress(
                        BoxError::from("tls mitm relay: ingress tls accept failed")
                            .context_debug_field("code", maybe_ssl_code),
                        maybe_ssl_code,
                    )
                }
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

        let ingress_tls_stream = TlsStream::new(ingress_boring_ssl_stream);
        Ok(BridgeIo(ingress_tls_stream, egress_tls_stream))
    }
}

impl<S, Issuer: Clone> Layer<S> for TlsMitmRelay<Issuer> {
    type Service = TlsMitmRelayService<Issuer, S>;

    fn layer(&self, inner: S) -> Self::Service {
        TlsMitmRelayService::new(self.clone(), inner)
    }

    fn into_layer(self, inner: S) -> Self::Service {
        TlsMitmRelayService::new(self, inner)
    }
}
