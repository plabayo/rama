use rama_boring::{
    pkey::{PKey, Private},
    ssl::ErrorCode,
    x509::X509,
};
use rama_boring_tokio::SslErrorStack;
use rama_core::error::BoxErrorExt as _;
use rama_core::{
    Layer,
    conversion::RamaTryInto as _,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    extensions::{self, ExtensionsRef as _},
    io::{BridgeIo, Io},
    telemetry::tracing,
};
use rama_net::{
    address::{Domain, HostWithPort},
    tls::{ApplicationProtocol, client::NegotiatedTlsParameters, server::SelfSignedData},
};
use rama_net::{extensions::StreamTransformed, tls::KeyLogIntent};
use rama_utils::str::any_submatch_ignore_ascii_case;
use std::{
    fmt,
    io::{Cursor, ErrorKind},
};

use crate::core::ssl::{AlpnError, SslAcceptor, SslMethod, SslRef};
use crate::{TlsStream, client};
use rama_net::tls::keylog::{KeyLogSink, open_intent_sink};

// `alert` module retained (encode_plain_alert + write_plain_alert) so
// the wire-format pin tests stay live and we can re-enable injection
// later without resurrecting the byte layout. The `write_plain_alert`
// call sites are reverted — see the comments at those sites.
// mod alert;

pub mod issuer;

pub mod revocation;

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
        /// Set the [`KeyLogIntent`].
        ///
        /// Default is [`KeyLogIntent::Environment`], matching Chrome,
        /// Firefox, curl, and most TLS stacks: a non-empty
        /// `SSLKEYLOGFILE` env var enables key logging. In a MITM
        /// relay this exports session keys for both the ingress
        /// (relay-mirrored) and egress (upstream) sides, so anyone
        /// with read access to the keylog file can decrypt every
        /// relayed flow. Treat the file as security-sensitive
        /// (restricted dir, rotate, delete when done) and pick
        /// [`KeyLogIntent::Disabled`] if your deployment shouldn't
        /// honour the env var at all.
        pub fn keylog_intent(mut self, intent: KeyLogIntent) -> Self {
            self.keylog_intent = intent;
            self
        }
    }

    /// Borrow the currently-configured [`KeyLogIntent`]. Useful when
    /// constructing a sibling relay (e.g. after a CA rotation) that
    /// should share the same sink — a `Custom(Arc<dyn KeyLogSink>)`
    /// cloned this way keeps writing through the same backing toggle.
    #[must_use]
    pub fn keylog_intent_ref(&self) -> &KeyLogIntent {
        &self.keylog_intent
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
/// Error type for [`TlsMitmRelay::handshake`] and the service using it.
///
/// Pattern-match on [`TlsMitmRelayError::kind`] to drive policy (e.g.
/// caching SNI bypass exceptions only on
/// [`HandshakeRelayClassification::CertTrust`]), and read
/// [`TlsMitmRelayError::direction`] to differentiate ingress
/// (client ↔ MITM) from egress (MITM ↔ upstream).
pub struct TlsMitmRelayError {
    kind: TlsMitmRelayErrorKind,
    connector_target: Option<HostWithPort>,
    sni: Option<Domain>,
    inner: BoxError,
}

impl TlsMitmRelayError {
    #[inline(always)]
    fn config(error: impl Into<BoxError>) -> Self {
        Self {
            kind: TlsMitmRelayErrorKind::Config,
            connector_target: None,
            sni: None,
            inner: error.into(),
        }
    }

    #[inline(always)]
    fn handshake(
        direction: TlsMitmRelayErrorDirection,
        error: impl Into<BoxError>,
        ssl_code: Option<ErrorCode>,
    ) -> Self {
        // `SSL_ERROR_SYSCALL` with neither an inner `io::Error` nor any
        // BoringSSL error-stack entry is the "unexpected EOF mid-handshake"
        // case: the peer FIN'd the TCP socket before sending a TLS alert.
        // Bucket alongside other transport-level failures — no TLS-protocol
        // signal to act on.
        let classification = match ssl_code {
            Some(ErrorCode::SYSCALL) => HandshakeRelayClassification::Transport,
            _ => HandshakeRelayClassification::Unclassified,
        };

        Self {
            kind: TlsMitmRelayErrorKind::Handshake {
                direction,
                classification,
            },
            connector_target: None,
            sni: None,
            inner: error.into(),
        }
    }

    #[inline(always)]
    fn handshake_io(direction: TlsMitmRelayErrorDirection, error: impl Into<BoxError>) -> Self {
        Self {
            kind: TlsMitmRelayErrorKind::Handshake {
                direction,
                classification: HandshakeRelayClassification::Transport,
            },
            connector_target: None,
            sni: None,
            inner: error.into(),
        }
    }

    #[inline(always)]
    fn handshake_ssl(direction: TlsMitmRelayErrorDirection, err: SslErrorStack) -> Self {
        let classification = classify_handshake_reasons(err.iter().filter_map(|e| e.reason()));

        Self {
            kind: TlsMitmRelayErrorKind::Handshake {
                direction,
                classification,
            },
            connector_target: None,
            sni: None,
            inner: BoxError::from(err).context("tls mitm relay: tls accept ssl error"),
        }
    }

    #[inline(always)]
    fn tls_serve(error: impl Into<BoxError>) -> Self {
        Self {
            kind: TlsMitmRelayErrorKind::TlsServe,
            connector_target: None,
            sni: None,
            inner: error.into(),
        }
    }

    #[inline(always)]
    pub fn connector_target(&self) -> Option<&HostWithPort> {
        self.connector_target.as_ref()
    }

    #[inline(always)]
    pub fn sni(&self) -> Option<&Domain> {
        self.sni.as_ref()
    }

    /// Full kind of this error. Pattern-match this to drive policy
    /// decisions (e.g. cache SNI bypass exception on
    /// `Handshake { classification: CertTrust, direction: Ingress }`).
    #[inline(always)]
    pub fn kind(&self) -> TlsMitmRelayErrorKind {
        self.kind
    }

    /// Convenience accessor: direction of a handshake error.
    /// Returns `None` for non-handshake kinds ([`TlsMitmRelayErrorKind::Config`]
    /// and [`TlsMitmRelayErrorKind::TlsServe`] have no inherent direction).
    #[inline(always)]
    pub fn direction(&self) -> Option<TlsMitmRelayErrorDirection> {
        match self.kind {
            TlsMitmRelayErrorKind::Handshake { direction, .. } => Some(direction),
            TlsMitmRelayErrorKind::Config | TlsMitmRelayErrorKind::TlsServe => None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        fn connector_target(mut self, connector_target: Option<HostWithPort>) -> Self {
            self.connector_target = connector_target;
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
            "{:?}: {} (connector-target={:?}; sni={:?})",
            self.kind, self.inner, self.connector_target, self.sni
        )
    }
}

impl std::error::Error for TlsMitmRelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.inner.as_ref())
    }
}

/// Kind of [`TlsMitmRelayError`]. Pattern-match this to drive
/// caller-side policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMitmRelayErrorKind {
    /// Our-side setup failure (acceptor build, cert mirroring,
    /// keylog open, missing upstream peer cert, ...). Always
    /// pre-handshake and not attributable to either ingress or
    /// egress alone.
    Config,
    /// TLS handshake failure on the ingress or egress side, with a
    /// classification of what kind of failure it was.
    Handshake {
        /// Which side of the relay the handshake failed on.
        direction: TlsMitmRelayErrorDirection,
        /// What kind of handshake failure it was.
        classification: HandshakeRelayClassification,
    },
    /// Post-handshake serving error from the wrapped inner service.
    /// Bidirectional bridge serving — no single direction applies.
    TlsServe,
}

/// Which side of the MITM relay a handshake error occurred on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMitmRelayErrorDirection {
    /// Client ↔ MITM side: the peer accepted or rejected our re-signed
    /// MITM cert.
    Ingress,
    /// MITM ↔ upstream side: our verifier accepted or rejected the
    /// upstream's real cert (or the upstream rejected us / dropped the
    /// connection).
    Egress,
}

/// Classification of a handshake-time failure.
///
/// Designed so callers can mix-and-match against direction (via
/// [`TlsMitmRelayError::direction`]) to express policy. The intended
/// shape for an MITM relay caching SNI bypass exceptions is:
///
/// ```text
/// match (err.kind(), err.direction()) {
///     (TlsMitmRelayErrorKind::Handshake {
///         classification: HandshakeRelayClassification::CertTrust, ..
///     }, Some(TlsMitmRelayErrorDirection::Ingress)) => {
///         // peer's trust store doesn't include our CA — cache SNI bypass
///     }
///     _ => { /* don't cache; log/event per classification */ }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRelayClassification {
    /// No recognizable signal (e.g. builder-style error with no SSL
    /// code, no `io::Error`, no error stack).
    Unclassified,

    /// Transport-layer failure during handshake. Covers both real
    /// `io::Error`s (TCP RST, ECONNRESET, broken pipe, EOF with errno)
    /// *and* the `SSL_ERROR_SYSCALL`-with-empty-error-queue case
    /// (peer FIN'd mid-handshake without sending a TLS alert). In
    /// neither case did the peer engage with us at TLS protocol
    /// layer.
    Transport,

    /// Peer / library engaged at TLS protocol layer and the handshake
    /// failed there. Covers any peer-sent alert (`handshake_failure`,
    /// `protocol_version`, `decrypt_error`, `internal_error`, ...),
    /// any library protocol error (`WRONG_VERSION_NUMBER`,
    /// `NO_SHARED_CIPHER`, `DOWNGRADE_DETECTED`, ...), and any
    /// cert-shaped error that is *not* a trust outcome — cert format,
    /// protocol, or config mismatches (`CERT_LENGTH_MISMATCH`,
    /// `BAD_ECC_CERT`, `CERTIFICATE_AND_PRIVATE_KEY_MISMATCH`,
    /// `UNSUPPORTED_CERTIFICATE`, `CERTIFICATE_REQUIRED`, ...).
    TlsProtocol,

    /// Trust-outcome failure: the peer's TLS stack rejected our cert
    /// chain as untrusted, or our local verifier rejected the peer's
    /// chain. Matches:
    /// - Peer alerts that signal trust validation failure:
    ///   `unknown_ca`, `certificate_expired`,
    ///   `certificate_revoked`, `certificate_unknown`.
    /// - Library validation outcomes: `CERTIFICATE_VERIFY_FAILED`,
    ///   `NO_MATCHING_ISSUER` (and OpenSSL-compatible `*untrusted*`).
    ///
    /// This is the *only* classification where caching an SNI bypass
    /// exception is meaningful — it indicates a structural trust
    /// mismatch (e.g. our managed CA is not in the peer's trust
    /// store) that will not clear up on retry.
    CertTrust,
}

/// Classify a handshake-time SSL error stack from its reason strings.
///
/// Intended to be called with the reasons of a non-empty BoringSSL
/// error stack (the [`TlsMitmRelayError::handshake_ssl`] path). For an
/// empty input — which shouldn't happen via the production callers —
/// defaults to [`HandshakeRelayClassification::TlsProtocol`] (we know
/// we came from an SSL error path, we just have no readable reason).
#[inline]
fn classify_handshake_reasons<'a, I>(reasons: I) -> HandshakeRelayClassification
where
    I: IntoIterator<Item = &'a str>,
{
    for reason in reasons {
        if reason_is_cert_trust_signal(reason) {
            return HandshakeRelayClassification::CertTrust;
        }
    }
    HandshakeRelayClassification::TlsProtocol
}

/// Substrings that mark a BoringSSL reason as a trust-outcome failure.
///
/// Kept narrow on purpose: only reasons that mean "the cert chain
/// failed trust validation". Cert-format / cert-protocol / cert-config
/// errors (`CERT_LENGTH_MISMATCH`, `BAD_ECC_CERT`,
/// `CERTIFICATE_AND_PRIVATE_KEY_MISMATCH`, `UNSUPPORTED_CERTIFICATE`,
/// `CERTIFICATE_REQUIRED`, ...) are *not* trust outcomes — they fall
/// through to [`HandshakeRelayClassification::TlsProtocol`].
///
/// Substrings are matched case-insensitively against BoringSSL reason
/// strings from `ERR_reason_error_string` (e.g. `TLSV1_ALERT_UNKNOWN_CA`,
/// `CERTIFICATE_VERIFY_FAILED`).
const CERT_TRUST_REASON_SUBSTRINGS: &[&str] = &[
    // Peer alerts that are trust-validation outcomes:
    "unknown_ca",          // TLSV1_ALERT_UNKNOWN_CA
    "certificate_expired", // *_ALERT_CERTIFICATE_EXPIRED
    "certificate_revoked", // *_ALERT_CERTIFICATE_REVOKED
    "certificate_unknown", // *_ALERT_CERTIFICATE_UNKNOWN (generic trust reject)
    // Library validation outcomes (our verifier failed the chain):
    "certificate_verify_failed", // CERTIFICATE_VERIFY_FAILED
    "no_matching_issuer",        // NO_MATCHING_ISSUER
    // Defensive OpenSSL cross-compat (not in current BoringSSL set):
    "untrusted",
];

#[inline]
fn reason_is_cert_trust_signal(reason: &str) -> bool {
    any_submatch_ignore_ascii_case(reason, CERT_TRUST_REASON_SUBSTRINGS)
}

impl<Issuer> TlsMitmRelay<Issuer>
where
    Issuer: self::issuer::BoringMitmCertIssuer<Error: Into<BoxError>>,
{
    /// Establish and MITM an handshake between the client (ingress) and server (egress).
    pub async fn handshake<Ingress, Egress>(
        &self,
        BridgeIo(mut ingress_stream, egress_stream): BridgeIo<Ingress, Egress>,
        connector_data: Option<client::TlsConnectorData>,
    ) -> Result<BridgeIo<TlsStream<Ingress>, TlsStream<Egress>>, TlsMitmRelayError>
    where
        Ingress: Io + Unpin + extensions::ExtensionsRef,
        Egress: Io + Unpin + extensions::ExtensionsRef,
    {
        let store_server_certificate_chain = connector_data
            .as_ref()
            .map(|cd| cd.store_server_certificate_chain)
            .unwrap_or_default();

        let egress_tls_stream = match crate::client::tls_connect(egress_stream, connector_data)
            .await
        {
            Ok(stream) => stream,
            Err(err) => {
                let relay_err = match err {
                    client::TlsConnectError::Builder(error) => TlsMitmRelayError::handshake(
                        TlsMitmRelayErrorDirection::Egress,
                        error.context("tls connect builder error"),
                        None,
                    ),
                    client::TlsConnectError::Handshake { server_name, error } => {
                        let maybe_ssl_code = error.code();
                        if let Some(io_err) = error.as_io_error() {
                            TlsMitmRelayError::handshake_io(
                                TlsMitmRelayErrorDirection::Egress,
                                BoxError::from(format!(
                                    "tls mitm relay: egress tls accept failed with io error: {io_err}"
                                ))
                                .context_debug_field("code", maybe_ssl_code)
                                .context_debug_field("sni", server_name),
                            )
                        } else if let Some(err) = error.as_ssl_error_stack() {
                            let mut relay_err = TlsMitmRelayError::handshake_ssl(
                                TlsMitmRelayErrorDirection::Egress,
                                err,
                            );
                            relay_err.sni = server_name;
                            relay_err
                        } else {
                            TlsMitmRelayError::handshake(
                                TlsMitmRelayErrorDirection::Egress,
                                BoxError::from_static_str(
                                    "tls mitm relay: egress tls accept failed",
                                )
                                .context_debug_field("code", maybe_ssl_code)
                                .context_debug_field("sni", server_name),
                                maybe_ssl_code,
                            )
                        }
                    }
                };
                // The plaintext TLS Alert injection that used to live
                // here was reverted — empirical regression report
                // (Firefox `SSL_ERROR_NO_CYPHER_OVERLAP` + Safari
                // weird-redirect behavior on a tproxy that worked
                // fine on `main`). Hypothesis: even though the
                // alert path only fires on egress-handshake failure,
                // emitting a fatal handshake-failure record changes
                // how Firefox NSS classifies the connection close
                // versus the previous transport-reset baseline, and
                // somehow drops the client into a worse retry path.
                // The right next step is a packet capture of one
                // failing handshake; until then, restore the
                // main-branch behavior of letting the transport
                // close speak for itself.
                let _ = &mut ingress_stream;
                return Err(relay_err);
            }
        };
        egress_tls_stream.extensions().insert(StreamTransformed {
            by: "rama-tls-boring::TlsMitmRelay",
        });

        // Cert-mirror + acceptor-build phase. Any failure here is still
        // pre-ingress-handshake — we haven't written a byte to the
        // client yet, so the plaintext alert is valid. Wrap in an
        // async block so every `?` propagates to a single point that
        // emits the alert before returning the error.
        //
        // The block extracts everything it needs from `egress_tls_stream`
        // into owned values *before* the cert-mirror `.await`; holding
        // a borrow across that await would force `Egress: Sync` on the
        // public signature, which the bridge stream type doesn't
        // provide.
        let acceptor_build_result: Result<
            (SslAcceptor, Option<NegotiatedTlsParameters>, TlsStream<Egress>),
            TlsMitmRelayError,
        > = async move {
            // Snapshot of every `egress_ssl_ref`-derived value the
            // post-await build path needs. Bounded to a scope that
            // ends before the `.await` so the borrow is released.
            struct EgressHandshakeSnapshot {
                source_cert: X509,
                session_protocol_version: Option<rama_boring::ssl::SslVersion>,
                alpn_proto: Option<ApplicationProtocol>,
                peer_cert_chain: Option<rama_net::tls::DataEncoding>,
                version_for_log: &'static str,
                has_alpn: bool,
            }
            let snapshot = {
                let egress_ssl_ref = egress_tls_stream.ssl_ref();
                let source_cert = egress_ssl_ref
                    .peer_certificate()
                    .ok_or_else(|| {
                        BoxError::from_static_str(
                            "tls mitm relay: egress tls stream has no peer cert",
                        )
                    })
                    .map_err(TlsMitmRelayError::config)?;
                let session_protocol_version =
                    egress_ssl_ref.session().map(|s| s.protocol_version());
                let alpn_proto = egress_ssl_ref
                    .selected_alpn_protocol()
                    .map(ApplicationProtocol::from);
                let peer_cert_chain = if store_server_certificate_chain {
                    match egress_ssl_ref.peer_cert_chain() {
                        Some(chain) => Some(
                            chain.rama_try_into().map_err(TlsMitmRelayError::config)?,
                        ),
                        None => None,
                    }
                } else {
                    None
                };
                let version_for_log = egress_ssl_ref.version_str();
                let has_alpn = egress_ssl_ref.selected_alpn_protocol().is_some();
                EgressHandshakeSnapshot {
                    source_cert,
                    session_protocol_version,
                    alpn_proto,
                    peer_cert_chain,
                    version_for_log,
                    has_alpn,
                }
            };
            // `egress_ssl_ref` borrow is released here.

            let self::issuer::MitmIssuedCert {
                crt_chain: mirrored_leaf_cert_chain,
                key: mirrored_leaf_key,
                ocsp_staple: mirrored_ocsp_staple,
            } = self
                .issuer
                .issue_mitm_x509_cert(snapshot.source_cert)
                .await
                .context("tls mitm relay: mirror server certificate")
                .map_err(TlsMitmRelayError::config)?;

            let mut acceptor_builder =
                SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
                    .context("tls mitm relay: create boring ssl acceptor")
                    .map_err(TlsMitmRelayError::config)?;
            acceptor_builder.set_grease_enabled(self.grease_enabled);
            // Deliberately NOT calling `set_default_verify_paths()`: this
            // acceptor never enables client-certificate verification
            // (`SSL_VERIFY_PEER`), so the OS trust store it would parse is never
            // consulted. Loading it parsed the whole bundle into this
            // per-handshake `SSL_CTX` and kept it resident for the entire
            // connection lifetime — pure waste, and an effective leak when flows
            // are retained. The egress connector installs only the store it
            // needs (see `connector_data`).
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

            // Staple the issuer-signed OCSP `good` response (when one was built
            // for this leaf) so revocation-strict clients accept the re-signed
            // leaf inline. Boring only emits it if the client sent
            // `status_request`, so this is a no-op for clients that don't ask.
            if let Some(staple) = mirrored_ocsp_staple {
                acceptor_builder
                    .set_status_callback(move |ssl| ssl.set_ocsp_status(&staple).map(|()| true))
                    .context("tls mitm relay: set OCSP status callback")
                    .map_err(TlsMitmRelayError::config)?;
            }

            let maybe_negotiated_params =
                if let Some(protocol_version) = snapshot.session_protocol_version {
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
                            BoxError::from_static_str(
                                "boring ssl connector: cast min proto version",
                            )
                            .context_field("protocol_version", v)
                        })
                        .map_err(TlsMitmRelayError::config)?;

                    tracing::debug!(
                        "boring client (connector) protocol version: {protocol_version} (set as min/max)"
                    );

                    let application_layer_protocol = snapshot.alpn_proto.clone();

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
                                            return Err(if error.kind() == ErrorKind::UnexpectedEof
                                            {
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

                    Some(NegotiatedTlsParameters {
                        protocol_version,
                        application_layer_protocol,
                        peer_certificate_chain: snapshot.peer_cert_chain,
                    })
                } else {
                    None
                };

            if let Some(sink) =
                open_intent_sink(&self.keylog_intent).map_err(TlsMitmRelayError::config)?
            {
                acceptor_builder.set_keylog_callback(move |_, line| {
                    let mut buf = String::with_capacity(line.len() + 1);
                    buf.push_str(line);
                    buf.push('\n');
                    sink.write_line(&buf);
                });
            }

            tracing::debug!(
                protocol = ?snapshot.version_for_log,
                has_alpn = snapshot.has_alpn,
                "tls mitm relay: accepting ingress tls handshake with mirrored server hints",
            );

            Ok((acceptor_builder.build(), maybe_negotiated_params, egress_tls_stream))
        }
        .await;

        let (acceptor, maybe_negotiated_params, egress_tls_stream) = match acceptor_build_result {
            Ok(t) => t,
            Err(e) => {
                // Same revert as the egress-handshake-failure path
                // above. See that comment for the full rationale.
                let _ = &mut ingress_stream;
                return Err(e);
            }
        };
        let ingress_boring_ssl_stream = rama_boring_tokio::accept(&acceptor, ingress_stream)
            .await
            .map_err(|err| {
                let maybe_ssl_code = err.code();
                if let Some(io_err) = err.as_io_error() {
                    TlsMitmRelayError::handshake_io(
                        TlsMitmRelayErrorDirection::Ingress,
                        BoxError::from(format!(
                            "tls mitm relay: ingress tls accept failed with io error: {io_err}"
                        ))
                        .context_debug_field("code", maybe_ssl_code),
                    )
                } else if let Some(err) = err.as_ssl_error_stack() {
                    TlsMitmRelayError::handshake_ssl(TlsMitmRelayErrorDirection::Ingress, err)
                } else {
                    TlsMitmRelayError::handshake(
                        TlsMitmRelayErrorDirection::Ingress,
                        BoxError::from_static_str("tls mitm relay: ingress tls accept failed")
                            .context_debug_field("code", maybe_ssl_code),
                        maybe_ssl_code,
                    )
                }
            })?;

        if let Some(negotiated_params) = maybe_negotiated_params {
            #[cfg(feature = "http")]
            if let Some(proto) = negotiated_params.application_layer_protocol.as_ref()
                && let Ok(neg_version) = rama_net::http::Version::try_from(proto)
            {
                egress_tls_stream
                    .extensions()
                    .insert(rama_net::http::TargetHttpVersion(neg_version));
            }

            egress_tls_stream.extensions().insert(negotiated_params);
        }

        let ingress_tls_stream = TlsStream::new(ingress_boring_ssl_stream);
        ingress_tls_stream.extensions().insert(StreamTransformed {
            by: "rama-tls-boring::TlsMitmRelay",
        });
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

#[cfg(test)]
mod tests {
    use super::{
        HandshakeRelayClassification, TlsMitmRelayError, TlsMitmRelayErrorDirection,
        TlsMitmRelayErrorKind, classify_handshake_reasons, reason_is_cert_trust_signal,
    };
    use rama_boring::ssl::ErrorCode;

    // The plaintext TLS Alert helpers (`encode_plain_alert`,
    // `write_plain_alert`) and their wire-format pins live in
    // `mitm::alert::tests` alongside the implementation.

    /// `reason_is_cert_trust_signal` is the load-bearing classifier for
    /// the [`CertTrust`] bucket — the only one that flips an SNI into
    /// a permanent MITM-bypass exception in downstream policy. Edits
    /// to the substring list silently change the classification of
    /// real-world peer alerts; pin the contract here.
    ///
    /// Coverage is walked against the `kOpenSSLReasonStringData` table
    /// shipped by rama-boring-sys (`gen/crypto/err_data.cc`).
    ///
    /// [`CertTrust`]: HandshakeRelayClassification::CertTrust
    #[test]
    fn cert_trust_signal_matches_trust_outcome_reasons() {
        for reason in [
            // Peer alerts that signal trust-validation failure:
            "TLSV1_ALERT_UNKNOWN_CA",
            "SSLV3_ALERT_CERTIFICATE_EXPIRED",
            "SSLV3_ALERT_CERTIFICATE_REVOKED",
            "SSLV3_ALERT_CERTIFICATE_UNKNOWN",
            // Library-side validation outcomes:
            "CERTIFICATE_VERIFY_FAILED",
            "NO_MATCHING_ISSUER",
            // OpenSSL cross-compat (not in current BoringSSL):
            "untrusted_ca",
            "TLSV1_ALERT_UNTRUSTED",
            // Mixed-case sanity:
            "tlsv1_alert_unknown_ca",
        ] {
            assert!(
                reason_is_cert_trust_signal(reason),
                "expected reason {reason:?} to count as a CertTrust signal",
            );
        }
    }

    /// Cert-*shaped* reasons that are *not* trust outcomes (format,
    /// protocol, or our-side config bugs) must classify as
    /// [`TlsProtocol`], not [`CertTrust`]. A regression here would
    /// cause unrelated cert-format issues to permanently cache an SNI
    /// bypass — masking real protocol problems.
    ///
    /// [`TlsProtocol`]: HandshakeRelayClassification::TlsProtocol
    /// [`CertTrust`]: HandshakeRelayClassification::CertTrust
    #[test]
    fn cert_shaped_but_non_trust_reasons_are_not_cert_trust() {
        for reason in [
            // Peer asked us for a client cert / we didn't send one /
            // peer couldn't fetch its cert: peer-protocol, not trust.
            "SSLV3_ALERT_BAD_CERTIFICATE",
            "TLSV1_ALERT_BAD_CERTIFICATE_HASH_VALUE",
            "TLSV1_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE",
            "TLSV1_ALERT_CERTIFICATE_REQUIRED",
            "TLSV1_ALERT_CERTIFICATE_UNOBTAINABLE",
            "SSLV3_ALERT_NO_CERTIFICATE",
            "TLSV1_ALERT_UNKNOWN_CERTIFICATE",
            // Format / type: not a trust decision.
            "SSLV3_ALERT_UNSUPPORTED_CERTIFICATE",
            "TLSV1_ALERT_UNSUPPORTED_CERTIFICATE",
            "UNKNOWN_CERTIFICATE_TYPE",
            "WRONG_CERTIFICATE_TYPE",
            "UNKNOWN_CERT_COMPRESSION_ALG",
            "CERT_DECOMPRESSION_FAILED",
            "CERT_LENGTH_MISMATCH",
            "UNCOMPRESSED_CERT_TOO_LARGE",
            "BAD_ECC_CERT",
            "ECC_CERT_NOT_FOR_SIGNING",
            "INVALID_CERTIFICATE_PROPERTY_LIST",
            "CANNOT_PARSE_LEAF_CERT",
            "PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE",
            // Our-side cert config bugs: would mask the bug if cached.
            "CERTIFICATE_AND_PRIVATE_KEY_MISMATCH",
            "CERT_CB_ERROR",
            "MISSING_RSA_CERTIFICATE",
            "NO_CERTIFICATE_ASSIGNED",
            "NO_CERTIFICATE_SET",
            // Peer protocol behaviour, not trust:
            "PEER_DID_NOT_RETURN_A_CERTIFICATE",
            "NO_CERTIFICATES_RETURNED",
            "TLS_PEER_DID_NOT_RESPOND_WITH_CERTIFICATE_LIST",
            "SERVER_CERT_CHANGED",
        ] {
            assert!(
                !reason_is_cert_trust_signal(reason),
                "cert-shaped non-trust reason {reason:?} must NOT classify as CertTrust",
            );
        }
    }

    /// Non-cert protocol / transport reasons must not classify as
    /// [`CertTrust`].
    ///
    /// [`CertTrust`]: HandshakeRelayClassification::CertTrust
    #[test]
    fn non_cert_reasons_are_not_cert_trust() {
        for reason in [
            "TLSV1_ALERT_HANDSHAKE_FAILURE",
            "TLSV1_ALERT_PROTOCOL_VERSION",
            "TLSV1_ALERT_INTERNAL_ERROR",
            "TLSV1_ALERT_DECRYPT_ERROR",
            "TLSV1_ALERT_DECODE_ERROR",
            "TLSV1_ALERT_RECORD_OVERFLOW",
            "TLSV1_ALERT_INSUFFICIENT_SECURITY",
            "TLSV1_ALERT_INAPPROPRIATE_FALLBACK",
            "TLSV1_ALERT_NO_RENEGOTIATION",
            "TLSV1_ALERT_NO_APPLICATION_PROTOCOL",
            "TLSV1_ALERT_USER_CANCELLED",
            "TLSV1_ALERT_UNKNOWN_PSK_IDENTITY",
            "TLSV1_ALERT_UNRECOGNIZED_NAME",
            "TLSV1_ALERT_UNSUPPORTED_EXTENSION",
            "TLSV1_ALERT_ACCESS_DENIED",
            "TLSV1_ALERT_ECH_REQUIRED",
            "SSLV3_ALERT_HANDSHAKE_FAILURE",
            "SSLV3_ALERT_BAD_RECORD_MAC",
            "SSLV3_ALERT_ILLEGAL_PARAMETER",
            "SSLV3_ALERT_UNEXPECTED_MESSAGE",
            "WRONG_VERSION_NUMBER",
            "NO_SHARED_CIPHER",
            "NO_SHARED_GROUP",
            "NO_APPLICATION_PROTOCOL",
            "HANDSHAKE_FAILURE_ON_CLIENT_HELLO",
            "HANDSHAKE_NOT_COMPLETE",
            "SSL_HANDSHAKE_FAILURE",
            "DOWNGRADE_DETECTED",
            "TLS13_DOWNGRADE",
            "UNEXPECTED_MESSAGE",
            "UNEXPECTED_RECORD",
            "DECRYPTION_FAILED",
            "DECRYPTION_FAILED_OR_BAD_RECORD_MAC",
            "BAD_HANDSHAKE_RECORD",
            "BAD_ALERT",
            "CONNECTION_REJECTED",
            "READ_TIMEOUT_EXPIRED",
            "PROTOCOL_IS_SHUTDOWN",
            "INAPPROPRIATE_FALLBACK",
            "internal_error",
            "",
        ] {
            assert!(
                !reason_is_cert_trust_signal(reason),
                "non-cert reason {reason:?} must NOT classify as CertTrust",
            );
        }
    }

    /// End-to-end classifier behaviour: drives
    /// [`classify_handshake_reasons`] with realistic reason sets and
    /// pins the resulting bucket.
    #[test]
    fn classify_routes_reasons_correctly() {
        // Pure CertTrust bucket — any trust-signal reason wins.
        for reasons in [
            &["TLSV1_ALERT_UNKNOWN_CA"][..],
            &["CERTIFICATE_VERIFY_FAILED"][..],
            &["NO_MATCHING_ISSUER"][..],
            &["SSLV3_ALERT_CERTIFICATE_EXPIRED"][..],
            // Mixed stack: trust signal wins over protocol noise.
            &["TLSV1_ALERT_HANDSHAKE_FAILURE", "TLSV1_ALERT_UNKNOWN_CA"][..],
            &["CERTIFICATE_VERIFY_FAILED", "WRONG_VERSION_NUMBER"][..],
        ] {
            assert_eq!(
                classify_handshake_reasons(reasons.iter().copied()),
                HandshakeRelayClassification::CertTrust,
                "expected {reasons:?} to classify as CertTrust",
            );
        }

        // TlsProtocol bucket — peer engaged / library protocol error,
        // no trust outcome. Includes cert-shaped non-trust reasons
        // that used to land in the (removed) generic `Cert` bucket.
        for reasons in [
            &["TLSV1_ALERT_HANDSHAKE_FAILURE"][..],
            &["TLSV1_ALERT_PROTOCOL_VERSION"][..],
            &["WRONG_VERSION_NUMBER"][..],
            &["NO_SHARED_CIPHER"][..],
            &["SSLV3_ALERT_BAD_CERTIFICATE"][..],
            &["TLSV1_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE"][..],
            &["TLSV1_ALERT_UNKNOWN_CERTIFICATE"][..],
            &["CERT_LENGTH_MISMATCH"][..],
            &["BAD_ECC_CERT"][..],
            &["CERTIFICATE_AND_PRIVATE_KEY_MISMATCH"][..],
            &["UNSUPPORTED_CERTIFICATE"][..],
            &["TLSV1_ALERT_CERTIFICATE_REQUIRED"][..],
            &[
                "WRONG_VERSION_NUMBER",
                "SSLV3_ALERT_BAD_RECORD_MAC",
                "internal_error",
            ][..],
        ] {
            assert_eq!(
                classify_handshake_reasons(reasons.iter().copied()),
                HandshakeRelayClassification::TlsProtocol,
                "expected {reasons:?} to classify as TlsProtocol",
            );
        }

        // Empty input — by contract the function defaults to
        // TlsProtocol (caller is the handshake_ssl path; if we got
        // here we know an SSL error stack existed, even if all
        // reasons were `None`).
        assert_eq!(
            classify_handshake_reasons(std::iter::empty::<&str>()),
            HandshakeRelayClassification::TlsProtocol,
        );
    }

    /// Pin the kind/direction routing of the private factories that
    /// don't need an SSL stack. Together with
    /// [`classify_routes_reasons_correctly`] this covers the full
    /// surface a downstream policy will pattern-match on.
    #[test]
    fn factory_kind_and_direction_routing() {
        // `config` → Config kind, no direction.
        let err = TlsMitmRelayError::config("setup");
        assert_eq!(err.kind(), TlsMitmRelayErrorKind::Config);
        assert_eq!(err.direction(), None);

        // `tls_serve` → TlsServe kind, no direction (bidirectional).
        let err = TlsMitmRelayError::tls_serve("inner");
        assert_eq!(err.kind(), TlsMitmRelayErrorKind::TlsServe);
        assert_eq!(err.direction(), None);

        // `handshake_io` → Transport on both sides.
        for direction in [
            TlsMitmRelayErrorDirection::Ingress,
            TlsMitmRelayErrorDirection::Egress,
        ] {
            let err = TlsMitmRelayError::handshake_io(direction, "io");
            assert_eq!(
                err.kind(),
                TlsMitmRelayErrorKind::Handshake {
                    direction,
                    classification: HandshakeRelayClassification::Transport,
                },
            );
            assert_eq!(err.direction(), Some(direction));
        }

        // `handshake` with `SSL_ERROR_SYSCALL` → Transport
        // (merged "unexpected EOF mid-handshake" bucket).
        let err = TlsMitmRelayError::handshake(
            TlsMitmRelayErrorDirection::Ingress,
            "syscall",
            Some(ErrorCode::SYSCALL),
        );
        assert_eq!(
            err.kind(),
            TlsMitmRelayErrorKind::Handshake {
                direction: TlsMitmRelayErrorDirection::Ingress,
                classification: HandshakeRelayClassification::Transport,
            },
        );

        // `handshake` with no code → Unclassified.
        let err = TlsMitmRelayError::handshake(TlsMitmRelayErrorDirection::Egress, "builder", None);
        assert_eq!(
            err.kind(),
            TlsMitmRelayErrorKind::Handshake {
                direction: TlsMitmRelayErrorDirection::Egress,
                classification: HandshakeRelayClassification::Unclassified,
            },
        );

        // `handshake` with a non-SYSCALL code (e.g. SSL with no stack
        // and no io — shouldn't happen via real boring paths, but
        // pin the defensive default) → Unclassified.
        let err = TlsMitmRelayError::handshake(
            TlsMitmRelayErrorDirection::Ingress,
            "ssl",
            Some(ErrorCode::SSL),
        );
        assert!(matches!(
            err.kind(),
            TlsMitmRelayErrorKind::Handshake {
                classification: HandshakeRelayClassification::Unclassified,
                ..
            }
        ));
    }
}
