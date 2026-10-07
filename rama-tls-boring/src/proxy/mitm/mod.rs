use moka::future::Cache;
use rama_boring::{
    pkey::{PKey, Private},
    ssl::ErrorCode,
    x509::X509,
};
use rama_boring_tokio::SslErrorStack;
use rama_core::{
    Layer,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    telemetry::tracing,
};
use rama_net::{
    address::{Domain, Host, HostWithPort},
    tls::ApplicationProtocol,
};
use rama_tls::{
    CertificateCompressionAlgorithm, KeyLogIntent, ProtocolVersion, client::TlsServerIdentity,
    server::SelfSignedCaConfig,
};
use rama_utils::str::any_submatch_ignore_ascii_case;
use std::{fmt, num::NonZeroU64, slice, sync::Arc, time::Duration};

use crate::certificate_compression::add_certificate_compressors;
use crate::core::ssl::{
    ExtensionType, SslAcceptor, SslMethod, SslOptions, SslRef, SslSessionCacheMode, SslVersion,
};
use crate::server::select_alpn_by_server_preference;
use rama_tls::keylog::{KeyLogSink, open_intent_sink};

// Plaintext alert injection remains disabled: transport close preserves
// intercepted clients' established retry behavior.
// mod alert;

pub mod issuer;

pub mod revocation;

mod egress;
pub use self::egress::TlsMitmEgressServerAuth;

pub mod client_auth;
use client_auth::TlsMitmClientAuthPolicy;

mod handshake;
mod service;
pub use self::service::TlsMitmRelayService;

/// Bounds for the relay's cache of ready-to-use ingress acceptors.
///
/// One entry is a built `SSL_CTX` keyed by the upstream cert, negotiated
/// version/ALPN and whether ingress authentication is configured. Repeat
/// connections to a known host skip certificate installation and the private key check entirely.
/// `max_size` caps memory regardless of how many distinct hosts are seen;
/// `ttl` bounds how long a stale keylog sink or rotated CA can linger.
#[derive(Debug, Clone, Copy)]
pub struct MitmAcceptorCacheConfig {
    pub max_size: NonZeroU64,
    pub ttl: Duration,
}

impl Default for MitmAcceptorCacheConfig {
    fn default() -> Self {
        Self {
            max_size: ACCEPTOR_CACHE_DEFAULT_MAX_SIZE,
            ttl: ACCEPTOR_CACHE_DEFAULT_TTL,
        }
    }
}

const ACCEPTOR_CACHE_DEFAULT_MAX_SIZE: NonZeroU64 =
    NonZeroU64::new(1_024).expect("NonZeroU64: 1_024 != 0");
const ACCEPTOR_CACHE_DEFAULT_TTL: Duration = Duration::from_hours(1);

/// Everything an ingress acceptor is built from, besides relay-wide settings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AcceptorKey {
    /// Signature bytes of the upstream leaf: same key as the cert issuer cache.
    upstream_signature: Arc<[u8]>,
    protocol_version: Option<ProtocolVersion>,
    alpn: Option<ApplicationProtocol>,
    certificate_compression: Option<CertificateCompressionAlgorithm>,
    ingress_auth: bool,
}

#[derive(Clone)]
/// A utility that can be used by MITM services such as transparent proxies,
/// in order to relay (and MITM) a TLS connection between a client and server,
/// as part of a deep protocol inspection protocol (DPI) flow.
///
/// Client authentication is opt-in through [`client_auth::TlsMitmClientAuthPolicy`].
/// Without a policy, upstream certificate requests are rejected.
///
/// With the `http` feature, a per-flow `TargetHttpVersion` is a best-effort
/// preference. The relay narrows its upstream ALPN offer only when a peeked
/// ingress ClientHello can negotiate the same protocol (or when HTTP/1.1 is
/// its natural no-ALPN fallback). Otherwise the preference is ignored because
/// this TLS relay does not translate HTTP versions and the intercepted client
/// remains authoritative. Upstream negotiation may also decline the preferred
/// protocol. Without an applicable preference, normal ClientHello mirroring
/// and upstream negotiation decide the concrete HTTP version.
pub struct TlsMitmRelay<Issuer> {
    issuer: Issuer,
    grease_enabled: bool,
    keylog_intent: KeyLogIntent,
    egress_server_auth: Option<TlsMitmEgressServerAuth>,
    client_auth: Option<TlsMitmClientAuthPolicy>,
    handshake_timeout: Option<Duration>,
    acceptors: Option<Cache<AcceptorKey, SslAcceptor>>,
}

impl<Issuer: fmt::Debug> fmt::Debug for TlsMitmRelay<Issuer> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsMitmRelay")
            .field("issuer", &self.issuer)
            .field("grease_enabled", &self.grease_enabled)
            .field("keylog_intent", &self.keylog_intent)
            .field("egress_server_auth", &self.egress_server_auth)
            .field("client_auth", &self.client_auth)
            .field("handshake_timeout", &self.handshake_timeout)
            .field(
                "acceptors",
                &self.acceptors.as_ref().map(|cache| cache.policy()),
            )
            .finish()
    }
}

impl<Issuer> TlsMitmRelay<Issuer> {
    #[inline(always)]
    /// Create a new [`TlsMitmRelay`].
    pub fn new(issuer: Issuer) -> Self {
        Self {
            issuer,
            grease_enabled: true,
            keylog_intent: KeyLogIntent::Environment,
            egress_server_auth: None,
            client_auth: None,
            handshake_timeout: Some(Duration::from_secs(30)),
            acceptors: Some(build_acceptor_cache(MitmAcceptorCacheConfig::default())),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Opt into client-authentication policy. A flow policy overrides this default.
        /// Without one, upstream certificate requests are rejected.
        pub fn client_auth(mut self, policy: Option<TlsMitmClientAuthPolicy>) -> Self {
            self.client_auth = policy;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Bound both handshakes, policy lookups and certificate issuance together.
        /// Defaults to 30 seconds. `without_handshake_timeout` delegates deadlines to the caller.
        pub fn handshake_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.handshake_timeout = timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Bound the cache of ready-to-use ingress acceptors, or disable it
        /// with `None` so every intercepted connection builds its own.
        ///
        /// Enabled by default with [`MitmAcceptorCacheConfig::default`].
        pub fn acceptor_cache(mut self, cfg: Option<MitmAcceptorCacheConfig>) -> Self {
            self.acceptors = cfg.map(build_acceptor_cache);
            self
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

    rama_utils::macros::generate_set_and_with! {
        /// Set the optional server-authentication policy for upstream TLS.
        ///
        /// This policy controls only upstream certificate and identity
        /// verification. It cannot override the ClientHello fingerprint,
        /// protocol negotiation, client authentication, or key logging.
        ///
        /// Upstream certificate verification is disabled by default, both with
        /// no policy and for [`TlsMitmEgressServerAuth::default`]. This preserves
        /// transparent relay behavior for certificates the intercepted client
        /// may choose to accept. Select
        /// [`rama_tls::client::ServerVerifyMode::Auto`] explicitly to enforce
        /// upstream certificate and hostname verification.
        ///
        /// Direct [`Self::handshake`] calls apply this policy when their
        /// `connector_data` argument is `None`. Explicit connector data is
        /// authoritative because it is already a fully-resolved backend
        /// configuration; [`TlsMitmRelayService`] supplies such data only after
        /// applying this policy itself.
        pub fn egress_server_auth(mut self, policy: Option<TlsMitmEgressServerAuth>) -> Self {
            self.egress_server_auth = policy;
            self
        }
    }

    /// Borrow the configured upstream server-authentication policy, if any.
    #[must_use]
    pub fn egress_server_auth_ref(&self) -> Option<&TlsMitmEgressServerAuth> {
        self.egress_server_auth.as_ref()
    }
}

fn build_acceptor_cache(cfg: MitmAcceptorCacheConfig) -> Cache<AcceptorKey, SslAcceptor> {
    Cache::builder()
        .max_capacity(cfg.max_size.get())
        .time_to_live(cfg.ttl)
        .build()
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
    pub fn try_new_with_self_signed_issuer(data: &SelfSignedCaConfig) -> Result<Self, BoxError> {
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
    pub fn try_new_with_cached_self_signed_issuer(
        data: &SelfSignedCaConfig,
    ) -> Result<Self, BoxError> {
        let issuer = self::issuer::InMemoryBoringMitmCertIssuer::try_new_self_signed(data)?;
        Ok(Self::new_with_cached_issuer(issuer))
    }

    #[inline(always)]
    /// Create a new [`TlsMitmRelay`] with self-signed CA using the given data,
    /// with a cache layer (created by given config)
    /// on top to provide reuse functionality of previously issued certs.
    pub fn try_new_with_cached_self_signed_issuer_and_config(
        data: &SelfSignedCaConfig,
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

    fn client_auth(error: impl Into<BoxError>) -> Self {
        let mut error = Self::config(error);
        error.kind = TlsMitmRelayErrorKind::ClientAuth;
        error
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
    /// Returns `None` for setup, policy, timeout and post-handshake serving errors.
    #[inline(always)]
    pub fn direction(&self) -> Option<TlsMitmRelayErrorDirection> {
        match self.kind {
            TlsMitmRelayErrorKind::Handshake { direction, .. } => Some(direction),
            TlsMitmRelayErrorKind::Config
            | TlsMitmRelayErrorKind::TlsServe
            | TlsMitmRelayErrorKind::Timeout
            | TlsMitmRelayErrorKind::ClientAuth => None,
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
    /// A client-authentication policy rejected the flow, failed to configure it,
    /// or either ingress peer rejected the other's certificate. Never a bypass hint.
    ClientAuth,
    /// The deadline for the complete relay handshake or authentication policy elapsed.
    Timeout,
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

/// Project a TLS server identity onto the DNS-only SNI namespace.
///
/// IP identities remain valid for certificate verification and pin scoping but
/// must never be serialized as SNI.
fn server_name_as_sni(server_name: &Host) -> Option<Domain> {
    match TlsServerIdentity::try_from(server_name).ok()? {
        TlsServerIdentity::Dns(domain) => Some(domain.into_owned()),
        TlsServerIdentity::Ip(_) => None,
    }
}

impl<Issuer> TlsMitmRelay<Issuer>
where
    Issuer: self::issuer::BoringMitmCertIssuer<Error: Into<BoxError>>,
{
    /// Mint the ingress acceptor for one upstream cert: mirror the leaf, then
    /// build an `SSL_CTX` pinned to the egress-negotiated protocol version and
    /// ALPN. Cached per [`AcceptorKey`] when the acceptor cache is enabled.
    async fn mint_acceptor(
        &self,
        source_cert: X509,
        protocol_version: Option<SslVersion>,
        alpn: Option<ApplicationProtocol>,
        certificate_compression: Option<CertificateCompressionAlgorithm>,
        ingress_auth: bool,
    ) -> Result<SslAcceptor, TlsMitmRelayError> {
        let self::issuer::MitmIssuedCert {
            crt_chain: mirrored_leaf_cert_chain,
            key: mirrored_leaf_key,
            ocsp_staple: mirrored_ocsp_staple,
        } = self
            .issuer
            .issue_mitm_x509_cert(source_cert)
            .await
            .context("tls mitm relay: mirror server certificate")
            .map_err(TlsMitmRelayError::config)?;

        let mut acceptor_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
            .context("tls mitm relay: create boring ssl acceptor")
            .map_err(TlsMitmRelayError::config)?;
        acceptor_builder.set_grease_enabled(self.grease_enabled);
        // Authentication policy is applied per SSL, never to cached contexts.
        if ingress_auth {
            acceptor_builder.set_session_cache_mode(SslSessionCacheMode::OFF);
            acceptor_builder.set_options(SslOptions::NO_TICKET);
        }
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

        // Compress exactly as the upstream did, which the client offered to accept.
        add_certificate_compressors(&mut acceptor_builder, certificate_compression.as_slice())
            .context("tls mitm relay: certificate compression")
            .map_err(TlsMitmRelayError::config)?;

        // A server answers ALPS only on the codepoint it uses, so follow the client.
        acceptor_builder.set_select_certificate_callback(|mut hello| {
            let new_codepoint = hello
                .get_extension(ExtensionType::APPLICATION_SETTINGS)
                .is_some();
            hello.ssl_mut().set_alps_use_new_codepoint(new_codepoint);
            Ok(())
        });

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

        if let Some(protocol_version) = protocol_version {
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
            tracing::debug!(
                "boring client (connector) protocol version: {protocol_version:?} (set as min/max)"
            );

            if let Some(selected_alpn_protocol) = alpn {
                tracing::debug!(
                    "boring client (connector) has selected ALPN {selected_alpn_protocol}"
                );

                acceptor_builder.set_alpn_select_callback(
                    move |_: &mut SslRef, client_alpns: &[u8]| {
                        select_alpn_by_server_preference(
                            slice::from_ref(&selected_alpn_protocol),
                            client_alpns,
                        )
                    },
                );
            }
        }

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

        Ok(acceptor_builder.build())
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
    use std::assert_matches;

    // The plaintext TLS Alert helpers (`encode_plain_alert`,
    // `write_plain_alert`) and their wire-format pins live in
    // `mitm::alert::tests` alongside the implementation.

    /// `reason_is_cert_trust_signal` is the classifier for
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
        assert_matches!(
            err.kind(),
            TlsMitmRelayErrorKind::Handshake {
                classification: HandshakeRelayClassification::Unclassified,
                ..
            },
        );
    }
}
