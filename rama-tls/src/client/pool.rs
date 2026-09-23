use std::{hash::Hash, sync::LazyLock};

use ahash::RandomState;
use rama_core::extensions::{Extension, Extensions};
use rama_net::{
    address::Host,
    client::pool::{ConnectionReuse, ConnectionReusePolicy},
    tls::{ApplicationProtocol, TlsAlpn},
};
use rama_utils::macros::generate_set_and_with;

use crate::client::{
    ServerVerifyMode, TlsClientAuth, TlsClientConfigProvider, TlsServerCertPins, TlsServerName,
    TlsServerTrust, TlsServerVerify, TlsStoreServerCertChain,
};
use crate::{
    CertificateCompressionAlgorithm, CipherSuite, ExtensionId, KeyLogIntent, ProtocolVersion,
    SignatureScheme, SupportedGroup, TlsKeyLog, TlsSupportedVersions, TlsTunnel,
};

/// Reuse rules published by the connector that performed a TLS handshake.
///
/// Capture request overrides before applying connector defaults, and publish only
/// after a successful handshake. Pools borrow the next request's extensions to
/// check compatibility; callers need not configure the provider on the pool.
/// Connector defaults must remain fixed for the lifetime of its pool. Dynamic
/// or opaque policies must report a non-reusable effective identity.
#[derive(Debug)]
pub struct TlsConnectionReuse<P> {
    provider: P,
    scope: ReuseScope,
    reusable: bool,
}

#[derive(Debug)]
enum ReuseScope {
    Origin(Option<TlsPoolId>),
    Tunnel,
}

impl<P: TlsClientConfigProvider + 'static> TlsConnectionReuse<P> {
    /// Capture the request policy and whether the actual handshake policy is reusable.
    pub fn new(provider: P, request: &Extensions, effective_id: Option<TlsPoolId>) -> Self {
        let identity = provider.pool_id(request);
        Self {
            provider,
            scope: ReuseScope::Origin(identity),
            reusable: identity.is_none_or(|id| id.is_reusable())
                && effective_id.is_none_or(|id| id.is_reusable()),
        }
    }

    /// Capture fixed proxy TLS policy, independently of origin TLS overrides.
    ///
    /// The pool's route key identifies the proxy. Explicit request-level tunnel
    /// configuration requires a fresh connection; route-generated tunnel context
    /// is applied inside the connector and does not appear at pool lookup.
    pub fn tunnel(provider: P, effective_id: Option<TlsPoolId>) -> Self {
        Self {
            provider,
            scope: ReuseScope::Tunnel,
            reusable: effective_id.is_none_or(|id| id.is_reusable()),
        }
    }

    /// Publish this handshake's rules while retaining restrictions from inner layers.
    pub fn publish(self, connection: &Extensions) {
        let tunnel = matches!(self.scope, ReuseScope::Tunnel);
        let policy = ConnectionReuse::new(self);
        let policy = match connection.get_ref::<ConnectionReuse>() {
            Some(inner) => inner.clone().and(policy),
            None => policy,
        };
        // Securing a proxy says nothing about the eventual origin handshake.
        connection.insert(if tunnel {
            policy.into_restriction()
        } else {
            policy
        });
    }
}

impl<P: TlsClientConfigProvider + 'static> ConnectionReusePolicy for TlsConnectionReuse<P> {
    fn is_reusable(&self) -> bool {
        self.reusable
    }

    fn matches(&self, input: &Extensions) -> bool {
        self.reusable
            && match self.scope {
                ReuseScope::Origin(identity) => self.provider.pool_id(input) == identity,
                ReuseScope::Tunnel => !input.contains::<TlsTunnel>(),
            }
    }
}

/// Compact, process-local identity of request-level TLS overrides.
///
/// Construct with [`Self::builder`]. An absent override differs from an explicit
/// default: the latter might replace a different connector default. Equivalent
/// settings have the same identity regardless of the TLS implementation.
///
/// This identifies overrides within a pool with fixed connector defaults. It
/// neither identifies a destination nor authenticates a peer, and is not a stable
/// serialization or a TLS wire fingerprint. Opaque policies cannot be compared
/// by value; pools must check [`Self::is_reusable`] at checkout and return.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
#[extension(tags(tls))]
pub struct TlsPoolId {
    digest: PolicyDigest,
    reusable: bool,
}

impl TlsPoolId {
    /// Begin an identity without request overrides.
    ///
    /// Set the request overrides through the typed builder methods.
    ///
    /// ```
    /// use rama_net::tls::TlsAlpn;
    /// use rama_tls::client::{ServerVerifyMode, TlsPoolId, TlsServerVerify};
    ///
    /// let alpn = TlsAlpn::http_2();
    /// let verify = TlsServerVerify(ServerVerifyMode::Auto);
    /// let id = TlsPoolId::builder()
    ///     .with_alpn(&alpn)
    ///     .with_verify(&verify)
    ///     .build()
    ///     .unwrap();
    /// assert!(id.is_reusable());
    /// ```
    pub fn builder<'a>() -> TlsPoolIdBuilder<'a> {
        TlsPoolIdBuilder {
            overrides: Overrides::default(),
            client_hello: ClientHelloSettings::default(),
            opaque_override: false,
        }
    }

    /// Require a fresh connection that is discarded after use.
    #[must_use]
    pub const fn non_reusable() -> Self {
        Self {
            digest: [0; 2],
            reusable: false,
        }
    }

    /// Whether this identity may participate in connection reuse.
    #[must_use]
    pub const fn is_reusable(&self) -> bool {
        self.reusable
    }
}

// Borrow the common overrides until the identity is built.
#[derive(Default)]
struct Overrides<'a> {
    alpn: Option<&'a TlsAlpn>,
    versions: Option<&'a TlsSupportedVersions>,
    verify: Option<&'a TlsServerVerify>,
    keylog: Option<&'a TlsKeyLog>,
    server_name: Option<&'a TlsServerName>,
    store_chain: Option<&'a TlsStoreServerCertChain>,
    client_auth: Option<&'a TlsClientAuth>,
    server_cert_pins: Option<&'a TlsServerCertPins>,
    server_trust: Option<&'a TlsServerTrust>,
}

// Canonical field ordering is independent of the order of builder calls.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
struct ClientHelloSettings<'a> {
    cipher_suites: Option<&'a [CipherSuite]>,
    supported_groups: Option<&'a [SupportedGroup]>,
    signature_schemes: Option<&'a [SignatureScheme]>,
    grease: Option<bool>,
    alps: Option<AlpsSettings<'a>>,
    extension_order: Option<&'a [ExtensionId]>,
    cert_compression: Option<&'a [CertificateCompressionAlgorithm]>,
    delegated_credentials: Option<&'a [SignatureScheme]>,
    record_size_limit: Option<u16>,
    encrypted_client_hello: Option<bool>,
    ocsp_stapling: Option<bool>,
    signed_cert_timestamps: Option<bool>,
    min_version: Option<ProtocolVersion>,
    max_version: Option<ProtocolVersion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct AlpsSettings<'a> {
    protocols: &'a [ApplicationProtocol],
    new_codepoint: bool,
}

/// Build a backend-independent identity with shared presence and field encoding.
///
/// The builder borrows configuration and allocates no storage. Settings are
/// encoded in one canonical order, independent of setter order. Library adapters
/// should exhaustively destructure their configuration before setting fields,
/// so additions require an explicit pooling decision.
pub struct TlsPoolIdBuilder<'a> {
    overrides: Overrides<'a>,
    client_hello: ClientHelloSettings<'a>,
    opaque_override: bool,
}

impl<'a> TlsPoolIdBuilder<'a> {
    generate_set_and_with! {
        /// Ordered application protocol offer.
        pub fn alpn(mut self, value: Option<&'a TlsAlpn>) -> Self {
            self.overrides.alpn = value;
            self
        }
    }

    generate_set_and_with! {
        /// Ordered supported TLS versions.
        pub fn versions(mut self, value: Option<&'a TlsSupportedVersions>) -> Self {
            self.overrides.versions = value;
            self
        }
    }

    generate_set_and_with! {
        /// Server certificate verification mode.
        pub fn verify(mut self, value: Option<&'a TlsServerVerify>) -> Self {
            self.overrides.verify = value;
            self
        }
    }

    generate_set_and_with! {
        /// Key logging policy; custom sinks prevent reuse.
        pub fn keylog(mut self, value: Option<&'a TlsKeyLog>) -> Self {
            self.overrides.keylog = value;
            self
        }
    }

    generate_set_and_with! {
        /// Explicit server-name override.
        pub fn server_name(mut self, value: Option<&'a TlsServerName>) -> Self {
            self.overrides.server_name = value;
            self
        }
    }

    generate_set_and_with! {
        /// Whether to retain the peer certificate chain.
        pub fn store_chain(mut self, value: Option<&'a TlsStoreServerCertChain>) -> Self {
            self.overrides.store_chain = value;
            self
        }
    }

    generate_set_and_with! {
        /// Client credentials; opaque credentials prevent reuse.
        pub fn client_auth(mut self, value: Option<&'a TlsClientAuth>) -> Self {
            self.overrides.client_auth = value;
            self
        }
    }

    generate_set_and_with! {
        /// Cached server certificate pin policy.
        pub fn server_cert_pins(mut self, value: Option<&'a TlsServerCertPins>) -> Self {
            self.overrides.server_cert_pins = value;
            self
        }
    }

    generate_set_and_with! {
        /// Cached server trust policy.
        pub fn server_trust(mut self, value: Option<&'a TlsServerTrust>) -> Self {
            self.overrides.server_trust = value;
            self
        }
    }

    generate_set_and_with! {
        /// Ordered cipher suite offer.
        pub fn cipher_suites(mut self, value: Option<&'a [CipherSuite]>) -> Self {
            self.client_hello.cipher_suites = value;
            self
        }
    }

    generate_set_and_with! {
        /// Ordered supported group offer.
        pub fn supported_groups(mut self, value: Option<&'a [SupportedGroup]>) -> Self {
            self.client_hello.supported_groups = value;
            self
        }
    }

    generate_set_and_with! {
        /// Ordered signature scheme offer.
        pub fn signature_schemes(mut self, value: Option<&'a [SignatureScheme]>) -> Self {
            self.client_hello.signature_schemes = value;
            self
        }
    }

    generate_set_and_with! {
        /// Whether GREASE values are offered.
        pub fn grease(mut self, value: Option<bool>) -> Self {
            self.client_hello.grease = value;
            self
        }
    }

    generate_set_and_with! {
        /// Ordered extension identifiers.
        pub fn extension_order(mut self, value: Option<&'a [ExtensionId]>) -> Self {
            self.client_hello.extension_order = value;
            self
        }
    }

    generate_set_and_with! {
        /// Ordered certificate compression algorithms.
        pub fn cert_compression(mut self, value: Option<&'a [CertificateCompressionAlgorithm]>) -> Self {
            self.client_hello.cert_compression = value;
            self
        }
    }

    generate_set_and_with! {
        /// Ordered delegated credential signature schemes.
        pub fn delegated_credentials(mut self, value: Option<&'a [SignatureScheme]>) -> Self {
            self.client_hello.delegated_credentials = value;
            self
        }
    }

    generate_set_and_with! {
        /// Advertised record size limit.
        pub fn record_size_limit(mut self, value: Option<u16>) -> Self {
            self.client_hello.record_size_limit = value;
            self
        }
    }

    generate_set_and_with! {
        /// Whether Encrypted ClientHello is enabled.
        pub fn encrypted_client_hello(mut self, value: Option<bool>) -> Self {
            self.client_hello.encrypted_client_hello = value;
            self
        }
    }

    generate_set_and_with! {
        /// Whether OCSP stapling is requested.
        pub fn ocsp_stapling(mut self, value: Option<bool>) -> Self {
            self.client_hello.ocsp_stapling = value;
            self
        }
    }

    generate_set_and_with! {
        /// Whether signed certificate timestamps are requested.
        pub fn signed_cert_timestamps(mut self, value: Option<bool>) -> Self {
            self.client_hello.signed_cert_timestamps = value;
            self
        }
    }

    generate_set_and_with! {
        /// Minimum permitted TLS version.
        pub fn min_version(mut self, value: Option<ProtocolVersion>) -> Self {
            self.client_hello.min_version = value;
            self
        }
    }

    generate_set_and_with! {
        /// Maximum permitted TLS version.
        pub fn max_version(mut self, value: Option<ProtocolVersion>) -> Self {
            self.client_hello.max_version = value;
            self
        }
    }

    generate_set_and_with! {
        /// Offer Application-Layer Protocol Settings for these ordered protocols.
        ///
        /// `new_codepoint` selects the newer ALPS extension codepoint.
        pub fn alps(mut self, protocols: &'a [ApplicationProtocol], new_codepoint: bool) -> Self {
            self.client_hello.alps = Some(AlpsSettings { protocols, new_codepoint });
            self
        }
    }

    generate_set_and_with! {
        /// Remove the Application-Layer Protocol Settings override.
        pub fn no_alps(mut self) -> Self {
            self.client_hello.alps = None;
            self
        }
    }

    generate_set_and_with! {
        /// Mark whether a verifier, native trust store or hook cannot be compared by value.
        ///
        /// Such overrides require a fresh connection. Never substitute an object
        /// address for the semantics of a mutable or opaque policy.
        pub fn opaque_override(mut self, present: bool) -> Self {
            self.opaque_override = present;
            self
        }
    }

    /// Finish the identity, returning `None` when no overrides are present.
    pub fn build(self) -> Option<TlsPoolId> {
        let Overrides {
            alpn,
            versions,
            verify,
            keylog,
            server_name,
            store_chain,
            client_auth,
            server_cert_pins,
            server_trust,
        } = self.overrides;
        if self.opaque_override || client_auth.is_some() {
            return Some(TlsPoolId::non_reusable());
        }
        let keylog = match keylog.map(|value| &value.0) {
            Some(KeyLogIntent::Environment) => Some(ComparableKeyLog::Environment),
            Some(KeyLogIntent::Disabled) => Some(ComparableKeyLog::Disabled),
            Some(KeyLogIntent::File(path)) => Some(ComparableKeyLog::File(path)),
            Some(KeyLogIntent::Custom(_)) => return Some(TlsPoolId::non_reusable()),
            None => None,
        };
        let settings = ComparableOverrides {
            alpn: alpn.map(|value| value.0.as_slice()),
            versions: versions.map(|value| value.0.as_slice()),
            verify: verify.map(|value| value.0),
            keylog,
            server_name: server_name.map(|value| &value.0),
            store_chain: store_chain.map(|value| value.0),
            server_cert_pins,
            server_trust,
            client_hello: self.client_hello,
        };
        (settings != ComparableOverrides::default()).then(|| TlsPoolId {
            digest: policy_digest(b"rama.tls.overrides.v2", &settings),
            reusable: true,
        })
    }
}

#[derive(Default, PartialEq, Eq, Hash)]
struct ComparableOverrides<'a> {
    alpn: Option<&'a [ApplicationProtocol]>,
    versions: Option<&'a [ProtocolVersion]>,
    verify: Option<ServerVerifyMode>,
    keylog: Option<ComparableKeyLog<'a>>,
    server_name: Option<&'a Host>,
    store_chain: Option<bool>,
    server_cert_pins: Option<&'a TlsServerCertPins>,
    server_trust: Option<&'a TlsServerTrust>,
    client_hello: ClientHelloSettings<'a>,
}

#[derive(PartialEq, Eq, Hash)]
enum ComparableKeyLog<'a> {
    Environment,
    Disabled,
    File(&'a str),
}

pub(crate) type PolicyDigest = [u64; 2];

// AHash is already used by Rama. Independently keyed lanes keep this cheap
// local identifier compact without reducing equality to a single 64-bit hash.
// These process-wide keys also keep cached certificate hashes consistent with
// newly built IDs. This is deliberately not a cryptographic digest.
static POLICY_HASHERS: LazyLock<[RandomState; 2]> =
    LazyLock::new(|| [RandomState::new(), RandomState::new()]);

pub(crate) fn policy_digest(domain: &[u8], settings: &impl Hash) -> PolicyDigest {
    POLICY_HASHERS
        .each_ref()
        .map(|state| state.hash_one((domain, settings)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{
        TlsServerCertPin, TlsServerCertPinSet, TlsServerCertPins, TlsServerTrustAnchors,
    };
    use rama_utils::octets::kib;
    use std::hash::Hasher;

    #[derive(Debug, Clone, Copy)]
    struct TestProvider;

    impl TlsClientConfigProvider for TestProvider {
        fn pool_id(&self, extensions: &Extensions) -> Option<TlsPoolId> {
            TlsPoolId::builder()
                .maybe_with_verify(extensions.get_ref::<TlsServerVerify>())
                .maybe_with_server_name(extensions.get_ref::<TlsServerName>())
                .build()
        }

        fn authenticates_server(&self, extensions: &Extensions) -> bool {
            extensions
                .get_ref::<TlsServerVerify>()
                .is_none_or(|verify| verify.0 != ServerVerifyMode::Disable)
        }
    }

    #[test]
    fn established_policy_matches_equal_overrides_in_both_directions() {
        let plain = Extensions::new();
        let insecure = Extensions::new();
        insecure.insert(TlsServerVerify(ServerVerifyMode::Disable));
        let equivalent = Extensions::new();
        equivalent.insert(TlsServerVerify(ServerVerifyMode::Disable));
        let explicit_default = Extensions::new();
        explicit_default.insert(TlsServerVerify(ServerVerifyMode::Auto));

        let default_policy = TlsConnectionReuse::new(TestProvider, &plain, None);
        let insecure_policy =
            TlsConnectionReuse::new(TestProvider, &insecure, TestProvider.pool_id(&insecure));
        assert!(default_policy.matches(&plain));
        assert!(!default_policy.matches(&insecure));
        assert!(!default_policy.matches(&explicit_default));
        assert!(insecure_policy.matches(&equivalent));
        assert!(!insecure_policy.matches(&plain));
        assert!(!insecure_policy.matches(&explicit_default));

        equivalent.insert(TlsServerName(Host::from_static("other.example")));
        assert!(!insecure_policy.matches(&equivalent));
    }

    #[test]
    fn opaque_effective_defaults_prevent_reuse_without_request_overrides() {
        let request = Extensions::new();
        let policy =
            TlsConnectionReuse::new(TestProvider, &request, Some(TlsPoolId::non_reusable()));
        assert!(!policy.is_reusable());
        assert!(!policy.matches(&request));
        let connection = Extensions::new();
        policy.publish(&connection);
        assert!(
            !connection
                .get_ref::<ConnectionReuse>()
                .unwrap()
                .is_reusable()
        );
    }

    #[test]
    fn origin_and_proxy_reuse_restrictions_compose() {
        let request = Extensions::new();
        request.insert(TlsServerVerify(ServerVerifyMode::Disable));
        let connection = Extensions::new();
        TlsConnectionReuse::tunnel(TestProvider, None).publish(&connection);
        assert!(
            !connection
                .get_ref::<ConnectionReuse>()
                .unwrap()
                .is_complete()
        );
        TlsConnectionReuse::new(TestProvider, &request, TestProvider.pool_id(&request))
            .publish(&connection);
        let policy = connection.get_ref::<ConnectionReuse>().unwrap();
        assert!(policy.is_complete());
        for proxy_matches in [false, true] {
            for origin_matches in [false, true] {
                let next = Extensions::new();
                if origin_matches {
                    next.insert(TlsServerVerify(ServerVerifyMode::Disable));
                }
                if !proxy_matches {
                    next.insert(TlsTunnel {
                        server_identity: Some(Host::from_static("proxy.example")),
                        application_protocol: None,
                        alpn: None,
                    });
                }
                assert_eq!(
                    policy.matches(&next),
                    proxy_matches && origin_matches,
                    "proxy_matches={proxy_matches}, origin_matches={origin_matches}"
                );
            }
        }

        let connection = Extensions::new();
        TlsConnectionReuse::tunnel(TestProvider, Some(TlsPoolId::non_reusable()))
            .publish(&connection);
        TlsConnectionReuse::new(TestProvider, &Extensions::new(), None).publish(&connection);
        assert!(
            !connection
                .get_ref::<ConnectionReuse>()
                .unwrap()
                .is_reusable()
        );
    }

    fn id_from_hash(value: &impl Hash) -> TlsPoolId {
        TlsPoolId {
            digest: policy_digest(b"test", value),
            reusable: true,
        }
    }

    #[test]
    fn builder_canonicalizes_setter_order_and_retains_explicit_defaults() {
        let verify = TlsServerVerify(ServerVerifyMode::Auto);
        let store = TlsStoreServerCertChain(false);
        let alpn = TlsAlpn::http_2();
        let keylog = TlsKeyLog(KeyLogIntent::Disabled);

        assert_eq!(TlsPoolId::builder().build(), None);
        let first = TlsPoolId::builder()
            .with_alpn(&alpn)
            .with_verify(&verify)
            .with_store_chain(&store)
            .with_keylog(&keylog)
            .build();
        let second = TlsPoolId::builder()
            .with_keylog(&keylog)
            .with_store_chain(&store)
            .with_verify(&verify)
            .with_alpn(&alpn)
            .build();
        assert_eq!(first, second);
        assert!(first.unwrap().is_reusable());
        assert!(TlsPoolId::builder().with_verify(&verify).build().is_some());
        assert!(
            TlsPoolId::builder()
                .with_store_chain(&store)
                .build()
                .is_some()
        );
        assert!(TlsPoolId::builder().with_keylog(&keylog).build().is_some());
        assert_eq!(
            TlsPoolId::builder()
                .with_verify(&verify)
                .without_verify()
                .build(),
            None
        );
    }

    #[test]
    fn builder_separates_fields_and_preserves_protocol_order() {
        let alpn = TlsAlpn(vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11].into());
        let reversed =
            TlsAlpn(vec![ApplicationProtocol::HTTP_11, ApplicationProtocol::HTTP_2].into());
        assert_ne!(
            TlsPoolId::builder().with_alpn(&alpn).build(),
            TlsPoolId::builder().with_alpn(&reversed).build(),
        );
        assert_ne!(
            TlsPoolId::builder().with_alpn(&TlsAlpn::empty()).build(),
            TlsPoolId::builder().build(),
        );
        assert_ne!(
            TlsPoolId::builder().with_grease(false).build(),
            TlsPoolId::builder()
                .with_encrypted_client_hello(false)
                .build(),
        );
        assert!(TlsPoolId::builder().with_grease(false).build().is_some());
        assert_ne!(
            TlsPoolId::builder().with_cipher_suites(&[]).build(),
            TlsPoolId::builder().build(),
        );
    }

    #[test]
    fn absent_client_hello_settings_do_not_change_common_identity() {
        let verify = TlsServerVerify(ServerVerifyMode::Disable);
        assert_eq!(TlsPoolId::builder().maybe_with_grease(None).build(), None);
        assert_eq!(
            TlsPoolId::builder().with_verify(&verify).build(),
            TlsPoolId::builder()
                .with_verify(&verify)
                .maybe_with_cipher_suites(None)
                .maybe_with_grease(None)
                .build(),
        );
    }

    #[test]
    fn opaque_override_dominates_comparable_settings() {
        let verify = TlsServerVerify(ServerVerifyMode::Disable);
        let alone = TlsPoolId::builder()
            .with_opaque_override(true)
            .build()
            .unwrap();
        let combined = TlsPoolId::builder()
            .with_verify(&verify)
            .with_grease(true)
            .with_opaque_override(true)
            .build()
            .unwrap();
        assert_eq!(alone, combined);
        assert!(!combined.is_reusable());
        assert_eq!(
            TlsPoolId::builder().with_opaque_override(false).build(),
            None
        );
    }

    #[test]
    fn native_setter_order_and_alps_codepoint_are_preserved() {
        let protocols = [ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11];
        let groups = [SupportedGroup::X25519];
        let first = TlsPoolId::builder()
            .with_grease(true)
            .with_supported_groups(&groups)
            .with_alps(&protocols, true)
            .build();
        let reordered = TlsPoolId::builder()
            .with_alps(&protocols, true)
            .with_supported_groups(&groups)
            .with_grease(true)
            .build();
        assert_eq!(first, reordered);
        assert_ne!(
            first,
            TlsPoolId::builder()
                .with_grease(true)
                .with_supported_groups(&groups)
                .with_alps(&protocols, false)
                .build()
        );
        assert_ne!(
            TlsPoolId::builder().with_alps(&protocols, true).build(),
            TlsPoolId::builder()
                .with_alps(&[protocols[1].clone(), protocols[0].clone()], true)
                .build(),
        );
        assert_eq!(
            TlsPoolId::builder()
                .with_alps(&protocols, true)
                .with_no_alps()
                .build(),
            None
        );
    }

    #[test]
    fn compact_identity_preserves_presence_and_reflexive_equality() {
        assert!(std::mem::size_of::<TlsPoolId>() <= 24);
        assert_ne!(id_from_hash(&None::<bool>), id_from_hash(&Some(false)));
        let opaque = TlsPoolId::non_reusable();
        assert_eq!(opaque, opaque);
        assert!(!opaque.is_reusable());
        let known = id_from_hash(&(Some(false), "name.example"));
        assert_eq!(known, id_from_hash(&(Some(false), "name.example")));
        assert!(known.is_reusable());
        assert_ne!(known, opaque);
    }

    #[test]
    fn field_sequences_and_domains_are_unambiguous() {
        assert_ne!(policy_digest(b"one", &42), policy_digest(b"two", &42));
        assert_ne!(id_from_hash(&("ab", "c")), id_from_hash(&("a", "bc")));
    }

    #[test]
    fn cached_certificate_hashes_are_bounded_and_updated_after_mutation() {
        struct ByteCounter(usize);

        impl Hasher for ByteCounter {
            fn finish(&self) -> u64 {
                0
            }

            fn write(&mut self, bytes: &[u8]) {
                self.0 += bytes.len();
            }
        }

        let large = vec![7; kib(64)];
        let pins = TlsServerCertPins::new(TlsServerCertPin::ExactDer(large.clone().into()));
        let anchors = TlsServerTrustAnchors::try_new([large.clone().into()]).unwrap();
        let mut counter = ByteCounter(0);
        pins.hash(&mut counter);
        anchors.hash(&mut counter);
        assert!(
            counter.0 <= 80,
            "certificate bytes were rehashed: {}",
            counter.0
        );
        assert_eq!(
            pins,
            TlsServerCertPins::new(TlsServerCertPin::ExactDer(large.clone().into()))
        );
        assert_eq!(
            anchors,
            TlsServerTrustAnchors::try_new([large.into()]).unwrap()
        );

        let original_id = id_from_hash(&pins);
        let changed = pins
            .clone()
            .with_pin_set(TlsServerCertPin::SpkiSha256([8; 32]));
        assert_eq!(original_id, id_from_hash(&pins));
        assert_ne!(original_id, id_from_hash(&changed));
        assert_eq!(
            id_from_hash(&changed),
            id_from_hash(&pins.with_pin_set(TlsServerCertPin::SpkiSha256([8; 32])))
        );

        let scoped = |name: &str| {
            TlsServerCertPins::new(
                TlsServerCertPinSet::new(TlsServerCertPin::SpkiSha256([1; 32]))
                    .with_server_name(name.parse::<rama_net::address::Host>().unwrap()),
            )
        };
        let lower = scoped("example.test");
        let upper = scoped("EXAMPLE.TEST");
        assert_eq!(lower, upper);
        assert_eq!(id_from_hash(&lower), id_from_hash(&upper));
    }
}
