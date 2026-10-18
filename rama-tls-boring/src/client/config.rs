use itertools::Itertools;
use rama_boring::{
    ssl::{GreaseValues, Padding, UnknownValues},
    x509::store::X509Store,
};
use rama_core::bytes::Bytes;
use rama_core::conversion::RamaFrom;
use rama_core::extensions::{Extension, Extensions, FromExtensions};
use rama_net::{
    client::pool::ReuseKey,
    tls::{ApplicationProtocol, TlsAlpn},
};
#[cfg(test)]
use rama_tls::KeyLogIntent;
use rama_tls::client::{
    ClientHandshake, ClientHello, ClientHelloExtension, ECHClientHello, ServerVerifyMode,
    TlsClientAuth, TlsClientConfig, TlsClientConfigProvider, TlsComponentIdentity,
    TlsPoolComponent, TlsPoolId, TlsServerCertPins, TlsServerName, TlsServerTrust, TlsServerVerify,
    TlsSessionProfileScope, TlsStoreServerCertChain, TlsStoreServerHello,
};
use rama_tls::{
    CertificateCompressionAlgorithm, CipherSuite, ExtensionId, ProtocolVersion, SignatureScheme,
    SupportedGroup, TlsKeyLog, TlsSupportedVersions,
};
use rama_utils::macros::generate_set_and_with;
use std::sync::Arc;

#[cfg(feature = "http")]
use rama_utils::collections::smallvec::smallvec;

use super::{BoringRequestedTrustAnchors, TlsClientSessionDomain, ech::EchGrease};
use crate::RamaTlsBoringCrateMarker;

/// Gather all the TLS extensions supported by boringssl
#[derive(Clone, FromExtensions)]
pub struct BoringTlsConnectorConfig<'a> {
    pub session_domain: Option<&'a TlsClientSessionDomain>,
    pub session_profile_scope: Option<&'a TlsSessionProfileScope>,
    pub client_handshake: Option<&'a ClientHandshake>,
    pub alpn: Option<&'a TlsAlpn>,
    pub versions: Option<&'a TlsSupportedVersions>,
    pub verify: Option<&'a TlsServerVerify>,
    pub keylog: Option<&'a TlsKeyLog>,
    pub server_name: Option<&'a TlsServerName>,
    pub store_chain: Option<&'a TlsStoreServerCertChain>,
    pub store_server_hello: Option<&'a TlsStoreServerHello>,
    pub client_auth: Option<&'a TlsClientAuth>,
    pub server_cert_pins: Option<&'a TlsServerCertPins>,
    pub server_trust: Option<&'a TlsServerTrust>,
    pub cipher_suites: Option<&'a BoringCipherSuites>,
    pub supported_groups: Option<&'a BoringSupportedGroups>,
    pub key_shares: Option<&'a BoringKeyShares>,
    pub signature_schemes: Option<&'a BoringSignatureSchemes>,
    pub grease: Option<&'a BoringGrease>,
    pub grease_signature_schemes: Option<&'a BoringGreaseSignatureSchemes>,
    pub alps: Option<&'a BoringAlps>,
    pub extension_order: Option<&'a BoringExtensionOrder>,
    pub permute_extensions: Option<&'a BoringPermuteExtensions>,
    pub unknown_values: Option<&'a BoringUnknownValues>,
    pub grease_values: Option<&'a BoringGreaseValues>,
    pub client_hello_padding: Option<&'a BoringClientHelloPadding>,
    pub legacy_extensions: Option<&'a BoringLegacyExtensions>,
    pub extension_bodies: Option<&'a BoringExtensionBodies>,
    pub requested_trust_anchors: Option<&'a BoringRequestedTrustAnchors>,
    pub cert_compression: Option<&'a BoringCertCompression>,
    pub delegated_credentials: Option<&'a BoringDelegatedCredentials>,
    pub record_size_limit: Option<&'a BoringRecordSizeLimit>,
    pub server_padding_request: Option<&'a BoringServerPaddingRequest>,
    pub encrypted_client_hello: Option<&'a BoringEncryptedClientHello>,
    pub ech_grease: Option<&'a EchGrease>,
    pub ocsp_stapling: Option<&'a BoringOcspStapling>,
    pub signed_cert_timestamps: Option<&'a BoringSignedCertTimestamps>,
    pub tls12_session_tickets: Option<&'a BoringTls12SessionTickets>,
    pub verify_cert_store: Option<Arc<BoringServerVerifyCertStore>>,
    pub min_version: Option<&'a BoringMinVersion>,
    pub max_version: Option<&'a BoringMaxVersion>,
}

impl BoringTlsConnectorConfig<'_> {
    /// Compact identity of request-level overrides, or `None` for the baseline.
    ///
    /// Explicit defaults remain distinct from absence. Equivalent settings compare
    /// independently of the TLS implementation. Shared stores and log sinks reuse
    /// connections while retaining their original instance identity.
    /// Connector defaults are fixed for the lifetime of the pool and must not
    /// be layered onto this request-only view.
    pub fn pool_id(&self) -> Option<TlsPoolId> {
        self.pool_id_with_cipher_suites(self.cipher_suites.map(|value| value.0.as_slice()))
    }

    fn pool_id_with_cipher_suites(&self, ciphers: Option<&[CipherSuite]>) -> Option<TlsPoolId> {
        if self.is_empty() {
            return None;
        }
        let Self {
            session_domain,
            session_profile_scope,
            client_handshake: _,
            alpn,
            versions,
            verify,
            keylog,
            server_name,
            store_chain,
            store_server_hello,
            client_auth,
            server_cert_pins,
            server_trust,
            cipher_suites: _,
            supported_groups,
            key_shares,
            signature_schemes,
            grease,
            grease_signature_schemes,
            alps,
            extension_order,
            permute_extensions,
            unknown_values,
            grease_values,
            client_hello_padding,
            legacy_extensions,
            extension_bodies,
            requested_trust_anchors,
            cert_compression,
            delegated_credentials,
            record_size_limit,
            server_padding_request,
            encrypted_client_hello,
            ech_grease,
            ocsp_stapling,
            signed_cert_timestamps,
            tls12_session_tickets,
            verify_cert_store,
            min_version,
            max_version,
        } = self;
        let mut builder = TlsPoolId::builder()
            .maybe_with_alpn(*alpn)
            .maybe_with_versions(*versions)
            .maybe_with_verify(*verify)
            .maybe_with_keylog(*keylog)
            .maybe_with_server_name(*server_name)
            .maybe_with_store_chain(*store_chain)
            .maybe_with_store_server_hello(*store_server_hello)
            .maybe_with_client_auth(*client_auth)
            .maybe_with_server_cert_pins(*server_cert_pins)
            .maybe_with_server_trust(*server_trust)
            .maybe_with_cipher_suites(ciphers)
            .maybe_with_supported_groups(supported_groups.map(|value| value.0.as_slice()))
            .maybe_with_key_shares(key_shares.map(|value| value.0.as_slice()))
            .maybe_with_signature_schemes(signature_schemes.map(|value| value.0.as_slice()))
            .maybe_with_grease(grease.map(|value| value.0))
            .maybe_with_grease_signature_schemes(grease_signature_schemes.map(|value| value.0))
            .maybe_with_extension_order(extension_order.map(|value| value.0.as_slice()))
            .maybe_with_permute_extensions(permute_extensions.map(|value| value.0))
            .maybe_with_cert_compression(cert_compression.map(|value| value.0.as_slice()))
            .maybe_with_delegated_credentials(delegated_credentials.map(|value| value.0.as_slice()))
            .maybe_with_record_size_limit(record_size_limit.map(|value| value.0))
            .maybe_with_encrypted_client_hello(encrypted_client_hello.map(|value| value.0))
            .maybe_with_ocsp_stapling(ocsp_stapling.map(|value| value.0))
            .maybe_with_signed_cert_timestamps(signed_cert_timestamps.map(|value| value.0))
            .maybe_with_tls12_session_tickets(tls12_session_tickets.map(|value| value.0))
            .maybe_with_min_version(min_version.map(|value| value.0))
            .maybe_with_max_version(max_version.map(|value| value.0));
        if let Some(shape) = ech_grease {
            builder.set_component(*shape);
        }
        if let Some(domain) = session_domain {
            builder.set_component(*domain);
        }
        if let Some(scope) = session_profile_scope {
            builder.set_component(*scope);
        }
        if let Some(store) = verify_cert_store {
            builder.set_component(store.as_ref());
        }
        if let Some(policy) = unknown_values {
            builder.set_component(*policy);
        }
        if let Some(values) = grease_values {
            builder.set_component(*values);
        }
        if let Some(padding) = client_hello_padding {
            builder.set_component(*padding);
        }
        if let Some(request) = server_padding_request {
            builder.set_component(*request);
        }
        if let Some(legacy) = legacy_extensions {
            builder.set_component(*legacy);
        }
        if let Some(bodies) = extension_bodies {
            builder.set_component(*bodies);
        }
        if let Some(anchors) = requested_trust_anchors {
            match anchors.extension_body() {
                Some(body) => builder.set_requested_trust_anchors(body),
                None => builder.set_omitted_trust_anchors(),
            };
        }

        if let Some(alps) = alps {
            builder.set_alps(&alps.protocols, alps.new_codepoint);
        }
        builder.build()
    }

    /// Identity of compatible client sessions: security settings, the non-GREASE
    /// cipher list, the session domain and the optional profile scope. Other wire
    /// settings, diagnostic sinks, chain retention and the separately keyed server
    /// name are not part of it, so sessions resume across those variants.
    pub fn session_scope(&self) -> Option<TlsPoolId> {
        self.security_pool_id(None)
    }

    /// What a native context is keyed by: the session scope and the keylog, the only
    /// context-level setting outside it. Wire settings are applied per connection.
    pub(crate) fn context_scope(&self) -> Option<TlsPoolId> {
        self.security_pool_id(self.keylog)
    }

    fn security_pool_id(&self, keylog: Option<&TlsKeyLog>) -> Option<TlsPoolId> {
        let security = self.security_policy(keylog);
        let ciphers = security.cipher_suites.map(|value| value.0.as_slice());
        // GREASE cannot be negotiated. Its literal draw affects the wire and
        // connection-pool identity, but not a ticket's compatible cipher policy.
        // Ordinary lists borrow directly; only GREASE lists need a filtered copy.
        let filtered = ciphers
            .filter(|values| values.iter().any(CipherSuite::is_grease))
            .map(|values| {
                values
                    .iter()
                    .copied()
                    .filter(|value| !value.is_grease())
                    .collect::<Vec<_>>()
            });
        security.pool_id_with_cipher_suites(filtered.as_deref().or(ciphers))
    }

    /// The security part only: wire settings are per connection, so sessions and native
    /// contexts are shared across them.
    fn security_policy<'a>(&self, keylog: Option<&'a TlsKeyLog>) -> BoringTlsConnectorConfig<'a>
    where
        Self: 'a,
    {
        static DEFAULT_VERIFY: TlsServerVerify = TlsServerVerify(ServerVerifyMode::Auto);
        // New fields must also be reviewed for whether they are security or wire.
        let Self {
            session_domain,
            session_profile_scope,
            client_handshake: _,
            alpn: _,
            versions: _,
            verify,
            keylog: _,
            server_name: _,
            store_chain: _,
            store_server_hello: _,
            client_auth,
            server_cert_pins,
            server_trust,
            cipher_suites,
            supported_groups: _,
            key_shares: _,
            signature_schemes: _,
            grease: _,
            grease_signature_schemes: _,
            alps: _,
            extension_order: _,
            permute_extensions: _,
            unknown_values: _,
            grease_values: _,
            client_hello_padding: _,
            legacy_extensions: _,
            extension_bodies: _,
            requested_trust_anchors: _,
            cert_compression: _,
            delegated_credentials: _,
            record_size_limit: _,
            server_padding_request: _,
            encrypted_client_hello: _,
            ech_grease: _,
            ocsp_stapling: _,
            signed_cert_timestamps: _,
            tls12_session_tickets: _,
            verify_cert_store,
            min_version: _,
            max_version: _,
        } = self.clone();
        // The mandatory verification policy makes normal configurations nonempty.
        // A missing or non-reusable identity must get an isolated native domain.
        BoringTlsConnectorConfig {
            session_domain,
            session_profile_scope,
            client_handshake: None,
            alpn: None,
            versions: None,
            verify: Some(verify.unwrap_or(&DEFAULT_VERIFY)),
            keylog,
            server_name: None,
            store_chain: None,
            store_server_hello: None,
            client_auth,
            server_cert_pins,
            server_trust,
            // A resumed TLS 1.2 session keeps its cipher, which the client rejects when its
            // own list lacks it.
            cipher_suites,
            supported_groups: None,
            key_shares: None,
            signature_schemes: None,
            grease: None,
            grease_signature_schemes: None,
            alps: None,
            extension_order: None,
            permute_extensions: None,
            unknown_values: None,
            grease_values: None,
            client_hello_padding: None,
            legacy_extensions: None,
            extension_bodies: None,
            requested_trust_anchors: None,
            cert_compression: None,
            delegated_credentials: None,
            record_size_limit: None,
            server_padding_request: None,
            encrypted_client_hello: None,
            ech_grease: None,
            ocsp_stapling: None,
            signed_cert_timestamps: None,
            tls12_session_tickets: None,
            verify_cert_store,
            min_version: None,
            max_version: None,
        }
    }

    /// Whether a successful handshake establishes the configured server identity.
    pub fn authenticates_server(&self) -> bool {
        // New fields must also be reviewed for their effect on authentication.
        let Self {
            session_domain: _,
            session_profile_scope: _,
            client_handshake: _,
            alpn: _,
            versions: _,
            verify,
            keylog: _,
            server_name: _,
            store_chain: _,
            store_server_hello: _,
            client_auth: _,
            server_cert_pins: _,
            server_trust: _,
            cipher_suites: _,
            supported_groups: _,
            key_shares: _,
            signature_schemes: _,
            grease: _,
            grease_signature_schemes: _,
            alps: _,
            extension_order: _,
            permute_extensions: _,
            unknown_values: _,
            grease_values: _,
            client_hello_padding: _,
            legacy_extensions: _,
            extension_bodies: _,
            requested_trust_anchors: _,
            cert_compression: _,
            delegated_credentials: _,
            record_size_limit: _,
            server_padding_request: _,
            encrypted_client_hello: _,
            ech_grease: _,
            ocsp_stapling: _,
            signed_cert_timestamps: _,
            tls12_session_tickets: _,
            verify_cert_store: _,
            min_version: _,
            max_version: _,
        } = self;

        verify.is_none_or(|verify| verify.0 != ServerVerifyMode::Disable)
    }
}

/// Boring-specific setters for [`TlsClientConfig`].
pub trait BoringClientConfigExt: Sized {
    /// Create a new config that mimics the provided [`ClientHello`]
    fn new_from_client_hello(hello: &ClientHello) -> Self;

    generate_set_and_with! {
        /// Layer the fingerprint pieces captured in a [`ClientHello`] onto this config.
        fn mimic_client_hello(self, hello: &ClientHello) -> Self;
    }

    generate_set_and_with! {
        /// Set the cipher suites to offer, in order.
        fn cipher_suites(self, suites: Vec<CipherSuite>) -> Self;
    }
    generate_set_and_with! {
        /// Set the supported groups (named curves), in order.
        fn supported_groups(self, groups: Vec<SupportedGroup>) -> Self;
    }
    generate_set_and_with! {
        /// Send key shares for exactly these groups, in order.
        ///
        /// Groups missing from the offered groups, or out of their order, are skipped.
        /// Without this, BoringSSL sends at most two, at most one post-quantum.
        fn key_shares(self, groups: Vec<SupportedGroup>) -> Self;
    }
    generate_set_and_with! {
        /// Set the signature schemes to advertise, in order.
        fn signature_schemes(self, schemes: Vec<SignatureScheme>) -> Self;
    }
    generate_set_and_with! {
        /// Enable/disable GREASE injection.
        fn grease(self, enabled: bool) -> Self;
    }
    generate_set_and_with! {
        /// Lead the signature schemes with a GREASE value (default: disabled).
        ///
        /// Independent of [`grease`](BoringClientConfigExt::set_grease).
        fn grease_signature_schemes(self, enabled: bool) -> Self;
    }
    generate_set_and_with! {
        /// Set Application-Layer Protocol Settings (ALPS).
        fn alps(self, protocols: Vec<ApplicationProtocol>, new_codepoint: bool) -> Self;
    }
    generate_set_and_with! {
        /// Set the ClientHello extension prefix order; unlisted extensions follow.
        /// With GREASE on, an order naming no GREASE codepoint gets the native slots,
        /// first and last; an empty order keeps the native layout.
        fn extension_order(self, order: Vec<ExtensionId>) -> Self;
    }
    generate_set_and_with! {
        /// Permute the extension order for every handshake (default: disabled),
        /// as Chromium-based browsers do.
        ///
        /// Takes precedence over an explicit [`extension_order`], which still
        /// applies once permutation is disabled again. Native GREASE, padding
        /// and pre-shared-key placement rules remain in force.
        ///
        /// [`extension_order`]: BoringClientConfigExt::set_extension_order
        fn permute_extensions(self, enabled: bool) -> Self;
    }
    generate_set_and_with! {
        /// What to do with listed values BoringSSL cannot negotiate (groups, signature
        /// schemes, extensions): drop them (the default), send them as listed
        /// ([`UnknownValues::Preserve`]: a server that selects or answers one fails the
        /// handshake), or fail ([`UnknownValues::Forbid`]).
        fn unknown_values(self, policy: UnknownValues) -> Self;
    }
    generate_set_and_with! {
        /// How GREASE slots are filled: fresh per connection (the default), from a seed,
        /// or exactly the listed codepoints ([`GreaseValues::Pinned`], for a relay that
        /// mirrors its client).
        fn grease_values(self, values: GreaseValues) -> Self;
    }
    generate_set_and_with! {
        /// Control ClientHello padding independently of extension order.
        /// Native padding is the default; explicit modes affect connection reuse.
        fn client_hello_padding(self, padding: Padding) -> Self;
    }
    generate_set_and_with! {
        /// Send extended_master_secret and renegotiation_info even when the minimum version is
        /// TLS 1.3, as some browsers do over QUIC. Off by default.
        fn legacy_extensions(self, enabled: bool) -> Self;
    }
    generate_set_and_with! {
        /// Bodies of GREASE extensions and of preserved extensions BoringSSL does not
        /// build itself, as a mimicked ClientHello sent them.
        fn extension_bodies(self, bodies: Vec<(ExtensionId, Bytes)>) -> Self;
    }
    generate_set_and_with! {
        /// Set requested trust anchor identifiers without changing certificate verification.
        fn requested_trust_anchors(self, anchors: BoringRequestedTrustAnchors) -> Self;
    }
    generate_set_and_with! {
        /// Set certificate compression algorithms to advertise.
        fn cert_compression(self, algorithms: Vec<CertificateCompressionAlgorithm>) -> Self;
    }
    generate_set_and_with! {
        /// Set delegated credential signature schemes.
        fn delegated_credentials(self, schemes: Vec<SignatureScheme>) -> Self;
    }
    generate_set_and_with! {
        /// Set the `record_size_limit` value; `0` omits the extension.
        fn record_size_limit(self, limit: u16) -> Self;
    }
    generate_set_and_with! {
        /// Request experimental server certificate padding on each new SSL.
        /// `None` omits it; `Some(0)` explicitly requests zero bytes. This does
        /// not require the server to respond or change certificate verification.
        fn server_padding_request(self, bytes: impl Into<Option<u16>>) -> Self;
    }
    generate_set_and_with! {
        /// Enable/disable Encrypted ClientHello (ECH) GREASE.
        fn encrypted_client_hello(self, enabled: bool) -> Self;
    }
    generate_set_and_with! {
        /// Select the algorithms and lengths of ECH GREASE. Enable emission with
        /// `encrypted_client_hello`; invalid shapes fail when building a connector.
        fn ech_grease(self, shape: EchGrease) -> Self;
    }
    generate_set_and_with! {
        /// Enable/disable OCSP stapling request.
        fn ocsp_stapling(self, enabled: bool) -> Self;
    }
    generate_set_and_with! {
        /// Enable/disable signed certificate timestamps request.
        fn signed_cert_timestamps(self, enabled: bool) -> Self;
    }
    generate_set_and_with! {
        /// Offer TLS 1.2 session tickets via the `session_ticket` extension (default: enabled).
        ///
        /// TLS 1.3 tickets travel in `pre_shared_key` instead and are unaffected.
        fn tls12_session_tickets(self, enabled: bool) -> Self;
    }
    generate_set_and_with! {
        /// Set a custom server-certificate verification store (custom CA roots).
        ///
        /// Ignored with [`ServerVerifyMode::Disable`]; takes precedence over
        /// common server trust policy.
        ///
        /// [`ServerVerifyMode::Disable`]: rama_tls::client::ServerVerifyMode::Disable
        fn server_verify_cert_store(self, store: Arc<X509Store>) -> Self;
    }
    generate_set_and_with! {
        /// Set the minimum TLS version boring will negotiate.
        fn min_version(self, version: ProtocolVersion) -> Self;
    }
    generate_set_and_with! {
        /// Cap the maximum TLS version boring will negotiate.
        fn max_version(self, version: ProtocolVersion) -> Self;
    }
}

impl BoringClientConfigExt for TlsClientConfig {
    fn new_from_client_hello(hello: &ClientHello) -> Self {
        Self::rama_from(hello)
    }

    generate_set_and_with! {
        fn mimic_client_hello(mut self, hello: &ClientHello) -> Self {
            Self::rama_from(hello).write_to(self.as_extensions());
            self
        }
    }

    generate_set_and_with! {
        fn cipher_suites(mut self, suites: Vec<CipherSuite>) -> Self {
            self.insert(BoringCipherSuites(suites));
            self
        }
    }
    generate_set_and_with! {
        fn supported_groups(mut self, groups: Vec<SupportedGroup>) -> Self {
            self.insert(BoringSupportedGroups(groups));
            self
        }
    }
    generate_set_and_with! {
        fn key_shares(mut self, groups: Vec<SupportedGroup>) -> Self {
            self.insert(BoringKeyShares(groups));
            self
        }
    }
    generate_set_and_with! {
        fn signature_schemes(mut self, schemes: Vec<SignatureScheme>) -> Self {
            self.insert(BoringSignatureSchemes(schemes));
            self
        }
    }
    generate_set_and_with! {
        fn grease(mut self, enabled: bool) -> Self {
            self.insert(BoringGrease(enabled));
            self
        }
    }
    generate_set_and_with! {
        fn grease_signature_schemes(mut self, enabled: bool) -> Self {
            self.insert(BoringGreaseSignatureSchemes(enabled));
            self
        }
    }
    generate_set_and_with! {
        fn alps(mut self, protocols: Vec<ApplicationProtocol>, new_codepoint: bool) -> Self {
            self.insert(BoringAlps {
                protocols,
                new_codepoint,
            });
            self
        }
    }
    generate_set_and_with! {
        fn extension_order(mut self, order: Vec<ExtensionId>) -> Self {
            self.insert(BoringExtensionOrder(order));
            self
        }
    }
    generate_set_and_with! {
        fn permute_extensions(mut self, enabled: bool) -> Self {
            self.insert(BoringPermuteExtensions(enabled));
            self
        }
    }
    generate_set_and_with! {
        fn unknown_values(mut self, policy: UnknownValues) -> Self {
            self.insert(BoringUnknownValues(policy));
            self
        }
    }
    generate_set_and_with! {
        fn grease_values(mut self, values: GreaseValues) -> Self {
            self.insert(BoringGreaseValues(values));
            self
        }
    }
    generate_set_and_with! {
        fn client_hello_padding(mut self, padding: Padding) -> Self {
            self.insert(BoringClientHelloPadding(padding));
            self
        }
    }
    generate_set_and_with! {
        fn legacy_extensions(mut self, enabled: bool) -> Self {
            self.insert(BoringLegacyExtensions(enabled));
            self
        }
    }
    generate_set_and_with! {
        fn extension_bodies(mut self, bodies: Vec<(ExtensionId, Bytes)>) -> Self {
            self.insert(BoringExtensionBodies(Arc::from(bodies)));
            self
        }
    }
    generate_set_and_with! {
        fn requested_trust_anchors(mut self, anchors: BoringRequestedTrustAnchors) -> Self {
            self.insert(anchors);
            self
        }
    }
    generate_set_and_with! {
        fn cert_compression(mut self, algorithms: Vec<CertificateCompressionAlgorithm>) -> Self {
            self.insert(BoringCertCompression(algorithms));
            self
        }
    }
    generate_set_and_with! {
        fn delegated_credentials(mut self, schemes: Vec<SignatureScheme>) -> Self {
            self.insert(BoringDelegatedCredentials(schemes));
            self
        }
    }
    generate_set_and_with! {
        fn record_size_limit(mut self, limit: u16) -> Self {
            self.insert(BoringRecordSizeLimit(limit));
            self
        }
    }
    generate_set_and_with! {
        fn server_padding_request(mut self, bytes: impl Into<Option<u16>>) -> Self {
            self.insert(BoringServerPaddingRequest(bytes.into()));
            self
        }
    }
    generate_set_and_with! {
        fn encrypted_client_hello(mut self, enabled: bool) -> Self {
            self.insert(BoringEncryptedClientHello(enabled));
            self
        }
    }
    generate_set_and_with! {
        fn ech_grease(mut self, shape: EchGrease) -> Self {
            self.insert(shape);
            self
        }
    }
    generate_set_and_with! {
        fn ocsp_stapling(mut self, enabled: bool) -> Self {
            self.insert(BoringOcspStapling(enabled));
            self
        }
    }
    generate_set_and_with! {
        fn signed_cert_timestamps(mut self, enabled: bool) -> Self {
            self.insert(BoringSignedCertTimestamps(enabled));
            self
        }
    }
    generate_set_and_with! {
        fn tls12_session_tickets(mut self, enabled: bool) -> Self {
            self.insert(BoringTls12SessionTickets(enabled));
            self
        }
    }
    generate_set_and_with! {
        fn server_verify_cert_store(mut self, store: Arc<X509Store>) -> Self {
            self.insert(BoringServerVerifyCertStore(store));
            self
        }
    }
    generate_set_and_with! {
        fn min_version(mut self, version: ProtocolVersion) -> Self {
            self.insert(BoringMinVersion(version));
            self
        }
    }
    generate_set_and_with! {
        fn max_version(mut self, version: ProtocolVersion) -> Self {
            self.insert(BoringMaxVersion(version));
            self
        }
    }
}

/// Cipher suites to offer, in order (may include GREASE / unknown values).
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringCipherSuites(pub Vec<CipherSuite>);

/// Supported groups (named curves), in order.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringSupportedGroups(pub Vec<SupportedGroup>);

/// Groups to send key shares for, in order.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringKeyShares(pub Vec<SupportedGroup>);

/// Signature schemes to advertise, in order.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringSignatureSchemes(pub Vec<SignatureScheme>);

/// Whether GREASE values are injected into the ClientHello.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringGrease(pub bool);

/// Whether a GREASE value leads the offered signature schemes.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringGreaseSignatureSchemes(pub bool);

/// Application-Layer Protocol Settings (ALPS).
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringAlps {
    /// Protocols for which settings are offered.
    pub protocols: Vec<ApplicationProtocol>,
    /// Use the new ALPS codepoint.
    pub new_codepoint: bool,
}

/// Result of coupling a concrete ALPN offer to mirrored ALPS support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AlpsCoupling {
    /// The config did not contain ALPS.
    NotConfigured,
    /// ALPS was retained for the selected ALPN protocol.
    Retained,
    /// ALPS was suppressed because it did not include the selected protocol.
    Suppressed,
}

/// Set an ALPN offer and keep inherited ALPS protocols within that offer.
pub(crate) fn set_alpn_list_with_coupled_alps(
    extensions: &Extensions,
    alpn: TlsAlpn,
) -> AlpsCoupling {
    let offered = alpn.0.clone();
    extensions.insert(alpn);

    let Some((protocols, new_codepoint)) = extensions
        .get_ref::<BoringAlps>()
        .map(|alps| (alps.protocols.clone(), alps.new_codepoint))
    else {
        return AlpsCoupling::NotConfigured;
    };

    let protocols: Vec<_> = protocols
        .into_iter()
        .filter(|protocol| offered.contains(protocol))
        .collect();
    let coupling = if protocols.is_empty() {
        AlpsCoupling::Suppressed
    } else {
        AlpsCoupling::Retained
    };
    extensions.insert(BoringAlps {
        protocols,
        new_codepoint,
    });
    coupling
}

/// Offer exactly one ALPN protocol and keep ALPS coherent with that offer.
///
/// ALPS settings are scoped to a negotiated ALPN protocol. BoringSSL requires
/// every configured ALPS protocol to also occur in its ALPN offer, so callers
/// which narrow ALPN must update both extensions together. Mirrored ALPS is
/// retained only when it included `protocol`; otherwise an empty newest value
/// shadows it in the append-only [`Extensions`] chain. The connector registers
/// no application settings for that empty value, causing BoringSSL to omit ALPS
/// from the wire ClientHello.
///
/// Suppressing ALPS only forgoes settings exchange inside the TLS handshake. It
/// does not disable the selected application protocol or its normal settings
/// exchange after the handshake.
///
/// See the [ALPS semantics][alps] and
/// [BoringSSL application-settings contract][boring-alps].
///
/// [alps]: https://datatracker.ietf.org/doc/html/draft-vvv-tls-alps-01#section-3
/// [boring-alps]: https://boringssl.googlesource.com/boringssl/+/refs/heads/master/include/openssl/ssl.h
#[cfg(feature = "http")]
pub(crate) fn set_alpn_with_coupled_alps(
    extensions: &Extensions,
    protocol: ApplicationProtocol,
) -> AlpsCoupling {
    set_alpn_list_with_coupled_alps(extensions, TlsAlpn(smallvec![protocol]))
}

/// ClientHello extension prefix order; unlisted extensions follow.
/// With GREASE on, an order naming no GREASE codepoint gets the native slots, first and
/// last; an empty order keeps the native layout. Permutation takes precedence over it.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringExtensionOrder(pub Vec<ExtensionId>);

/// Per-handshake extension permutation, taking precedence over [`BoringExtensionOrder`].
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringPermuteExtensions(pub bool);

/// What a ClientHello does with listed values BoringSSL cannot negotiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
#[extension(tags(tls))]
pub struct BoringUnknownValues(pub UnknownValues);

impl TlsPoolComponent for BoringUnknownValues {
    type Identity = Self;

    fn pool_component_identity(&self) -> Self {
        *self
    }
}

/// How a ClientHello fills its GREASE slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
#[extension(tags(tls))]
pub struct BoringGreaseValues(pub GreaseValues);

impl TlsPoolComponent for BoringGreaseValues {
    type Identity = Self;

    fn pool_component_identity(&self) -> Self {
        *self
    }
}

/// ClientHello padding policy; native behavior is used when absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
#[extension(tags(tls))]
pub struct BoringClientHelloPadding(pub Padding);

impl TlsPoolComponent for BoringClientHelloPadding {
    type Identity = Self;

    fn pool_component_identity(&self) -> Self {
        *self
    }
}

/// Whether a ClientHello with a TLS 1.3 minimum still sends the TLS 1.2 extensions
/// extended_master_secret and renegotiation_info.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
#[extension(tags(tls))]
pub struct BoringLegacyExtensions(pub bool);

impl TlsPoolComponent for BoringLegacyExtensions {
    type Identity = Self;

    fn pool_component_identity(&self) -> Self {
        *self
    }
}

/// Bodies of GREASE extensions and of preserved extensions BoringSSL does not build itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Extension)]
#[extension(tags(tls))]
pub struct BoringExtensionBodies(pub Arc<[(ExtensionId, Bytes)]>);

impl TlsPoolComponent for BoringExtensionBodies {
    type Identity = Self;

    fn pool_component_identity(&self) -> Self {
        self.clone()
    }
}

/// Certificate compression algorithms to advertise.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringCertCompression(pub Vec<CertificateCompressionAlgorithm>);

/// Delegated credential signature schemes.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringDelegatedCredentials(pub Vec<SignatureScheme>);

/// `record_size_limit` extension value; `0` omits the extension.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringRecordSizeLimit(pub u16);

/// Experimental server certificate padding requested on a fresh SSL.
/// `None` explicitly omits the extension; `Some(0)` requests zero bytes.
/// A new native SSL is configured before its handshake; no live SSL is reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
#[extension(tags(tls))]
pub struct BoringServerPaddingRequest(pub Option<u16>);

impl TlsPoolComponent for BoringServerPaddingRequest {
    type Identity = Self;

    fn pool_component_identity(&self) -> Self {
        *self
    }
}

/// Whether to GREASE the Encrypted ClientHello (ECH) extension.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringEncryptedClientHello(pub bool);

/// Whether to request OCSP stapling (`status_request`).
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringOcspStapling(pub bool);

/// Whether to request signed certificate timestamps (SCT).
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringSignedCertTimestamps(pub bool);

/// Whether to offer TLS 1.2 session tickets (`session_ticket`).
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringTls12SessionTickets(pub bool);

/// Minimum TLS version boring negotiates, overriding the min derived from the
/// supported-versions list.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringMinVersion(pub ProtocolVersion);

/// Maximum TLS version boring negotiates, overriding the max derived from the
/// supported-versions list.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringMaxVersion(pub ProtocolVersion);

/// Custom [`X509Store`] used to verify the server certificate (overrides the
/// default OS trust store, unless verification is disabled).
#[derive(Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringServerVerifyCertStore(pub Arc<X509Store>);

impl TlsPoolComponent for BoringServerVerifyCertStore {
    type Identity = TlsComponentIdentity<X509Store>;

    fn pool_component_identity(&self) -> Self::Identity {
        TlsComponentIdentity::shared(&self.0)
    }
}

impl std::fmt::Debug for BoringServerVerifyCertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoringServerVerifyCertStore")
            .finish_non_exhaustive()
    }
}

impl RamaFrom<&ClientHello, RamaTlsBoringCrateMarker> for TlsClientConfig {
    fn rama_from(hello: &ClientHello) -> Self {
        let mut config = Self::new();

        // Every shaping piece is set explicitly, absent extensions included,
        // so a layered base config cannot add anything the hello did not offer.
        let mut alps = BoringAlps {
            protocols: Vec::new(),
            new_codepoint: false,
        };
        let mut cert_compression = Vec::new();
        let mut delegated_credentials = Vec::new();
        let mut record_size_limit = 0;
        let mut server_padding_request = None;
        let mut encrypted_client_hello = false;
        let mut ech_grease = EchGrease::Native;
        let mut ocsp_stapling = false;
        let mut signed_cert_timestamps = false;
        let mut tls12_session_tickets = false;
        let mut requested_trust_anchors = BoringRequestedTrustAnchors::omitted();
        let mut extension_bodies = Vec::new();

        let cipher_suites = hello.cipher_suites();
        if !cipher_suites.is_empty() {
            config.set_cipher_suites(cipher_suites.to_vec());
        }

        let extensions = hello.extensions();
        config.set_extension_order(extensions.iter().map(|e| e.id()).dedup().collect());
        config.set_permute_extensions(false);

        for ext in extensions {
            match ext {
                // The server identity is resolved per request from the target
                // host, rather than copied from the observed ClientHello.
                ClientHelloExtension::ServerName(_) => {}
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(alpn) => {
                    config.set_alpn(alpn.clone().into());
                }
                ClientHelloExtension::SupportedGroups(groups) => {
                    config.set_supported_groups(groups.clone());
                }
                ClientHelloExtension::SupportedVersions(versions) => {
                    config.set_supported_versions(versions.clone());
                }
                ClientHelloExtension::SignatureAlgorithms(schemes) => {
                    config.set_signature_schemes(schemes.clone());
                }
                ClientHelloExtension::CertificateCompression(algorithms) => {
                    cert_compression.clone_from(algorithms);
                }
                ClientHelloExtension::DelegatedCredentials(schemes) => {
                    delegated_credentials.clone_from(schemes);
                }
                ClientHelloExtension::ServerPaddingRequest(bytes) => {
                    server_padding_request = Some(*bytes);
                }
                ClientHelloExtension::RecordSizeLimit(limit) => {
                    record_size_limit = *limit;
                }
                ClientHelloExtension::EncryptedClientHello(ech) => {
                    encrypted_client_hello = true;
                    if let ECHClientHello::Outer(outer) = ech {
                        ech_grease = EchGrease::Shape {
                            kdf_id: outer.cipher_suite.kdf_id.into(),
                            aead_id: outer.cipher_suite.aead_id.into(),
                            encapsulated_key_len: outer.enc.len(),
                            payload_len: outer.payload.len(),
                        };
                    }
                }
                ClientHelloExtension::ApplicationSettings {
                    protocols,
                    new_codepoint,
                } => {
                    alps = BoringAlps {
                        protocols: protocols.clone(),
                        new_codepoint: *new_codepoint,
                    };
                }
                ClientHelloExtension::Opaque { id, data } if *id == ExtensionId::TRUST_ANCHORS => {
                    requested_trust_anchors =
                        BoringRequestedTrustAnchors::from_raw_extension_body(data.as_slice());
                }
                // GREASE bodies, and extensions BoringSSL does not build, which an unknown-value
                // policy of `Preserve` sends as captured.
                ClientHelloExtension::Opaque { id, data }
                    if !NATIVE_EXTENSIONS.contains(&u16::from(*id)) =>
                {
                    extension_bodies.push((*id, Bytes::copy_from_slice(data)));
                }
                other => match other.id() {
                    ExtensionId::STATUS_REQUEST => {
                        ocsp_stapling = true;
                    }
                    ExtensionId::SIGNED_CERTIFICATE_TIMESTAMP => {
                        signed_cert_timestamps = true;
                    }
                    ExtensionId::SESSION_TICKET => {
                        tls12_session_tickets = true;
                    }
                    _ => {}
                },
            }
        }

        config.insert(alps);
        // Every list above is set exactly as captured, its GREASE codepoints included, so no
        // native list may add GREASE the capture did not have.
        config.set_grease(false);
        config.set_grease_signature_schemes(false);
        // Only a TLS 1.3 offer sends key shares, and it always carries the extension.
        if let Some(groups) = hello.ext_key_share_groups() {
            config.set_key_shares(groups);
        }
        if !extension_bodies.is_empty() {
            config.set_extension_bodies(extension_bodies);
        }
        // Browsers over QUIC send both although only TLS 1.3 can be negotiated there.
        let sent = |id| hello.extensions().iter().any(|ext| ext.id() == id);
        if sent(ExtensionId::EXTENDED_MASTER_SECRET) && sent(ExtensionId::RENEGOTIATION_INFO) {
            config.set_legacy_extensions(true);
        }
        config.set_cert_compression(cert_compression);
        config.set_delegated_credentials(delegated_credentials);
        config.set_record_size_limit(record_size_limit);
        config.set_server_padding_request(server_padding_request);
        config.set_encrypted_client_hello(encrypted_client_hello);
        config.set_ech_grease(ech_grease);
        config.set_ocsp_stapling(ocsp_stapling);
        config.set_signed_cert_timestamps(signed_cert_timestamps);
        config.set_tls12_session_tickets(tls12_session_tickets);
        config.set_requested_trust_anchors(requested_trust_anchors);

        // Egress version safety (mitm mirror): cap boring's max negotiated version
        // when the mirrored ClientHello isn't a viable TLS 1.3 offer.
        if let Some(max) = egress_max_version_clamp(hello) {
            config.set_max_version(max);
        }

        config
    }
}

/// Extensions BoringSSL writes itself (its extension table, padding and pre_shared_key): a
/// ClientHello shape cannot carry a body for them.
const NATIVE_EXTENSIONS: [u16; 33] = [
    0, 5, 10, 11, 13, 14, 16, 18, 19, 20, 21, 23, 27, 34, 35, 41, 42, 43, 44, 45, 47, 51, 57, 4832,
    13172, 17513, 17613, 30032, 0x8a3b, 0xca34, 0xfe0d, 0xff01, 0xffa5,
];

/// Compute the egress max-version clamp for a mirrored [`ClientHello`], or
/// `None` when no clamp is needed.
///
/// Two cases require a clamp (otherwise boring would happily offer TLS 1.3 on
/// egress even when the mirrored client wouldn't or couldn't):
/// - the hello has **no `supported_versions` extension** (legacy hello): cap to
///   the legacy `protocol_version`;
/// - the hello advertises TLS 1.3 but isn't viable as 1.3 (no TLS 1.3 cipher
///   suite, or no TLS 1.3-capable signature algorithm): clamp to TLS 1.2 rather
///   than sending an internally inconsistent ClientHello servers reject.
fn egress_max_version_clamp(hello: &ClientHello) -> Option<ProtocolVersion> {
    let Some(versions) = hello.supported_versions() else {
        // No supported_versions extension: the negotiated version lives only in
        // the legacy field, so cap egress to it.
        return Some(hello.protocol_version());
    };

    let advertises_tls13 = versions
        .iter()
        .filter(|v| !v.is_grease())
        .any(|v| *v == ProtocolVersion::TLSv1_3);
    if !advertises_tls13 {
        return None;
    }

    let has_tls13_cipher = hello
        .cipher_suites()
        .iter()
        .filter(|c| !c.is_grease())
        .any(|c| c.is_tls13());
    let has_tls13_sig_alg = hello.ext_signature_algorithms().is_some_and(|schemes| {
        schemes
            .iter()
            .filter(|s| !s.is_grease())
            .any(|s| s.is_tls13_capable())
    });

    (!has_tls13_cipher || !has_tls13_sig_alg).then_some(ProtocolVersion::TLSv1_2)
}

/// Classification of request overrides understood by Boring.
#[derive(Debug, Clone, Copy, Default)]
pub struct BoringTlsClientConfigProvider;

impl TlsClientConfigProvider for BoringTlsClientConfigProvider {
    fn pool_id(&self, extensions: &Extensions) -> Option<TlsPoolId> {
        BoringTlsConnectorConfig::from_extensions(extensions).pool_id()
    }

    fn pool_classifier(&self) -> ReuseKey {
        ReuseKey::of::<BoringTlsConnectorConfig>()
    }

    fn authenticates_server(&self, extensions: &Extensions) -> bool {
        BoringTlsConnectorConfig::from_extensions(extensions).authenticates_server()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_tls::CompressionAlgorithm;

    fn clamp_of(hello: &ClientHello) -> Option<ProtocolVersion> {
        TlsClientConfig::rama_from(hello)
            .as_extensions()
            .get_ref::<BoringMaxVersion>()
            .map(|p| p.0)
    }

    #[test]
    fn clamp_caps_to_legacy_version_when_no_supported_versions_ext() {
        let hello = ClientHello::new(
            ProtocolVersion::TLSv1_2,
            vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            vec![CompressionAlgorithm::Null],
            vec![],
        );
        assert_eq!(clamp_of(&hello), Some(ProtocolVersion::TLSv1_2));
    }

    #[test]
    fn clamp_to_tls12_when_tls13_advertised_without_tls13_cipher() {
        let hello = ClientHello::new(
            ProtocolVersion::TLSv1_2,
            // no TLS 1.3 cipher suite
            vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            vec![CompressionAlgorithm::Null],
            vec![
                ClientHelloExtension::SupportedVersions(vec![
                    ProtocolVersion::TLSv1_3,
                    ProtocolVersion::TLSv1_2,
                ]),
                ClientHelloExtension::SignatureAlgorithms(vec![SignatureScheme::RSA_PSS_SHA256]),
            ],
        );
        assert_eq!(clamp_of(&hello), Some(ProtocolVersion::TLSv1_2));
    }

    #[test]
    fn clamp_to_tls12_when_tls13_advertised_without_tls13_capable_sig_alg() {
        let hello = ClientHello::new(
            ProtocolVersion::TLSv1_2,
            vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
            vec![CompressionAlgorithm::Null],
            vec![
                ClientHelloExtension::SupportedVersions(vec![ProtocolVersion::TLSv1_3]),
                // PKCS1 is TLS 1.2-only
                ClientHelloExtension::SignatureAlgorithms(vec![SignatureScheme::RSA_PKCS1_SHA256]),
            ],
        );
        assert_eq!(clamp_of(&hello), Some(ProtocolVersion::TLSv1_2));
    }

    #[test]
    fn no_clamp_for_viable_tls13_hello() {
        let hello = ClientHello::new(
            ProtocolVersion::TLSv1_2,
            vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
            vec![CompressionAlgorithm::Null],
            vec![
                ClientHelloExtension::SupportedVersions(vec![
                    ProtocolVersion::TLSv1_3,
                    ProtocolVersion::TLSv1_2,
                ]),
                ClientHelloExtension::SignatureAlgorithms(vec![SignatureScheme::RSA_PSS_SHA256]),
            ],
        );
        assert_eq!(clamp_of(&hello), None);
    }
}

#[cfg(test)]
mod pool_tests {
    use super::*;
    use itertools::iproduct;
    use rama_boring::x509::store::X509StoreBuilder;
    use rama_core::extensions::Extensions;
    use rama_tls::ProtocolVersion;
    use rama_tls::client::{ClientAuth, ServerVerifyMode, TlsServerCertPin, TlsServerTrustAnchors};
    use rama_tls::keylog::NoopKeyLogSink;

    #[test]
    fn every_comparable_override_preserves_presence_and_value() {
        type Insert = fn(&Extensions, u8);
        let cases: &[(&str, Insert)] = &[
            ("session_profile_scope", |ext, value| {
                ext.insert(TlsSessionProfileScope(if value == 0 {
                    "first".into()
                } else {
                    "second".into()
                }));
            }),
            ("empty_alpn", |ext, value| {
                ext.insert(if value == 0 {
                    TlsAlpn::empty()
                } else {
                    TlsAlpn::http_2()
                });
            }),
            ("keylog_environment_disabled", |ext, value| {
                ext.insert(TlsKeyLog(if value == 0 {
                    KeyLogIntent::Environment
                } else {
                    KeyLogIntent::Disabled
                }));
            }),
            ("alpn", |ext, value| {
                ext.insert(if value == 0 {
                    TlsAlpn::http_1()
                } else {
                    TlsAlpn::http_2()
                });
            }),
            ("versions", |ext, value| {
                ext.insert(TlsSupportedVersions(vec![if value == 0 {
                    ProtocolVersion::TLSv1_2
                } else {
                    ProtocolVersion::TLSv1_3
                }]));
            }),
            ("verify", |ext, value| {
                ext.insert(TlsServerVerify(if value == 0 {
                    ServerVerifyMode::Auto
                } else {
                    ServerVerifyMode::Disable
                }));
            }),
            ("keylog", |ext, value| {
                ext.insert(TlsKeyLog(KeyLogIntent::File(format!("pool-test-{value}"))));
            }),
            ("server_name", |ext, value| {
                ext.insert(TlsServerName(
                    if value == 0 {
                        "one.example"
                    } else {
                        "two.example"
                    }
                    .parse()
                    .unwrap(),
                ));
            }),
            ("store_chain", |ext, value| {
                ext.insert(TlsStoreServerCertChain(value != 0));
            }),
            ("store_server_hello", |ext, value| {
                ext.insert(TlsStoreServerHello(value != 0));
            }),
            ("pins", |ext, value| {
                ext.insert(TlsServerCertPins::new(TlsServerCertPin::SpkiSha256(
                    [value; 32],
                )));
            }),
            ("trust", |ext, value| {
                ext.insert(TlsServerTrust::custom(
                    TlsServerTrustAnchors::try_new([vec![value; 4096].into()]).unwrap(),
                ));
            }),
            ("cipher_suites", |ext, value| {
                ext.insert(BoringCipherSuites(vec![u16::from(value).into()]));
            }),
            ("supported_groups", |ext, value| {
                ext.insert(BoringSupportedGroups(vec![u16::from(value).into()]));
            }),
            ("signature_schemes", |ext, value| {
                ext.insert(BoringSignatureSchemes(vec![u16::from(value).into()]));
            }),
            ("client_hello_padding", |ext, value| {
                ext.insert(BoringClientHelloPadding(if value == 0 {
                    Padding::Native
                } else {
                    Padding::Off
                }));
            }),
            ("grease", |ext, value| {
                ext.insert(BoringGrease(value != 0));
            }),
            ("grease_signature_schemes", |ext, value| {
                ext.insert(BoringGreaseSignatureSchemes(value != 0));
            }),
            ("key_shares", |ext, value| {
                ext.insert(BoringKeyShares(vec![u16::from(value).into()]));
            }),
            ("alps_protocols", |ext, value| {
                ext.insert(BoringAlps {
                    protocols: vec![if value == 0 {
                        ApplicationProtocol::HTTP_2
                    } else {
                        ApplicationProtocol::HTTP_11
                    }],
                    new_codepoint: false,
                });
            }),
            ("alps_codepoint", |ext, value| {
                ext.insert(BoringAlps {
                    protocols: vec![ApplicationProtocol::HTTP_2],
                    new_codepoint: value != 0,
                });
            }),
            ("extension_order", |ext, value| {
                ext.insert(BoringExtensionOrder(vec![u16::from(value).into()]));
            }),
            ("permute_extensions", |ext, value| {
                ext.insert(BoringPermuteExtensions(value != 0));
            }),
            ("requested_trust_anchors_presence", |ext, value| {
                ext.insert(if value == 0 {
                    BoringRequestedTrustAnchors::omitted()
                } else {
                    BoringRequestedTrustAnchors::try_from_ids(std::iter::empty::<&[u8]>()).unwrap()
                });
            }),
            ("requested_trust_anchors", |ext, value| {
                ext.insert(BoringRequestedTrustAnchors::try_from_ids([[value + 1]]).unwrap());
            }),
            ("tls12_session_tickets", |ext, value| {
                ext.insert(BoringTls12SessionTickets(value != 0));
            }),
            ("cert_compression", |ext, value| {
                ext.insert(BoringCertCompression(vec![u16::from(value).into()]));
            }),
            ("delegated_credentials", |ext, value| {
                ext.insert(BoringDelegatedCredentials(vec![u16::from(value).into()]));
            }),
            ("record_size_limit", |ext, value| {
                ext.insert(BoringRecordSizeLimit(u16::from(value)));
            }),
            ("encrypted_client_hello", |ext, value| {
                ext.insert(BoringEncryptedClientHello(value != 0));
            }),
            ("ech_grease", |ext, value| {
                ext.insert(EchGrease::Shape {
                    kdf_id: 1,
                    aead_id: 1,
                    encapsulated_key_len: 32,
                    payload_len: 144 + usize::from(value),
                });
            }),
            ("ocsp_stapling", |ext, value| {
                ext.insert(BoringOcspStapling(value != 0));
            }),
            ("signed_cert_timestamps", |ext, value| {
                ext.insert(BoringSignedCertTimestamps(value != 0));
            }),
            ("min_version", |ext, value| {
                ext.insert(BoringMinVersion(if value == 0 {
                    ProtocolVersion::TLSv1_2
                } else {
                    ProtocolVersion::TLSv1_3
                }));
            }),
            ("max_version", |ext, value| {
                ext.insert(BoringMaxVersion(if value == 0 {
                    ProtocolVersion::TLSv1_2
                } else {
                    ProtocolVersion::TLSv1_3
                }));
            }),
        ];
        for (name, insert) in cases {
            let first = Extensions::new();
            let empty = BoringTlsConnectorConfig::from_extensions(&first);
            assert!(empty.is_empty(), "{name}");
            assert_eq!(empty.pool_id(), None, "{name}");
            insert(&first, 0);
            let view = BoringTlsConnectorConfig::from_extensions(&first);
            assert!(!view.is_empty(), "{name}");
            let id = view.pool_id().unwrap();
            assert!(id.is_reusable(), "{name}");
            let equal = Extensions::new();
            insert(&equal, 0);
            assert_eq!(
                Some(id.clone()),
                BoringTlsConnectorConfig::from_extensions(&equal).pool_id(),
                "{name}"
            );
            let changed = Extensions::new();
            insert(&changed, 1);
            assert_ne!(
                Some(id),
                BoringTlsConnectorConfig::from_extensions(&changed).pool_id(),
                "{name}"
            );
            if matches!(
                *name,
                "session_profile_scope" | "verify" | "pins" | "trust" | "cipher_suites"
            ) {
                assert_eq!(
                    view.session_scope(),
                    BoringTlsConnectorConfig::from_extensions(&equal).session_scope(),
                    "{name}"
                );
                assert_ne!(
                    view.session_scope(),
                    BoringTlsConnectorConfig::from_extensions(&changed).session_scope(),
                    "{name}"
                );
            } else if !matches!(
                *name,
                "keylog_environment_disabled" | "keylog" | "server_name" | "store_chain"
            ) {
                // Wire settings are per connection: sessions resume across them.
                assert_eq!(
                    view.session_scope(),
                    BoringTlsConnectorConfig::from_extensions(&changed).session_scope(),
                    "{name}"
                );
            }
            // Newest request settings replace older values of the same type.
            insert(&first, 1);
            assert_eq!(
                BoringTlsConnectorConfig::from_extensions(&first).pool_id(),
                BoringTlsConnectorConfig::from_extensions(&changed).pool_id(),
                "{name}"
            );
        }
    }

    #[test]
    fn generic_builder_matches_native_override_identity() {
        let alpn = TlsAlpn::http_2();
        let protocols = [ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11];
        let ciphers = [CipherSuite::TLS13_AES_128_GCM_SHA256];
        let groups = [SupportedGroup::X25519];
        let signatures = [SignatureScheme::RSA_PSS_SHA256];
        let delegated = [SignatureScheme::ECDSA_NISTP256_SHA256];
        let extensions = [ExtensionId::SERVER_NAME];
        let compression = [CertificateCompressionAlgorithm::Zlib];

        let anchors = BoringRequestedTrustAnchors::try_from_ids([[7]]).unwrap();

        // Distinct combinations catch swapped boolean setters as well as omitted fields.
        for (grease, ech, ocsp, timestamps, new_codepoint, permute, tickets, grease_schemes) in iproduct!(
            [false, true],
            [false, true],
            [false, true],
            [false, true],
            [false, true],
            [false, true],
            [false, true],
            [false, true]
        ) {
            let input = Extensions::new();
            input.insert(alpn.clone());
            input.insert(BoringCipherSuites(ciphers.to_vec()));
            input.insert(BoringSupportedGroups(groups.to_vec()));
            input.insert(BoringKeyShares(groups.to_vec()));
            input.insert(BoringGreaseSignatureSchemes(grease_schemes));
            input.insert(BoringSignatureSchemes(signatures.to_vec()));
            input.insert(BoringGrease(grease));
            input.insert(BoringAlps {
                protocols: protocols.to_vec(),
                new_codepoint,
            });
            input.insert(BoringExtensionOrder(extensions.to_vec()));
            input.insert(BoringPermuteExtensions(permute));
            input.insert(anchors.clone());
            input.insert(BoringTls12SessionTickets(tickets));
            input.insert(BoringCertCompression(compression.to_vec()));
            input.insert(BoringDelegatedCredentials(delegated.to_vec()));
            input.insert(BoringRecordSizeLimit(4096));
            input.insert(BoringEncryptedClientHello(ech));
            input.insert(BoringOcspStapling(ocsp));
            input.insert(BoringSignedCertTimestamps(timestamps));
            input.insert(BoringMinVersion(ProtocolVersion::TLSv1_2));
            input.insert(BoringMaxVersion(ProtocolVersion::TLSv1_3));

            let expected = TlsPoolId::builder()
                .with_alpn(&alpn)
                .with_cipher_suites(&ciphers)
                .with_supported_groups(&groups)
                .with_key_shares(&groups)
                .with_signature_schemes(&signatures)
                .with_grease(grease)
                .with_grease_signature_schemes(grease_schemes)
                .with_alps(&protocols, new_codepoint)
                .with_extension_order(&extensions)
                .with_permute_extensions(permute)
                .with_requested_trust_anchors(anchors.extension_body().unwrap())
                .with_tls12_session_tickets(tickets)
                .with_cert_compression(&compression)
                .with_delegated_credentials(&delegated)
                .with_record_size_limit(4096)
                .with_encrypted_client_hello(ech)
                .with_ocsp_stapling(ocsp)
                .with_signed_cert_timestamps(timestamps)
                .with_min_version(ProtocolVersion::TLSv1_2)
                .with_max_version(ProtocolVersion::TLSv1_3)
                .build();
            assert_eq!(
                BoringTlsConnectorConfig::from_extensions(&input).pool_id(),
                expected
            );
        }
    }

    #[test]
    fn omitted_trust_anchors_never_share_an_identity_with_a_captured_body() {
        let identity = |anchors: BoringRequestedTrustAnchors| {
            let extensions = Extensions::new();
            extensions.insert(anchors);
            BoringTlsConnectorConfig::from_extensions(&extensions).pool_id()
        };
        let omitted = identity(BoringRequestedTrustAnchors::omitted());
        assert!(omitted.is_some());
        // A malformed captured body must keep failing the connector, not reuse a connection.
        assert_ne!(
            omitted,
            identity(BoringRequestedTrustAnchors::from_raw_extension_body(vec![]))
        );
        assert_ne!(
            omitted,
            identity(
                BoringRequestedTrustAnchors::try_from_ids(std::iter::empty::<&[u8]>()).unwrap()
            )
        );
    }

    #[test]
    fn custom_overrides_reuse_their_shared_policy() {
        let cases: &[fn(&Extensions)] = &[
            |ext| {
                ext.insert(TlsClientAuth(ClientAuth::SelfSigned));
            },
            |ext| {
                ext.insert(TlsKeyLog(KeyLogIntent::Custom(Arc::new(NoopKeyLogSink))));
            },
            |ext| {
                ext.insert(BoringServerVerifyCertStore(Arc::new(
                    X509StoreBuilder::new().unwrap().build(),
                )));
            },
        ];
        for insert in cases {
            let extensions = Extensions::new();
            insert(&extensions);
            let view = BoringTlsConnectorConfig::from_extensions(&extensions);
            assert!(!view.is_empty());
            let id = view.pool_id().unwrap();
            assert!(id.is_reusable());
            assert_eq!(Some(id), view.pool_id());
        }
    }

    #[test]
    fn cloned_native_store_matches_but_replacements_do_not() {
        let store = BoringServerVerifyCertStore(Arc::new(X509StoreBuilder::new().unwrap().build()));
        let first = Extensions::new();
        first.insert(store.clone());
        let same = Extensions::new();
        same.insert(store);
        let identity = BoringTlsClientConfigProvider.pool_id(&first);
        assert_eq!(identity, BoringTlsClientConfigProvider.pool_id(&same));
        same.insert(BoringServerVerifyCertStore(Arc::new(
            X509StoreBuilder::new().unwrap().build(),
        )));
        assert_ne!(identity, BoringTlsClientConfigProvider.pool_id(&same));
    }

    #[test]
    fn session_scope_normalizes_default_verification_and_ignores_drawn_order() {
        let empty = Extensions::new();
        let explicit = Extensions::new();
        explicit.insert(TlsServerVerify(ServerVerifyMode::Auto));
        explicit.insert(BoringExtensionOrder(vec![
            ExtensionId::SERVER_NAME,
            ExtensionId::SUPPORTED_VERSIONS,
        ]));
        explicit.insert(BoringPermuteExtensions(false));
        assert_eq!(
            BoringTlsConnectorConfig::from_extensions(&empty).session_scope(),
            BoringTlsConnectorConfig::from_extensions(&explicit).session_scope()
        );
        assert_ne!(
            BoringTlsConnectorConfig::from_extensions(&empty).pool_id(),
            BoringTlsConnectorConfig::from_extensions(&explicit).pool_id()
        );
        let domain = TlsClientSessionDomain::new();
        let other_domain = TlsClientSessionDomain::new();
        empty.insert(domain);
        explicit.insert(domain);
        assert_eq!(
            BoringTlsConnectorConfig::from_extensions(&empty).session_scope(),
            BoringTlsConnectorConfig::from_extensions(&explicit).session_scope()
        );
        explicit.insert(other_domain);
        assert_ne!(
            BoringTlsConnectorConfig::from_extensions(&empty).session_scope(),
            BoringTlsConnectorConfig::from_extensions(&explicit).session_scope()
        );
    }
}

#[cfg(test)]
mod native_extension_tests {
    use rama_boring::ssl::{ClientHelloShape, ExtensionType};
    use rama_tls::client::TlsClientConfig;

    use super::NATIVE_EXTENSIONS;
    use crate::client::TlsConnectorData;

    /// Whether a ClientHello shape may carry a body for `id`.
    fn takes_a_body(id: u16) -> bool {
        let mut data = TlsConnectorData::try_from(&TlsClientConfig::new()).unwrap();
        data.config
            .set_client_hello_shape(
                &ClientHelloShape::new().with_extension_body(ExtensionType::from(id), vec![1]),
            )
            .is_ok()
    }

    #[test]
    fn native_extensions_are_the_ones_boringssl_builds() {
        for id in NATIVE_EXTENSIONS {
            assert!(!takes_a_body(id), "{id:#06x} is not native");
        }
        // Mimicked hellos carry these as bodies: status_request_v2, a private extension,
        // signature_algorithms_cert, a GREASE codepoint.
        for id in [17, 0x1234, 50, 0x0a0a] {
            assert!(takes_a_body(id), "{id:#06x} is native");
        }
    }
}
