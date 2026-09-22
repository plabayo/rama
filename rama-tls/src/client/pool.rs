use std::hash::{Hash, Hasher};

use rama_core::extensions::{Extension, Extensions};
use rama_net::tls::TlsAlpn;
use sha2::{Digest, Sha256};

use super::{
    ServerVerifyMode, TlsClientAuth, TlsServerCertPins, TlsServerName, TlsServerTrust,
    TlsServerVerify, TlsStoreServerCertChain,
};
use crate::{KeyLogIntent, TlsBackend, TlsKeyLog, TlsSupportedVersions};

/// Target-independent identity of common TLS client configuration and policies.
///
/// SHA-256 covers the selected provider, verification and trust policy, pins,
/// offered protocols, certificate capture and key logging. It excludes the
/// destination and explicit server-name override. Construct a [`TlsClientPoolKey`]
/// for pooling: opaque client credentials, key-log sinks and provider hooks must
/// additionally disable reuse.
///
/// This is an in-process configuration identity, not a ClientHello fingerprint
/// or a stable serialization format. Its encoding can change between builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsClientFingerprint([u8; 32]);

/// Compact TLS identity that must agree before a connection can be reused.
///
/// Construct this from request extensions layered over the connector defaults,
/// before pool lookup. The fingerprint owns no certificates or policy collections.
/// Explicit server-name overrides are hashed into the identity: two requests
/// to the same target can select different SNI and verification names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Extension)]
#[extension(tags(tls))]
pub struct TlsClientPoolKey {
    fingerprint: [u8; 32],
    reusable: bool,
}

/// A provider-prepared pooling policy with a cached identity for its defaults.
///
/// Provider crates construct this policy and classify their native overrides.
/// It retains no configuration, certificates or credential objects. Per-request
/// settings are combined with the cached defaults before pool lookup. Equivalent
/// explicit and inherited settings may occupy separate buckets; this conservative
/// separation avoids rebuilding and hashing the default trust store per request.
#[derive(Debug, Clone)]
pub struct TlsClientPoolPolicy {
    defaults: TlsClientPoolKey,
    classify: fn(&Extensions) -> TlsClientPoolKey,
}

impl TlsClientPoolPolicy {
    /// Provider integration: cache defaults using the provider's complete policy
    /// classifier. Opaque native settings must disable reuse.
    #[doc(hidden)]
    pub fn new(defaults: &Extensions, classify: fn(&Extensions) -> TlsClientPoolKey) -> Self {
        Self {
            defaults: classify(defaults),
            classify,
        }
    }

    /// Compare request settings against the cached connector defaults.
    #[must_use]
    pub fn key(&self, extensions: &Extensions) -> TlsClientPoolKey {
        let request = (self.classify)(extensions);
        let mut state = PolicyHasher(Sha256::new());
        state.write(b"rama.tls.client-pool-policy.v1");
        self.defaults.fingerprint.hash(&mut state);
        request.fingerprint.hash(&mut state);
        TlsClientPoolKey {
            fingerprint: state.0.finalize().into(),
            reusable: self.defaults.reusable && request.reusable,
        }
    }
}

// Borrow the effective policy only while hashing it. Derived Hash incorporates
// nested policy fields and preserves their existing equality semantics, including
// host normalization in name-scoped certificate pins.
#[derive(Hash)]
struct ClientPolicy<'a> {
    backend: TlsBackend,
    verify: Option<ServerVerifyMode>,
    trust: Option<&'a TlsServerTrust>,
    pins: Option<&'a TlsServerCertPins>,
    alpn: Option<&'a TlsAlpn>,
    versions: Option<&'a TlsSupportedVersions>,
    store_chain: Option<bool>,
    keylog: KeyLogPolicy<'a>,
}

#[derive(Hash)]
enum KeyLogPolicy<'a> {
    Unspecified,
    Environment,
    Disabled,
    File(&'a str),
    Custom,
}

impl TlsClientFingerprint {
    /// Fingerprint common settings for the selected provider, excluding the
    /// destination and server-name override. Native settings require the
    /// provider's separate reuse check; this digest alone does not authorize reuse.
    #[must_use]
    pub fn from_extensions(extensions: &Extensions, backend: TlsBackend) -> Self {
        let keylog = match extensions.get_ref::<TlsKeyLog>().map(|value| &value.0) {
            None => KeyLogPolicy::Unspecified,
            Some(KeyLogIntent::Disabled) => KeyLogPolicy::Disabled,
            Some(KeyLogIntent::Environment) => KeyLogPolicy::Environment,
            Some(KeyLogIntent::File(path)) => KeyLogPolicy::File(path),
            Some(KeyLogIntent::Custom(_)) => KeyLogPolicy::Custom,
        };
        let policy = ClientPolicy {
            backend,
            verify: extensions.get_ref::<TlsServerVerify>().map(|value| value.0),
            trust: extensions.get_ref::<TlsServerTrust>(),
            pins: extensions.get_ref::<TlsServerCertPins>(),
            alpn: extensions.get_ref::<TlsAlpn>(),
            versions: extensions.get_ref::<TlsSupportedVersions>(),
            store_chain: extensions
                .get_ref::<TlsStoreServerCertChain>()
                .map(|value| value.0),
            keylog,
        };

        let mut state = PolicyHasher(Sha256::new());
        state.write(b"rama.tls.client-policy.v1");
        policy.hash(&mut state);
        Self(state.0.finalize().into())
    }
}

impl TlsClientPoolKey {
    /// Capture common settings for the selected backend. Provider crates must
    /// disable reuse when their native settings cannot be compared by value.
    #[must_use]
    pub fn from_extensions(extensions: &Extensions, backend: TlsBackend) -> Self {
        let mut state = PolicyHasher(Sha256::new());
        state.write(b"rama.tls.client-pool-key.v1");
        TlsClientFingerprint::from_extensions(extensions, backend).hash(&mut state);
        extensions
            .get_ref::<TlsServerName>()
            .map(|value| &value.0)
            .hash(&mut state);
        Self {
            fingerprint: state.0.finalize().into(),
            reusable: !extensions.contains::<TlsClientAuth>()
                && !extensions
                    .get_ref::<TlsKeyLog>()
                    .is_some_and(|value| matches!(value.0, KeyLogIntent::Custom(_))),
        }
    }

    /// Whether these settings can be compared completely enough to permit reuse.
    #[must_use]
    pub fn is_reusable(&self) -> bool {
        self.reusable
    }

    /// Require a fresh, unpooled connection for opaque provider settings.
    pub fn disable_reuse(&mut self) {
        self.reusable = false;
    }
}

// Hash's ordinary 64-bit output is insufficient for a security-policy identity.
// Feed the complete, length-framed hash input to SHA-256 instead. Framing prevents
// different sequences of writes from collapsing into the same digest input.
// The underlying Hash encoding is deliberately local to this build; only full
// 256-bit fingerprints participate in connection-key equality.
struct PolicyHasher(Sha256);

impl Hasher for PolicyHasher {
    fn finish(&self) -> u64 {
        // Honor Hasher's contract for nested Hash implementations. Pool identity
        // never uses this projection: it finalizes all 256 bits above.
        let digest = self.0.clone().finalize();
        let mut prefix = [0; 8];
        prefix.copy_from_slice(&digest[..8]);
        u64::from_be_bytes(prefix)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.update((bytes.len() as u64).to_be_bytes());
        self.0.update(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ClientAuth, TlsClientConfig, TlsServerCertPin};
    use rama_net::address::Host;

    #[test]
    fn cached_defaults_preserve_explicit_verification_and_capture_overrides() {
        fn classify(extensions: &Extensions) -> TlsClientPoolKey {
            TlsClientPoolKey::from_extensions(extensions, TlsBackend::Rustls)
        }
        let defaults = TlsClientConfig::new()
            .with_server_verify(ServerVerifyMode::Disable)
            .with_store_server_cert_chain(true);
        defaults
            .as_extensions()
            .insert(TlsServerTrust::webpki_roots());
        let trust = defaults
            .as_extensions()
            .get_arc::<TlsServerTrust>()
            .unwrap();
        let retained = std::sync::Arc::strong_count(&trust);
        let policy = TlsClientPoolPolicy::new(defaults.as_extensions(), classify);
        assert_eq!(std::sync::Arc::strong_count(&trust), retained);

        let request = Extensions::new();
        let inherited = policy.key(&request);
        assert_eq!(inherited, policy.key(&request));
        request.insert(TlsServerVerify(ServerVerifyMode::Auto));
        let verified = policy.key(&request);
        assert_ne!(inherited, verified);
        request.insert(TlsStoreServerCertChain(false));
        assert_ne!(verified, policy.key(&request));
        assert_eq!(std::sync::Arc::strong_count(&trust), retained);
    }

    #[test]
    fn equivalent_pins_reuse_but_distinct_security_policies_do_not() {
        let key =
            |pin| {
                let config = TlsClientConfig::new();
                config.as_extensions().insert(TlsServerCertPins::new(
                    TlsServerCertPin::SpkiSha256([pin; 32]),
                ));
                TlsClientPoolKey::from_extensions(config.as_extensions(), TlsBackend::Rustls)
            };
        assert_eq!(key(1), key(1));
        assert_ne!(key(1), key(2));
        assert!(key(1).is_reusable());

        let settings = Extensions::new();
        let verified = TlsClientPoolKey::from_extensions(&settings, TlsBackend::Rustls);
        settings.insert(TlsServerVerify(ServerVerifyMode::Disable));
        assert_ne!(
            verified,
            TlsClientPoolKey::from_extensions(&settings, TlsBackend::Rustls)
        );
        settings.insert(TlsServerTrust::webpki_roots());
        let webpki = TlsClientPoolKey::from_extensions(&settings, TlsBackend::Rustls);
        settings.insert(TlsServerTrust::default_roots());
        assert_ne!(
            webpki,
            TlsClientPoolKey::from_extensions(&settings, TlsBackend::Rustls)
        );
        settings.insert(TlsClientAuth(ClientAuth::SelfSigned));
        assert!(!TlsClientPoolKey::from_extensions(&settings, TlsBackend::Rustls).is_reusable());
    }

    #[test]
    fn fingerprint_excludes_target_but_pool_key_preserves_server_identity() {
        let settings = Extensions::new();
        let initial = TlsClientPoolKey::from_extensions(&settings, TlsBackend::Rustls);
        settings.insert(TlsServerName(Host::try_from("one.example").unwrap()));
        let one = TlsClientPoolKey::from_extensions(&settings, TlsBackend::Rustls);
        settings.insert(TlsServerName(Host::try_from("two.example").unwrap()));
        let two = TlsClientPoolKey::from_extensions(&settings, TlsBackend::Rustls);

        let common = TlsClientFingerprint::from_extensions(&settings, TlsBackend::Rustls);
        settings.insert(TlsServerName(Host::try_from("three.example").unwrap()));
        assert_eq!(
            common,
            TlsClientFingerprint::from_extensions(&settings, TlsBackend::Rustls)
        );
        assert_ne!(initial, one);
        assert_ne!(one, two);
    }

    #[test]
    fn fingerprint_separates_protocol_preferences_and_observability() {
        let settings = Extensions::new();
        let fingerprint = || TlsClientFingerprint::from_extensions(&settings, TlsBackend::Rustls);
        let baseline = fingerprint();
        settings.insert(TlsAlpn::empty());
        let no_alpn = fingerprint();
        settings.insert(TlsAlpn::http_1());
        let http1 = fingerprint();
        settings.insert(TlsAlpn::http_2());
        let http2 = fingerprint();
        settings.insert(TlsAlpn::http_auto());
        let automatic = fingerprint();
        let mut reversed = TlsAlpn::http_auto();
        reversed.0.reverse();
        settings.insert(reversed);
        let reversed = fingerprint();
        let protocols = [baseline, no_alpn, http1, http2, automatic, reversed];
        for (index, item) in protocols.iter().enumerate() {
            assert!(!protocols[..index].contains(item));
        }

        settings.insert(TlsSupportedVersions(vec![crate::ProtocolVersion::TLSv1_3]));
        let tls13 = fingerprint();
        settings.insert(TlsSupportedVersions(vec![crate::ProtocolVersion::TLSv1_2]));
        assert_ne!(tls13, fingerprint());
        let before_capture = fingerprint();
        settings.insert(TlsStoreServerCertChain(true));
        assert_ne!(before_capture, fingerprint());

        let before_keylog = fingerprint();
        settings.insert(TlsKeyLog(KeyLogIntent::Disabled));
        let disabled = fingerprint();
        settings.insert(TlsKeyLog(KeyLogIntent::Environment));
        let environment = fingerprint();
        settings.insert(TlsKeyLog(KeyLogIntent::File("one.log".into())));
        let one_file = fingerprint();
        settings.insert(TlsKeyLog(KeyLogIntent::File("two.log".into())));
        let two_files = fingerprint();
        let loggers = [before_keylog, disabled, environment, one_file, two_files];
        for (index, item) in loggers.iter().enumerate() {
            assert!(!loggers[..index].contains(item));
        }
    }

    #[test]
    fn equivalent_scoped_pins_have_equal_fingerprints() {
        let key = |host: &str| {
            let settings = Extensions::new();
            settings.insert(TlsServerCertPins::new(
                crate::client::TlsServerCertPinSet::new(TlsServerCertPin::SpkiSha256([1; 32]))
                    .with_server_name(Host::try_from(host).unwrap()),
            ));
            TlsClientFingerprint::from_extensions(&settings, TlsBackend::Rustls)
        };
        assert_eq!(key("EXAMPLE.com"), key("example.com"));
        assert_ne!(key("one.example"), key("two.example"));
    }

    #[test]
    fn opaque_settings_and_provider_overrides_still_disable_reuse() {
        let settings = Extensions::new();
        let mut key = TlsClientPoolKey::from_extensions(&settings, TlsBackend::Rustls);
        assert!(key.is_reusable());
        key.disable_reuse();
        assert!(!key.is_reusable());

        settings.insert(TlsKeyLog(KeyLogIntent::Custom(std::sync::Arc::new(
            crate::keylog::NoopKeyLogSink,
        ))));
        assert!(!TlsClientPoolKey::from_extensions(&settings, TlsBackend::Rustls).is_reusable());
    }

    #[test]
    fn fingerprints_are_compact_and_do_not_retain_policy_collections() {
        assert_eq!(std::mem::size_of::<TlsClientFingerprint>(), 32);
        assert!(std::mem::size_of::<TlsClientPoolKey>() <= 40);
        let settings = Extensions::new();
        settings.insert(TlsServerTrust::webpki_roots());
        let trust = settings.get_arc::<TlsServerTrust>().unwrap();
        let count = std::sync::Arc::strong_count(&trust);
        let key = TlsClientPoolKey::from_extensions(&settings, TlsBackend::Rustls);
        assert_eq!(std::sync::Arc::strong_count(&trust), count);
        let cloned = key.clone();
        assert_eq!(key, cloned);
        assert_eq!(std::sync::Arc::strong_count(&trust), count);
    }

    #[test]
    fn hash_write_boundaries_are_unambiguous() {
        let mut first = PolicyHasher(Sha256::new());
        first.write(b"a");
        first.write(b"bc");
        let mut second = PolicyHasher(Sha256::new());
        second.write(b"ab");
        second.write(b"c");
        assert_ne!(first.0.finalize(), second.0.finalize());
    }

    #[test]
    fn request_overrides_shadow_defaults_before_pool_selection() {
        let defaults = Extensions::new();
        defaults.insert(TlsServerVerify(ServerVerifyMode::Disable));
        let request = Extensions::new();
        request.insert(TlsServerVerify(ServerVerifyMode::Auto));
        assert_eq!(
            TlsClientPoolKey::from_extensions(&request.with_base(&defaults), TlsBackend::Rustls),
            TlsClientPoolKey::from_extensions(&request, TlsBackend::Rustls),
        );
        assert_ne!(
            TlsClientPoolKey::from_extensions(&request, TlsBackend::Rustls),
            TlsClientPoolKey::from_extensions(&request, TlsBackend::Boring),
        );
    }
}
