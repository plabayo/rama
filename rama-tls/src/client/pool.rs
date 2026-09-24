use std::{
    any::{Any, TypeId},
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
    mem::{Discriminant, discriminant},
    sync::{Arc, LazyLock},
};

use ahash::RandomState;
use rama_core::extensions::{Extension, Extensions};
use rama_crypto::pki_types::{CertificateDer, PrivateKeyDer};
use rama_net::{
    address::Host,
    client::pool::{ConnectionReuse, ConnectionReusePolicy},
    tls::{ApplicationProtocol, TlsAlpn},
};
use rama_utils::{collections::smallvec::SmallVec, macros::generate_set_and_with};

use crate::client::{
    ClientAuth, ServerVerifyMode, TlsClientAuth, TlsClientConfigProvider, TlsServerCertPins,
    TlsServerName, TlsServerTrust, TlsServerVerify, TlsStoreServerCertChain,
};
use crate::{
    CertificateCompressionAlgorithm, CipherSuite, ExtensionId, KeyLogIntent, ProtocolVersion,
    SignatureScheme, SupportedGroup, TlsKeyLog, TlsSupportedVersions, TlsTunnel,
    keylog::KeyLogSink,
};

/// Reuse rules published by the connector that performed a TLS handshake.
///
/// Capture request overrides before applying connector defaults, and publish only
/// after a successful handshake. Pools borrow the next request's extensions to
/// check compatibility; callers need not configure the provider on the pool.
/// Connector defaults, including credentials and hooks, remain fixed for the
/// lifetime of its pool. Custom components supply stable value or instance identities.
#[derive(Debug)]
pub struct TlsConnectionReuse<P> {
    provider: P,
    scope: ReuseScope,
    reusable: bool,
}

#[derive(Debug)]
enum ReuseScope {
    Origin(Option<TlsPoolId>),
    Tunnel(Option<TlsTunnel>),
}

impl<P: TlsClientConfigProvider + 'static> TlsConnectionReuse<P> {
    /// Capture request overrides relative to this connector's fixed defaults.
    pub fn new(provider: P, request: &Extensions) -> Self {
        let identity = provider.pool_id(request);
        Self {
            provider,
            reusable: identity.as_ref().is_none_or(TlsPoolId::is_reusable),
            scope: ReuseScope::Origin(identity),
        }
    }

    /// Capture fixed proxy TLS policy, independently of origin TLS overrides.
    ///
    /// The pool's route key identifies the proxy. Caller-supplied tunnel settings
    /// must match on later requests; route-generated settings remain fixed for
    /// that route and are distinct from the caller's overrides.
    pub fn tunnel(provider: P, request: &Extensions) -> Self {
        Self {
            provider,
            scope: ReuseScope::Tunnel(request.get_ref::<TlsTunnel>().cloned()),
            reusable: true,
        }
    }

    /// Publish this handshake's rules while retaining restrictions from inner layers.
    pub fn publish(self, connection: &Extensions) {
        let tunnel = matches!(self.scope, ReuseScope::Tunnel(_));
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
            && match &self.scope {
                ReuseScope::Origin(identity) => {
                    self.provider.pool_id(input).as_ref() == identity.as_ref()
                }
                ReuseScope::Tunnel(tunnel) => input.get_ref::<TlsTunnel>() == tunnel.as_ref(),
            }
    }
}

/// Compact, process-local identity of request-level TLS overrides.
///
/// Construct with [`Self::builder`]. An absent override differs from an explicit
/// default: the latter might replace a different connector default. Equivalent
/// common settings have the same identity regardless of the TLS implementation.
///
/// This identifies overrides within a pool with fixed connector defaults. It
/// neither identifies a destination nor authenticates a peer, and is not a stable
/// serialization or a TLS wire fingerprint. Custom identities are captured by
/// value; instance identities retain their owners to prevent address reuse from
/// matching a different policy. Pools must check [`Self::is_reusable`] at checkout
/// and return.
#[derive(Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsPoolId {
    digest: PolicyDigest,
    reusable: bool,
    components: Option<Arc<SharedComponents>>,
}

// Common settings use a compact fingerprint; custom components compare their
// actual captured identities, independently of this list's allocation.
impl PartialEq for TlsPoolId {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
            && self.reusable == other.reusable
            && self.components == other.components
    }
}

impl Eq for TlsPoolId {}

impl Hash for TlsPoolId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
        self.reusable.hash(state);
        self.components.hash(state);
    }
}

impl fmt::Debug for TlsPoolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsPoolId")
            .field("digest", &self.digest)
            .field("reusable", &self.reusable)
            .finish_non_exhaustive()
    }
}

/// Owning instance identity for components whose policy follows a shared object.
///
/// Clones of the same `Arc` compare equal, regardless of its value. Retaining the
/// owner prevents a recycled address from matching a different policy instance.
/// Use a value identity instead when independently built policies are equivalent.
pub struct TlsComponentIdentity<T: ?Sized>(Arc<T>);

impl<T: ?Sized> TlsComponentIdentity<T> {
    /// Retain a shared instance, including an unsized trait object.
    pub fn shared(value: &Arc<T>) -> Self {
        Self(value.clone())
    }
}

impl<T: ?Sized> Clone for TlsComponentIdentity<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: ?Sized> PartialEq for TlsComponentIdentity<T> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl<T: ?Sized> Eq for TlsComponentIdentity<T> {}

impl<T: ?Sized> Hash for TlsComponentIdentity<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Arc::as_ptr(&self.0).cast::<()>().hash(state);
    }
}

impl<T: ?Sized> fmt::Debug for TlsComponentIdentity<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsComponentIdentity")
            .finish_non_exhaustive()
    }
}

/// Explicit pooling identity for a custom TLS configuration component.
///
/// Equal identities promise equivalent connection reuse policies. The builder
/// captures an owned identity; it never reads the component again. A value,
/// immutable shared configuration, or [`TlsComponentIdentity`] can identify the
/// policy without copying the component itself. Identity equality and hashing
/// must remain stable for the identity's lifetime.
///
/// A mutable component must return a new identity when its policy changes. Use
/// [`TlsPoolIdBuilder::with_opaque_override`] if that cannot be guaranteed.
/// Equality of arbitrary callbacks cannot be inferred automatically.
///
/// ```
/// use std::sync::Arc;
/// use rama_tls::client::{TlsComponentIdentity, TlsPoolComponent, TlsPoolId};
///
/// struct VerifyHook(Arc<dyn Fn() -> bool + Send + Sync>);
///
/// impl TlsPoolComponent for VerifyHook {
///     type Identity = TlsComponentIdentity<dyn Fn() -> bool + Send + Sync>;
///
///     fn pool_component_identity(&self) -> Self::Identity {
///         TlsComponentIdentity::shared(&self.0)
///     }
/// }
///
/// let hook = Arc::new(VerifyHook(Arc::new(|| true)));
/// let identity = TlsPoolId::builder().with_component(hook.as_ref()).build();
/// let clone = Arc::new(VerifyHook(hook.0.clone()));
/// assert_eq!(identity, TlsPoolId::builder().with_component(clone.as_ref()).build());
/// ```
pub trait TlsPoolComponent: Any + Send + Sync {
    /// An owned, stable snapshot of this component's reuse policy.
    type Identity: Eq + Hash + Send + Sync + 'static;

    /// Capture the current policy identity independently of this borrow.
    fn pool_component_identity(&self) -> Self::Identity;
}

// Erasure is internal: callers implement ordinary value equality and hashing,
// and hash collisions never replace exact identity comparison.
trait ErasedIdentity: Send + Sync {
    fn kind(&self) -> TypeId;
    fn as_any(&self) -> &dyn Any;
    fn eq(&self, other: &dyn ErasedIdentity) -> bool;
    fn hash_erased(&self, state: &mut dyn Hasher);
}

struct ComponentIdentity<T: TlsPoolComponent> {
    value: T::Identity,
    _component: PhantomData<fn() -> T>,
}

impl<T: TlsPoolComponent> ErasedIdentity for ComponentIdentity<T> {
    fn kind(&self) -> TypeId {
        TypeId::of::<T>()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn eq(&self, other: &dyn ErasedIdentity) -> bool {
        other
            .as_any()
            .downcast_ref::<Self>()
            .is_some_and(|other| self.value == other.value)
    }

    fn hash_erased(&self, mut state: &mut dyn Hasher) {
        self.value.hash(&mut state);
    }
}

// Keep keylog's already-erased Arc directly, without allocating another adapter.
enum SharedComponent {
    Custom(Box<dyn ErasedIdentity>),
    KeyLog(TlsComponentIdentity<dyn KeyLogSink>),
}

// Keep a custom verifier, configuration hook and keylog sink inline together.
const INLINE_SHARED_COMPONENTS: usize = 3;
type SharedComponents = SmallVec<[SharedComponent; INLINE_SHARED_COMPONENTS]>;

impl SharedComponent {
    fn capture<T: TlsPoolComponent>(component: &T) -> Self {
        Self::Custom(Box::new(ComponentIdentity::<T> {
            value: component.pool_component_identity(),
            _component: PhantomData,
        }))
    }

    fn kind(&self) -> TypeId {
        match self {
            Self::Custom(identity) => identity.kind(),
            Self::KeyLog(_) => TypeId::of::<TlsKeyLog>(),
        }
    }
}

impl PartialEq for SharedComponent {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Custom(identity), Self::Custom(other_identity)) => {
                identity.eq(other_identity.as_ref())
            }
            (Self::KeyLog(sink), Self::KeyLog(other_sink)) => sink == other_sink,
            _ => false,
        }
    }
}

impl Eq for SharedComponent {}

impl Hash for SharedComponent {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.kind().hash(state);
        match self {
            Self::Custom(identity) => identity.hash_erased(state),
            Self::KeyLog(sink) => sink.hash(state),
        }
    }
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
            components: SmallVec::new(),
        }
    }

    /// Require a fresh connection that is discarded after use.
    #[must_use]
    pub const fn non_reusable() -> Self {
        Self {
            digest: [0; 2],
            reusable: false,
            components: None,
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
/// Ordinary settings are borrowed without allocation. Custom component identities
/// are captured in shared storage. Settings are
/// encoded in one canonical order, independent of setter order. Library adapters
/// should exhaustively destructure their configuration before setting fields,
/// so additions require an explicit pooling decision.
pub struct TlsPoolIdBuilder<'a> {
    overrides: Overrides<'a>,
    client_hello: ClientHelloSettings<'a>,
    opaque_override: bool,
    components: SharedComponents,
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
        /// Key logging policy; a custom sink is identified by its shared instance.
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
        /// Client credentials, compared by certificate chain and private key contents.
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
        /// Explicitly disable reuse for policy that can change within one instance.
        ///
        /// Components with stable identities should use [`Self::with_component`].
        pub fn opaque_override(mut self, present: bool) -> Self {
            self.opaque_override = present;
            self
        }
    }

    generate_set_and_with! {
        /// Capture a custom component's owned policy identity.
        ///
        /// Components are keyed by type, independently of setter order. Only the
        /// identity is retained; the component needs no general-purpose `Hash`
        /// implementation. Later policy changes cannot mutate this snapshot.
        pub fn component(mut self, value: &impl TlsPoolComponent) -> Self {
            self.insert_component(SharedComponent::capture(value));
            self
        }
    }

    fn insert_component(&mut self, component: SharedComponent) {
        match self
            .components
            .binary_search_by_key(&component.kind(), SharedComponent::kind)
        {
            Ok(index) => self.components[index] = component,
            Err(index) => self.components.insert(index, component),
        }
    }

    /// Finish the identity, returning `None` when no overrides are present.
    pub fn build(mut self) -> Option<TlsPoolId> {
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
        let reusable = !self.opaque_override;
        let keylog = match keylog.map(|value| &value.0) {
            Some(KeyLogIntent::Environment) => Some(ComparableKeyLog::Environment),
            Some(KeyLogIntent::Disabled) => Some(ComparableKeyLog::Disabled),
            Some(KeyLogIntent::File(path)) => Some(ComparableKeyLog::File(path)),
            Some(KeyLogIntent::Custom(sink)) => {
                self.insert_component(SharedComponent::KeyLog(TlsComponentIdentity::shared(sink)));
                Some(ComparableKeyLog::Custom)
            }
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
            client_auth: client_auth.map(|auth| match &auth.0 {
                ClientAuth::SelfSigned => ComparableClientAuth::SelfSigned,
                ClientAuth::Single(data) => ComparableClientAuth::Single {
                    format: discriminant(&data.private_key),
                    private_key: data.private_key.secret_der(),
                    cert_chain: &data.cert_chain,
                },
            }),
        };
        let has_shared = !self.components.is_empty();
        if reusable && !has_shared && settings == ComparableOverrides::default() {
            return None;
        }
        Some(TlsPoolId {
            digest: policy_digest(b"rama.tls.overrides.v4", &settings),
            reusable,
            components: has_shared.then(|| Arc::new(self.components)),
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
    client_auth: Option<ComparableClientAuth<'a>>,
}

#[derive(PartialEq, Eq, Hash)]
enum ComparableKeyLog<'a> {
    Environment,
    Disabled,
    File(&'a str),
    Custom,
}

#[derive(PartialEq, Eq, Hash)]
enum ComparableClientAuth<'a> {
    SelfSigned,
    Single {
        format: Discriminant<PrivateKeyDer<'static>>,
        private_key: &'a [u8],
        cert_chain: &'a [CertificateDer<'static>],
    },
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
        ClientAuth, ClientAuthData, TlsServerCertPin, TlsServerCertPinSet, TlsServerCertPins,
        TlsServerTrustAnchors,
    };
    use crate::keylog::NoopKeyLogSink;
    use rama_crypto::pki_types::PrivatePkcs8KeyDer;
    use rama_utils::octets::kib;
    use std::{
        hash::Hasher,
        ptr,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[derive(Debug, Clone, Copy)]
    struct TestProvider;

    impl TlsClientConfigProvider for TestProvider {
        fn pool_id(&self, extensions: &Extensions) -> Option<TlsPoolId> {
            TlsPoolId::builder()
                .maybe_with_verify(extensions.get_ref::<TlsServerVerify>())
                .maybe_with_client_auth(extensions.get_ref::<TlsClientAuth>())
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

        let default_policy = TlsConnectionReuse::new(TestProvider, &plain);
        let insecure_policy = TlsConnectionReuse::new(TestProvider, &insecure);
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
    fn equivalent_request_credentials_allow_reuse() {
        let request = Extensions::new();
        request.insert(TlsClientAuth(ClientAuth::SelfSigned));
        let policy = TlsConnectionReuse::new(TestProvider, &request);
        assert!(policy.is_reusable());
        assert!(policy.matches(&request));
        assert!(!policy.matches(&Extensions::new()));
    }

    #[test]
    fn custom_keylog_identity_retains_and_distinguishes_sinks() {
        let sink: Arc<dyn KeyLogSink> = Arc::new(NoopKeyLogSink);
        let weak = Arc::downgrade(&sink);
        let intent = TlsKeyLog(KeyLogIntent::Custom(sink.clone()));
        let id = TlsPoolId::builder().with_keylog(&intent).build().unwrap();
        let clone = TlsKeyLog(KeyLogIntent::Custom(sink.clone()));
        assert!(id.is_reusable());
        assert_eq!(
            Some(id.clone()),
            TlsPoolId::builder().with_keylog(&clone).build()
        );
        let replacement = TlsKeyLog(KeyLogIntent::Custom(Arc::new(NoopKeyLogSink)));
        assert_ne!(
            Some(id.clone()),
            TlsPoolId::builder().with_keylog(&replacement).build()
        );
        drop((sink, intent, clone));
        assert!(
            weak.upgrade().is_some(),
            "the identity must prevent address reuse"
        );
        drop(id);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn shared_component_order_replacement_and_lifetime_are_preserved() {
        struct Verifier(Arc<()>);

        impl TlsPoolComponent for Verifier {
            type Identity = TlsComponentIdentity<()>;

            fn pool_component_identity(&self) -> Self::Identity {
                TlsComponentIdentity::shared(&self.0)
            }
        }

        struct Hook(Arc<()>);

        impl TlsPoolComponent for Hook {
            type Identity = TlsComponentIdentity<()>;

            fn pool_component_identity(&self) -> Self::Identity {
                TlsComponentIdentity::shared(&self.0)
            }
        }

        let verifier = Arc::new(Verifier(Arc::new(())));
        let hook = Arc::new(Hook(Arc::new(())));
        let weak = Arc::downgrade(&verifier.0);
        let id = TlsPoolId::builder()
            .with_component(verifier.as_ref())
            .with_component(hook.as_ref())
            .build()
            .unwrap();
        assert_eq!(
            Some(id.clone()),
            TlsPoolId::builder()
                .with_component(hook.as_ref())
                .with_component(verifier.as_ref())
                .build()
        );
        let replacement = Arc::new(Verifier(Arc::new(())));
        assert_ne!(
            Some(id.clone()),
            TlsPoolId::builder()
                .with_component(verifier.as_ref())
                .with_component(hook.as_ref())
                .with_component(replacement.as_ref())
                .build()
        );
        drop(verifier);
        assert!(weak.upgrade().is_some());
        drop(id);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn custom_components_compare_instances_even_with_equal_settings_digests() {
        struct Hook(Arc<dyn Fn() + Send + Sync>);

        impl TlsPoolComponent for Hook {
            type Identity = TlsComponentIdentity<dyn Fn() + Send + Sync>;

            fn pool_component_identity(&self) -> Self::Identity {
                TlsComponentIdentity::shared(&self.0)
            }
        }

        let callback: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
        let weak = Arc::downgrade(&callback);
        let hook = Arc::new(Hook(callback.clone()));
        let wrapper_clone = Arc::new(Hook(callback));
        let replacement = Arc::new(Hook(Arc::new(|| {})));
        let id = TlsPoolId::builder()
            .with_component(hook.as_ref())
            .build()
            .unwrap();
        let same = TlsPoolId::builder()
            .with_component(wrapper_clone.as_ref())
            .build()
            .unwrap();
        let other = TlsPoolId::builder()
            .with_component(replacement.as_ref())
            .build()
            .unwrap();
        assert_eq!(id.digest, other.digest, "common settings are identical");
        assert_eq!(id, same, "wrapper allocation is not the policy instance");
        assert_eq!(policy_digest(b"test", &id), policy_digest(b"test", &same));
        assert_ne!(id, other, "custom identity uses exact instance comparison");
        drop(hook);
        drop(wrapper_clone);
        drop(same);
        assert!(
            weak.upgrade().is_some(),
            "the remaining ID owns the callback"
        );
        drop(id);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn value_identities_compare_equal_across_distinct_components() {
        struct Policy(&'static str);

        impl TlsPoolComponent for Policy {
            type Identity = &'static str;

            fn pool_component_identity(&self) -> Self::Identity {
                self.0
            }
        }

        let first = Policy("trusted");
        let equal = Policy("trusted");
        let other = Policy("untrusted");
        let id = |policy| TlsPoolId::builder().with_component(policy).build();
        assert!(!ptr::eq(&first, &equal));
        assert_eq!(id(&first), id(&equal));
        assert_ne!(id(&first), id(&other));
        assert_eq!(
            policy_digest(b"test", &id(&first)),
            policy_digest(b"test", &id(&equal))
        );
    }

    #[test]
    fn identity_hash_collisions_do_not_allow_reuse() {
        #[derive(PartialEq, Eq)]
        struct Identity(u64);

        impl Hash for Identity {
            fn hash<H: Hasher>(&self, state: &mut H) {
                0_u8.hash(state);
            }
        }

        struct Policy(u64);

        impl TlsPoolComponent for Policy {
            type Identity = Identity;

            fn pool_component_identity(&self) -> Self::Identity {
                Identity(self.0)
            }
        }

        let first = TlsPoolId::builder().with_component(&Policy(1)).build();
        let second = TlsPoolId::builder().with_component(&Policy(2)).build();
        assert_eq!(
            policy_digest(b"test", &first),
            policy_digest(b"test", &second)
        );
        assert_ne!(first, second);
    }

    #[test]
    fn identity_snapshot_survives_policy_changes_and_component_drop() {
        struct Policy(AtomicU64);

        impl TlsPoolComponent for Policy {
            type Identity = u64;

            fn pool_component_identity(&self) -> Self::Identity {
                self.0.load(Ordering::Relaxed)
            }
        }

        let (first, first_hash, restored) = {
            let policy = Policy(AtomicU64::new(1));
            let first = TlsPoolId::builder().with_component(&policy).build();
            let first_hash = policy_digest(b"test", &first);
            policy.0.store(2, Ordering::Relaxed);
            let second = TlsPoolId::builder().with_component(&policy).build();
            assert_ne!(first, second);
            policy.0.store(1, Ordering::Relaxed);
            let restored = TlsPoolId::builder().with_component(&policy).build();
            (first, first_hash, restored)
        };
        // The stack-allocated component is gone; only its captured values remain.
        assert_eq!(first, restored);
        assert_eq!(first_hash, policy_digest(b"test", &first));
    }

    #[test]
    fn identical_values_from_different_component_types_do_not_match() {
        struct Verifier;
        struct Hook;

        impl TlsPoolComponent for Verifier {
            type Identity = u64;

            fn pool_component_identity(&self) -> Self::Identity {
                1
            }
        }

        impl TlsPoolComponent for Hook {
            type Identity = u64;

            fn pool_component_identity(&self) -> Self::Identity {
                1
            }
        }

        assert_ne!(
            TlsPoolId::builder().with_component(&Verifier).build(),
            TlsPoolId::builder().with_component(&Hook).build(),
        );
    }

    #[test]
    fn credentials_compare_both_private_key_and_certificate_chain() {
        let make = |key: u8, cert: u8| {
            TlsClientAuth(ClientAuth::Single(ClientAuthData {
                private_key: PrivatePkcs8KeyDer::from(vec![key]).into(),
                cert_chain: vec![CertificateDer::from(vec![cert])],
            }))
        };
        let original = make(1, 2);
        let cloned = original.clone();
        let id = TlsPoolId::builder()
            .with_client_auth(&original)
            .build()
            .unwrap();
        assert!(id.is_reusable());
        assert_eq!(
            Some(id.clone()),
            TlsPoolId::builder().with_client_auth(&cloned).build()
        );
        for changed in [
            make(2, 2),
            make(1, 3),
            TlsClientAuth(ClientAuth::SelfSigned),
        ] {
            assert_ne!(
                Some(id.clone()),
                TlsPoolId::builder().with_client_auth(&changed).build()
            );
        }
    }

    #[test]
    fn proxy_reuse_matches_caller_tunnel_settings() {
        let plain = Extensions::new();
        let tunnel = TlsTunnel {
            server_identity: Some(Host::from_static("proxy.example")),
            application_protocol: None,
            alpn: Some(TlsAlpn::http_2()),
        };
        let first = Extensions::new();
        first.insert(tunnel.clone());
        let same = Extensions::new();
        same.insert(tunnel.clone());
        let different = Extensions::new();
        different.insert(TlsTunnel {
            alpn: Some(TlsAlpn::http_1()),
            ..tunnel
        });
        let explicit = TlsConnectionReuse::tunnel(TestProvider, &first);
        assert!(explicit.is_reusable());
        assert!(explicit.matches(&same));
        assert!(!explicit.matches(&different));
        assert!(!explicit.matches(&plain));
        let default = TlsConnectionReuse::tunnel(TestProvider, &plain);
        assert!(default.matches(&plain));
        assert!(!default.matches(&same));
    }

    #[test]
    fn origin_and_proxy_reuse_restrictions_compose() {
        let request = Extensions::new();
        request.insert(TlsServerVerify(ServerVerifyMode::Disable));
        let connection = Extensions::new();
        TlsConnectionReuse::tunnel(TestProvider, &Extensions::new()).publish(&connection);
        assert!(
            !connection
                .get_ref::<ConnectionReuse>()
                .unwrap()
                .is_complete()
        );
        TlsConnectionReuse::new(TestProvider, &request).publish(&connection);
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
        TlsConnectionReuse::tunnel(TestProvider, &Extensions::new()).publish(&connection);
        TlsConnectionReuse::new(TestProvider, &Extensions::new()).publish(&connection);
        assert!(
            connection
                .get_ref::<ConnectionReuse>()
                .unwrap()
                .is_reusable()
        );
    }

    fn id_from_hash(value: &impl Hash) -> TlsPoolId {
        TlsPoolId {
            digest: policy_digest(b"test", value),
            reusable: true,
            components: None,
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
    fn opaque_override_prevents_reuse_but_retains_comparable_settings() {
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
        assert_ne!(alone, combined);
        assert!(!alone.is_reusable());
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
        assert!(std::mem::size_of::<TlsPoolId>() <= 32);
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
