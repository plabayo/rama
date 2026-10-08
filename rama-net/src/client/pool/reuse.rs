//! Key based reuse rules for pooled connections.

use core::any::{Any, TypeId};
use core::fmt;
use core::hash::{Hash, Hasher};
use std::sync::{Arc, LazyLock};

use ahash::RandomState;
use rama_core::extensions::{Extension, Extensions};

/// Exact identity of the reuse requirements of a connection or a request.
///
/// Keys compare by value. Their hash only indexes them: distinct keys never
/// match on a hash collision. Keys built from a type or inline bits do not
/// allocate; [`Self::and`] allocates its composition once, which clones share.
#[derive(Clone)]
pub struct ReuseKey {
    hash: u64,
    repr: Repr,
}

#[derive(Clone)]
enum Repr {
    One(KeyPart),
    Many(Arc<[KeyPart]>),
}

#[derive(Clone)]
enum KeyPart {
    // Split bits keep the part 8-byte aligned, and so the key compact.
    Bits(TypeId, [u64; 2]),
    Value(Arc<dyn ErasedKey>),
}

// One state per process: equal keys hash equally wherever they are built,
// while request-controlled values cannot be chosen to collide.
static KEY_HASHER: LazyLock<RandomState> = LazyLock::new(RandomState::new);
static BITS_SEED: LazyLock<[u64; 2]> =
    LazyLock::new(|| [KEY_HASHER.hash_one(0_u8), KEY_HASHER.hash_one(1_u8)]);

/// Folded multiply: the mixing step of fast keyed hashes, a few cycles.
const fn fold(a: u64, b: u64) -> u64 {
    let full = (a as u128).wrapping_mul(b as u128);
    (full as u64) ^ ((full >> 64) as u64)
}

/// Odd base of the polynomial combining part hashes, which keeps a
/// composition's hash independent of how its parts were grouped.
const PART_BASE: u64 = 0x9e37_79b9_7f4a_7c15;

impl ReuseKey {
    /// The key of `T` itself, for fixed requirements or a classifier.
    ///
    /// Equal to `Self::from_bits::<T>(0)`.
    #[must_use]
    pub fn of<T: ?Sized + 'static>() -> Self {
        Self::from_bits::<T>(0)
    }

    /// Inline bits, such as an id or a digest, in the namespace of `T`.
    #[must_use]
    pub fn from_bits<T: ?Sized + 'static>(bits: u128) -> Self {
        let [high, low] = [(bits >> 64) as u64, bits as u64];
        // A keyed fold rather than the general hasher: request keys are built
        // on every checkout. The type is left to equality: keys a pool indexes
        // together share theirs.
        let [k0, k1] = *BITS_SEED;
        let hash = fold(fold(high ^ k0, low ^ k1), k0 ^ PART_BASE);
        Self::from_part(hash, KeyPart::Bits(TypeId::of::<T>(), [high, low]))
    }

    /// A value compared with its own `Eq`, allocated once.
    #[must_use]
    pub fn new<T: Eq + Hash + fmt::Debug + Send + Sync + 'static>(value: T) -> Self {
        Self::from_arc(Arc::new(value))
    }

    /// A value compared with its own `Eq`, sharing an existing allocation.
    #[must_use]
    pub fn from_arc<T: Eq + Hash + fmt::Debug + Send + Sync + 'static>(value: Arc<T>) -> Self {
        let hash = KEY_HASHER.hash_one((TypeId::of::<T>(), &*value));
        Self::from_part(hash, KeyPart::Value(value))
    }

    /// Both keys in order, equal only to a composition of equal keys.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        let shift = PART_BASE.wrapping_pow(other.parts().len() as u32);
        let hash = self.hash.wrapping_mul(shift).wrapping_add(other.hash);
        let mut parts = Vec::with_capacity(self.parts().len() + other.parts().len());
        for key in [self, other] {
            match key.repr {
                Repr::One(part) => parts.push(part),
                Repr::Many(many) => parts.extend(many.iter().cloned()),
            }
        }
        Self {
            hash,
            repr: Repr::Many(parts.into()),
        }
    }

    fn from_part(hash: u64, part: KeyPart) -> Self {
        Self {
            hash,
            repr: Repr::One(part),
        }
    }

    fn parts(&self) -> &[KeyPart] {
        match &self.repr {
            Repr::One(part) => core::slice::from_ref(part),
            Repr::Many(parts) => parts,
        }
    }
}

impl PartialEq for ReuseKey {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.parts() == other.parts()
    }
}

impl Eq for ReuseKey {}

impl Hash for ReuseKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

impl fmt::Debug for ReuseKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.parts()).finish()
    }
}

impl PartialEq for KeyPart {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Bits(kind, bits), Self::Bits(other_kind, other_bits)) => {
                kind == other_kind && bits == other_bits
            }
            (Self::Value(value), Self::Value(other)) => {
                Arc::ptr_eq(value, other) || value.eq_erased(other.as_any())
            }
            _ => false,
        }
    }
}

impl fmt::Debug for KeyPart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bits(kind, [high, low]) => f
                .debug_tuple("Bits")
                .field(kind)
                .field(&((u128::from(*high) << 64) | u128::from(*low)))
                .finish(),
            Self::Value(value) => value.fmt_erased(f),
        }
    }
}

trait ErasedKey: Send + Sync + 'static {
    fn as_any(&self) -> &dyn Any;
    fn eq_erased(&self, other: &dyn Any) -> bool;
    fn fmt_erased(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
}

impl<T: Eq + fmt::Debug + Send + Sync + 'static> ErasedKey for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn eq_erased(&self, other: &dyn Any) -> bool {
        other.downcast_ref::<T>() == Some(self)
    }

    fn fmt_erased(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Connection-owned requirements for reusing an established transport.
///
/// A connection serves a request whose key equals the connection's key. Pools
/// derive a request's key once per [classifier](Self::classifier) and index
/// connections by key, so a checkout does not test each pooled connection.
/// Methods must be deterministic, nonblocking and side-effect free; pools call
/// them outside their locks.
///
/// A requirement beyond the pool's connection id maps to a cheap exact key,
/// such as `ReuseKey::from_bits::<Tenant>(id)` for a tenant, `ReuseKey::from_arc`
/// of a shared authenticated identity, or `ReuseKey::new` of a pinned SPKI digest:
///
/// ```
/// use rama_core::extensions::{Extension, Extensions};
/// use rama_net::client::pool::{ConnectionReuse, ConnectionReusePolicy, ReuseKey};
///
/// #[derive(Debug, Clone, Copy, Extension)]
/// struct Tenant(u64);
///
/// /// A connection authenticated for a tenant only serves that tenant.
/// #[derive(Debug)]
/// struct TenantReuse(Tenant);
///
/// impl ConnectionReusePolicy for TenantReuse {
///     fn classifier(&self) -> ReuseKey {
///         ReuseKey::of::<Self>()
///     }
///
///     fn connection_key(&self) -> Option<ReuseKey> {
///         Some(ReuseKey::from_bits::<Tenant>(self.0.0.into()))
///     }
///
///     fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
///         let tenant = input.get_ref::<Tenant>()?;
///         Some(ReuseKey::from_bits::<Tenant>(tenant.0.into()))
///     }
/// }
///
/// let reuse = ConnectionReuse::new(TenantReuse(Tenant(7)));
/// let request = Extensions::new();
/// request.insert(Tenant(7));
/// assert!(reuse.matches(&request));
/// request.insert(Tenant(8));
/// assert!(!reuse.matches(&request));
/// ```
pub trait ConnectionReusePolicy: fmt::Debug + Send + Sync + 'static {
    /// Identity of [`Self::request_key`]: policies with equal classifiers must
    /// derive equal keys for every request.
    fn classifier(&self) -> ReuseKey;

    /// This connection's key, captured when it was established, or `None` if
    /// the connection must not be retained after its establishing request.
    fn connection_key(&self) -> Option<ReuseKey>;

    /// The key a connection needs to serve `input`, or `None` if no connection
    /// of this classifier may serve it.
    fn request_key(&self, input: &Extensions) -> Option<ReuseKey>;
}

/// Reuse requirements published by a connector on its established connection.
///
/// Without this extension, the pool's connection identifier determines reuse.
/// Connectors whose policy varies by request must publish their requirements.
/// Layered transports can combine requirements once with [`Self::and`]. Pools
/// read it once, when the connection is added.
#[derive(Clone, Debug, Extension)]
pub struct ConnectionReuse {
    policy: Arc<dyn ConnectionReusePolicy>,
    classifier: ReuseKey,
    key: Option<ReuseKey>,
    complete: bool,
}

impl ConnectionReuse {
    /// Publish the complete reuse policy for the requested endpoint.
    ///
    /// This describes policy compatibility, not peer authentication. Transport
    /// layers which cover only an intermediary must use [`Self::restriction`].
    pub fn new(policy: impl ConnectionReusePolicy) -> Self {
        Self {
            classifier: policy.classifier(),
            key: policy.connection_key(),
            policy: Arc::new(policy),
            complete: true,
        }
    }

    /// Publish an additional transport restriction without certifying the
    /// requested endpoint's complete policy, such as TLS to an intermediary.
    pub fn restriction(policy: impl ConnectionReusePolicy) -> Self {
        Self::new(policy).into_restriction()
    }

    /// Whether a connector has published the requested endpoint's complete policy.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Preserve the requirements while limiting them to an inner transport.
    ///
    /// A tunnel layer must apply this to its combined inner requirements before
    /// passing the connection to the requested endpoint's connector.
    #[must_use]
    pub fn into_restriction(mut self) -> Self {
        self.complete = false;
        self
    }

    /// Whether the established connection may be retained for later requests.
    #[must_use]
    pub fn is_reusable(&self) -> bool {
        self.key.is_some()
    }

    /// Identity of the rules deriving request keys.
    #[must_use]
    pub fn classifier(&self) -> &ReuseKey {
        &self.classifier
    }

    /// The connection's key, `None` if it must not be reused.
    #[must_use]
    pub fn key(&self) -> Option<&ReuseKey> {
        self.key.as_ref()
    }

    /// The key a connection of this classifier needs to serve `input`.
    #[must_use]
    pub fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
        self.policy.request_key(input)
    }

    /// Check the request against the established connection's requirements.
    #[must_use]
    pub fn matches(&self, input: &Extensions) -> bool {
        self.key
            .as_ref()
            .is_some_and(|key| self.request_key(input).as_ref() == Some(key))
    }

    /// Require both transport layers to accept reuse of the connection.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        let complete = self.complete || other.complete;
        let classifier = self.classifier.clone().and(other.classifier.clone());
        let key = self
            .key
            .clone()
            .zip(other.key.clone())
            .map(|(first, second)| first.and(second));
        Self {
            policy: Arc::new(CombinedReuse(self, other)),
            classifier,
            key,
            complete,
        }
    }
}

#[derive(Debug)]
struct CombinedReuse(ConnectionReuse, ConnectionReuse);

impl ConnectionReusePolicy for CombinedReuse {
    fn classifier(&self) -> ReuseKey {
        self.0.classifier.clone().and(self.1.classifier.clone())
    }

    fn connection_key(&self) -> Option<ReuseKey> {
        Some(self.0.key.clone()?.and(self.1.key.clone()?))
    }

    fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
        Some(self.0.request_key(input)?.and(self.1.request_key(input)?))
    }
}

/// Where a pool files a connection: the requirements it was added with.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum LaneKey {
    /// Connections without [`ConnectionReuse`]: any request of their pool id
    /// may use them.
    Unrestricted,
    /// Connections with requirements. Boxed, which keeps a stored
    /// connection's hot counters close together.
    Keyed(Box<KeyedLane>),
}

/// Connections whose requirements derive `key` in `class`. Identified by the
/// class's classifier and the key.
#[derive(Clone, Debug)]
pub(super) struct KeyedLane {
    pub(super) class: ReuseClass,
    pub(super) key: ReuseKey,
}

impl PartialEq for KeyedLane {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.class.classifier == other.class.classifier
    }
}

impl Eq for KeyedLane {}

impl Hash for KeyedLane {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.class.classifier.hash(state);
        self.key.hash(state);
    }
}

impl LaneKey {
    /// The lane of a connection publishing `reuse`, `None` if the connection
    /// must not be retained.
    pub(super) fn of_connection(reuse: Option<&ConnectionReuse>) -> Option<Self> {
        match reuse {
            Some(reuse) => Some(Self::Keyed(Box::new(KeyedLane {
                key: reuse.key.clone()?,
                class: ReuseClass {
                    classifier: reuse.classifier.clone(),
                    policy: reuse.policy.clone(),
                },
            }))),
            None => Some(Self::Unrestricted),
        }
    }
}

/// The request key derivation shared by connections with one classifier.
#[derive(Clone, Debug)]
pub(super) struct ReuseClass {
    classifier: ReuseKey,
    policy: Arc<dyn ConnectionReusePolicy>,
}

impl ReuseClass {
    pub(super) fn classifier(&self) -> &ReuseKey {
        &self.classifier
    }

    /// The key of this class able to serve `input`, if any. Runs the
    /// connector's policy: call outside pool locks.
    pub(super) fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
        self.policy.request_key(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Hash)]
    struct Identity(&'static str);

    #[derive(Debug, PartialEq, Eq, Hash)]
    struct Other(&'static str);

    fn hash_of(key: &ReuseKey) -> u64 {
        KEY_HASHER.hash_one(key)
    }

    #[test]
    fn bits_are_namespaced_by_type() {
        assert_eq!(ReuseKey::from_bits::<u8>(7), ReuseKey::from_bits::<u8>(7));
        assert_ne!(ReuseKey::from_bits::<u8>(7), ReuseKey::from_bits::<u8>(8));
        assert_ne!(ReuseKey::from_bits::<u8>(7), ReuseKey::from_bits::<u16>(7));
        assert_eq!(ReuseKey::of::<u8>(), ReuseKey::from_bits::<u8>(0));
        assert_ne!(ReuseKey::of::<u8>(), ReuseKey::of::<u16>());
    }

    #[test]
    fn values_compare_by_value_and_type() {
        let shared = Arc::new(Identity("a"));
        assert_eq!(
            ReuseKey::from_arc(shared.clone()),
            ReuseKey::from_arc(shared)
        );
        assert_eq!(ReuseKey::new(Identity("a")), ReuseKey::new(Identity("a")));
        assert_ne!(ReuseKey::new(Identity("a")), ReuseKey::new(Identity("b")));
        assert_ne!(ReuseKey::new(Identity("a")), ReuseKey::new(Other("a")));
        assert_ne!(ReuseKey::new(Identity("a")), ReuseKey::of::<Identity>());
    }

    #[test]
    fn equal_keys_hash_equally() {
        let pairs = [
            (ReuseKey::from_bits::<u8>(1), ReuseKey::from_bits::<u8>(1)),
            (ReuseKey::new(Identity("a")), ReuseKey::new(Identity("a"))),
            (
                ReuseKey::of::<u8>().and(ReuseKey::new(Identity("a"))),
                ReuseKey::of::<u8>().and(ReuseKey::new(Identity("a"))),
            ),
        ];
        for (first, second) in pairs {
            assert_eq!(first, second);
            assert_eq!(hash_of(&first), hash_of(&second));
        }
    }

    #[test]
    fn composition_is_ordered_and_exact() {
        let a = || ReuseKey::from_bits::<u8>(1);
        let b = || ReuseKey::new(Identity("b"));
        assert_eq!(a().and(b()), a().and(b()));
        assert_ne!(a().and(b()), b().and(a()));
        assert_ne!(a().and(b()), a());
        assert_ne!(a().and(a()), a());
        assert_eq!(
            a().and(b()).and(a()),
            a().and(b().and(a())),
            "composition is associative"
        );
    }

    #[derive(Debug, Extension)]
    struct RequestId(u8);

    #[derive(Debug)]
    struct ById {
        id: u8,
        reusable: bool,
    }

    impl ConnectionReusePolicy for ById {
        fn classifier(&self) -> ReuseKey {
            ReuseKey::of::<Self>()
        }

        fn connection_key(&self) -> Option<ReuseKey> {
            self.reusable
                .then(|| ReuseKey::from_bits::<RequestId>(self.id.into()))
        }

        fn request_key(&self, input: &Extensions) -> Option<ReuseKey> {
            let id = input.get_ref::<RequestId>()?;
            Some(ReuseKey::from_bits::<RequestId>(id.0.into()))
        }
    }

    fn input(id: u8) -> Extensions {
        let extensions = Extensions::new();
        extensions.insert(RequestId(id));
        extensions
    }

    #[test]
    fn composition_requires_every_layer() {
        let reuse = |id| ConnectionReuse::new(ById { id, reusable: true });
        let both = reuse(1).and(reuse(1));
        assert!(both.matches(&input(1)));
        assert!(!both.matches(&input(2)));
        assert!(!both.matches(&Extensions::new()));
        assert!(!reuse(1).and(reuse(2)).matches(&input(1)));
        assert_eq!(both.classifier(), reuse(2).and(reuse(3)).classifier());
        assert_ne!(both.key(), reuse(1).key());

        let opaque = both.and(ConnectionReuse::new(ById {
            id: 1,
            reusable: false,
        }));
        assert!(!opaque.is_reusable());
        assert!(!opaque.matches(&input(1)));
    }
}
