#![allow(clippy::disallowed_types)]
//! Extensions passed to and between services
//!
//! # State
//!
//! [`rama`] supports two kinds of states:
//!
//! 1. static state: this state can be a part of the service struct or captured by a closure
//! 2. dynamic state: these can be injected as [`Extensions`]s in Requests/Responses/Connections if it [`ExtensionsRef`]
//!
//! Any state that is optional, and especially optional state injected by middleware, can be inserted using extensions.
//! It is however important to try as much as possible to then also consume this state in an approach that deals
//! gracefully with its absence. Good examples of this are header-related inputs. Headers might be set or not,
//! and so absence of [`Extensions`]s that might be created as a result of these might reasonably not exist.
//! It might of course still mean the app returns an error response when it is absent, but it should not unwrap/panic.
//!
//! [`rama`]: crate
//!
//! # Examples
//!
//! ## Example: Extensions
//! ```
//! use rama_core::extensions::{Extensions, Extension};
//!
//! #[derive(Debug, Clone, PartialEq)]
//! struct MyExt(i32);
//! impl Extension for MyExt {}
//!
//! let mut ext = Extensions::default();
//! ext.insert(MyExt(5));
//! assert_eq!(ext.get_ref::<MyExt>(), Some(&MyExt(5)));
//! ```

use core::any::{Any, TypeId};
use core::fmt;
use core::hash::{Hash, Hasher};
use core::pin::Pin;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::std::{boxed::Box, sync::Arc, vec::Vec};

pub use rama_macros::{Extension, FromExtensions};
use rama_utils::collections::AppendOnlyVec;
use rama_utils::macros::impl_deref;

#[derive(Clone)]
/// A type map of protocol extensions.
///
/// [`Extension`]s are internally stored in a type erased [`Arc`]. Since values
/// are stored in an [`Arc`] there are extra methods exposed that build on top
/// of this and leverage characteristics of an [`Arc`] to expose things like
/// cheap cloning of the Arc.
///
/// [`Extensions`] may have an optional [`parent`][Self::parent]: the
/// [`Extensions`] this one was forked from. Lookups walk the parent chain when
/// the local [`Extension`]s don't have the requested type. The parent relationship is
/// best described as "I'm layered on top of that, but I'm not exactly the same":
/// - Retry attempts fork from the original request (don't leak failed extensions)
/// - Responses fork the request (response != request)
/// - H2 streams fork from underlying H2 connection (nested connection with isolated properties)
///
/// Connection's who logically map one-to-one we don't fork and we just pass the [`Extensions`]
/// up, examples are:
/// - TLS layered on top of TCP
/// - HTTP layered on top of TLS
/// - ...
pub struct Extensions {
    node: Arc<Node>,
}

/// One level of an [`Extensions`] chain, shared by all clones of its handle,
/// so cloning a handle is a reference count and forking one allocation.
// `repr(C)`: a lookup that skips the level reads the links and the filter
// only, which share the first cache line with the first entries.
#[repr(C)]
struct Node {
    /// The level whose entries a [`Extensions::with_base`] view shows instead
    /// of its own (always empty) ones. That level is never a view itself.
    view_of: Option<Extensions>,
    parent: Option<Extensions>,
    entries: Store,
}

/// Entries an [`Extensions`] level holds without allocating storage of its
/// own: most levels hold no more, and are then a single allocation.
const INLINE_ENTRIES: usize = 6;

/// The first storage a level allocates, once its inline entries are used up,
/// holds `2^SPILL_BIN_OFFSET` entries, every later one double the one before.
const SPILL_BIN_OFFSET: u32 = 4;

/// The entries of one [`Extensions`] level.
///
/// Every entry is pushed with its [`Store::seen_bit`] as tag, which makes the
/// tags of the entries (see [`AppendOnlyVec::push_tagged`]) a tiny bloom
/// filter over the [`TypeId`]s pushed so far. Type lookups are dominated by
/// misses (optional extensions that were never inserted) and each miss walks
/// every level of the chain and every entry in it. A level whose filter has
/// none of the requested bits cannot hold a match, so it is skipped in O(1)
/// instead of scanned.
#[derive(Default)]
struct Store {
    entries: AppendOnlyVec<TypeErasedExtension, INLINE_ENTRIES, SPILL_BIN_OFFSET>,
}

/// Bit of the [`Store`] filter reserved for [`Egress`] and [`Ingress`] wrappers.
///
/// Lookups recurse into these wrappers, so a level holding one can never be
/// skipped, whatever the requested type. They get their own bit rather than a
/// [`type_bit`] so this holds without any per-type bookkeeping.
const WRAPPER_BIT: usize = 1 << (usize::BITS - 1);

/// Number of slots a [`TypeId`] can hash to: every bit of the [`Store`]
/// filter except [`WRAPPER_BIT`].
const TYPE_SLOTS: usize = usize::BITS as usize - 1;

/// The slot of a [`TypeId`], below [`TYPE_SLOTS`].
///
/// `TypeId` hashes as 64 bits of an already well distributed 128-bit value,
/// so the hash is used as is, without another round of mixing.
#[inline(always)]
fn type_slot(id: TypeId) -> usize {
    struct Fold(u64);

    impl Hasher for Fold {
        #[inline(always)]
        fn finish(&self) -> u64 {
            self.0
        }

        #[inline(always)]
        fn write(&mut self, bytes: &[u8]) {
            for byte in bytes {
                self.0 = self.0.rotate_left(8) ^ u64::from(*byte);
            }
        }

        #[inline(always)]
        fn write_u64(&mut self, v: u64) {
            self.0 ^= v;
        }
    }

    let mut hasher = Fold(0);
    id.hash(&mut hasher);
    // a mask is cheaper than a modulo, the one slot left over folds into the last
    ((hasher.finish() as usize) & (usize::BITS as usize - 1)).min(TYPE_SLOTS - 1)
}

/// The bit a [`TypeId`] sets in the [`Store`] filter, never [`WRAPPER_BIT`].
#[inline(always)]
fn type_bit(id: TypeId) -> usize {
    1 << type_slot(id)
}

/// The target types of one multi-type lookup, indexed by [`type_slot`].
///
/// Testing an entry against every target costs one comparison per target.
/// The slots reduce this to a table read for the (vast) majority of entries
/// that are none of the targets, and to a comparison or two for the others.
///
/// Hidden and not part of the public API surface: `#[derive(FromExtensions)]`
/// builds it once per type through a [`TargetPlan`].
#[doc(hidden)]
pub struct Targets<const N: usize> {
    ids: [TypeId; N],
    /// Per slot: 1 + the index of the last target in that slot, 0 for none.
    head: [u16; usize::BITS as usize],
    /// Per target: the same for the target before it in its slot.
    next: [u16; N],
    /// The [`type_bit`] of every target, see [`Store::may_contain`].
    bits: usize,
}

impl<const N: usize> Targets<N> {
    #[inline(always)]
    fn new(ids: [TypeId; N]) -> Self {
        const {
            assert!(N < u16::MAX as usize, "too many extension targets");
        }
        let mut targets = Self {
            ids,
            head: [0; usize::BITS as usize],
            next: [0; N],
            bits: 0,
        };
        for (i, &id) in ids.iter().enumerate() {
            let slot = type_slot(id);
            targets.next[i] = targets.head[slot];
            targets.head[slot] = i as u16 + 1;
            targets.bits |= 1 << slot;
        }
        targets
    }
}

/// The [`Targets`] of a `#[derive(FromExtensions)]` type, built on first use.
///
/// The targets of such a type never change, so the derive keeps them in a
/// `static` instead of rebuilding them on every lookup.
///
/// Hidden and not part of the public API surface.
#[doc(hidden)]
pub struct TargetPlan<const N: usize> {
    /// Installed once: concurrent first uses race to build it, and the losers
    /// free theirs. Only needs `alloc`.
    targets: AtomicPtr<Targets<N>>,
}

impl<const N: usize> TargetPlan<N> {
    /// An empty plan, to be kept in a `static`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            targets: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// The targets, built from `ids` on the first call.
    #[inline]
    pub fn get(&self, ids: impl FnOnce() -> [TypeId; N]) -> &Targets<N> {
        let targets = self.targets.load(Ordering::Acquire);
        if targets.is_null() {
            return self.install(ids());
        }
        // Safety: an installed plan is never freed while `self` is borrowed.
        unsafe { &*targets }
    }

    #[cold]
    fn install(&self, ids: [TypeId; N]) -> &Targets<N> {
        let new = Box::into_raw(Box::new(Targets::new(ids)));
        let targets = match self.targets.compare_exchange(
            core::ptr::null_mut(),
            new,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => new,
            Err(installed) => {
                // Safety: `new` was just leaked from a box and never shared.
                drop(unsafe { Box::from_raw(new) });
                installed
            }
        };
        // Safety: an installed plan is never freed while `self` is borrowed.
        unsafe { &*targets }
    }
}

impl<const N: usize> Drop for TargetPlan<N> {
    fn drop(&mut self) {
        let targets = *self.targets.get_mut();
        if !targets.is_null() {
            // Safety: installed from a leaked box, and nothing borrows `self` anymore.
            drop(unsafe { Box::from_raw(targets) });
        }
    }
}

impl<const N: usize> Default for TargetPlan<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Extensions {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    /// The bit of the filter that an entry of type `T` sets.
    ///
    /// A constant for every `T`, so pushing a typed value needs no hashing.
    #[inline(always)]
    fn seen_bit_of<T: Extension>() -> usize {
        Self::seen_bit(TypeId::of::<T>())
    }

    #[inline(always)]
    fn seen_bit(id: TypeId) -> usize {
        if id == TypeId::of::<Egress<Extensions>>() || id == TypeId::of::<Ingress<Extensions>>() {
            WRAPPER_BIT
        } else {
            type_bit(id)
        }
    }

    fn push(&self, extension: TypeErasedExtension) -> usize {
        let bit = Self::seen_bit(extension.type_id);
        self.push_with_bit(extension, bit)
    }

    /// Push an entry whose [`Self::seen_bit`] is already known.
    #[inline(always)]
    fn push_with_bit(&self, extension: TypeErasedExtension, bit: usize) -> usize {
        self.entries.push_tagged(extension, bit)
    }

    /// Whether this level holds an [`Egress`] or [`Ingress`] wrapper. Read it
    /// after the entries to scan, then no wrapper among them is missed (see
    /// [`AppendOnlyVec::push_tagged`]).
    #[inline(always)]
    fn has_wrappers(&self) -> bool {
        self.entries.tags() & WRAPPER_BIT != 0
    }

    /// Whether a lookup for `targets` (the OR of their [`type_bit`]s) has to
    /// scan this level: false only if it can hold neither of them nor a wrapper.
    #[inline(always)]
    fn may_contain(&self, targets: usize) -> bool {
        self.entries.tags() & (targets | WRAPPER_BIT) != 0
    }
}

impl Extensions {
    /// Create an empty [`Extensions`] store with no parent.
    #[inline(always)]
    #[must_use]
    pub fn new() -> Self {
        Self::with_parent(None)
    }

    #[inline(always)]
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "one in-place initialization of a fresh allocation"
    )]
    fn with_parent(parent: Option<Self>) -> Self {
        // Built in place: the inline entries are most of a node and stay
        // uninitialized, so there is nothing to move into the allocation.
        let node = Arc::into_raw(Arc::<Node>::new_uninit())
            .cast::<Node>()
            .cast_mut();
        // Safety: the allocation is fresh, aligned for a `Node` and only
        // reachable through `node`. Every field but the inline entries, which
        // may stay uninitialized, is written before the pointer goes back to
        // an `Arc` of the layout it came from (`MaybeUninit<Node>`).
        let node = unsafe {
            (&raw mut (*node).view_of).write(None);
            (&raw mut (*node).parent).write(parent);
            AppendOnlyVec::init_in_place(&raw mut (*node).entries.entries);
            Arc::from_raw(node)
        };
        Self { node }
    }

    /// The entries of this level.
    #[inline(always)]
    fn store(&self) -> &Store {
        match &self.node.view_of {
            None => &self.node.entries,
            Some(owner) => &owner.node.entries,
        }
    }

    /// The handle of the level that owns the entries of this one.
    fn owner(&self) -> &Self {
        self.node.view_of.as_ref().unwrap_or(self)
    }

    /// Create a fresh child [`Extensions`] whose parent is this [`Extensions`] store.
    ///
    /// The child has its own empty top-level storage. Lookups that miss
    /// locally walk into the parent (and recursively up the chain). Inserts
    /// land on this child only, parents are never structurally mutated through
    /// the child. Existing extension values remain `Arc`-shared, so mutating
    /// their interior state is visible through both parent and child.
    #[must_use]
    pub fn fork(&self) -> Self {
        Self::with_parent(Some(self.clone()))
    }

    /// The parent [`Extensions`] this blob was forked from, if any.
    #[inline(always)]
    #[must_use]
    pub fn parent(&self) -> Option<&Self> {
        self.node.parent.as_ref()
    }

    /// Return a view of this [`Extensions`] chain layered on top of `base`.
    ///
    /// The toplevel extensions are still the same and are editable.
    /// Lookups resolve through this chain first falling back to `base`
    /// only when nothing matches. `base` is all the way at the bottom.
    ///
    /// Use this when you have an Extensions (chain) to which you want to apply
    /// defaults, e.g. `request_extensions().with_base(&base_extension_config)`
    #[must_use]
    pub fn with_base(&self, base: &Self) -> Self {
        let parent = match self.parent() {
            Some(parent) => parent.with_base(base),
            None => base.clone(),
        };
        Self {
            node: Arc::new(Node {
                view_of: Some(self.owner().clone()),
                parent: Some(parent),
                entries: Store::default(),
            }),
        }
    }

    /// Insert a type `T` into this [`Extensions`] store.
    ///
    /// This method returns a reference to the just inserted value.
    ///
    /// If the value you are inserting is an `Arc<T>`, prefer using
    /// [`Self::insert_arc`] to prevent the double indirection of storing
    /// an `Arc<Arc<T>>`.
    pub fn insert<T: Extension>(&self, val: T) -> &T {
        let extension = TypeErasedExtension::new(val);
        let idx = self
            .store()
            .push_with_bit(extension, Store::seen_bit_of::<T>());

        #[expect(
            clippy::unwrap_used,
            reason = "`downcast_ref` can only be none if TypeId doesn't match, but we just inserted this type"
        )]
        self.store().entries[idx].downcast_ref::<T>().unwrap()
    }

    /// Insert a type `Arc<T>` into this [`Extensions]` store.
    ///
    /// This method returns a a cloned Arc of the value just inserted
    ///
    /// If the value you are inserting is not an `Arc<T>` or you don't
    /// need a cloned `Arc<T>` prefer using [`Self::insert()`]
    pub fn insert_arc<T: Extension>(&self, val: Arc<T>) -> Arc<T> {
        let extension = TypeErasedExtension::new_arc(val);
        let idx = self
            .store()
            .push_with_bit(extension, Store::seen_bit_of::<T>());

        #[expect(
            clippy::unwrap_used,
            reason = "`cloned_downcast` can only be none if TypeId doesn't match, but we just inserted this type"
        )]
        self.store().entries[idx].cloned_downcast::<T>().unwrap()
    }

    /// Insert an already erased extension, retaining its original type identity.
    pub fn insert_erased(&self, extension: TypeErasedExtension) {
        self.store().push(extension);
    }

    /// Extend this [`Extensions`] store with the other [`Extensions`].
    ///
    /// The other [`Extensions`]s will be appended behind the current ones
    pub fn extend(&self, other: &Self) {
        for ext in other.store().entries.iter() {
            self.store().push(ext.clone());
        }
    }

    /// Returns true if the [`Extensions`] store contains the given type.
    ///
    /// This function is recursive and will traverse multiple nested [`Extensions`]
    /// stores to find the correct item. See [`Extensions::get_ref()`] for how this works.
    ///
    /// If you don't want any of this special logic and you just want to check this
    /// [`Extensions`] store, use [`Extensions::self_contains()`] instead.
    #[must_use]
    pub fn contains<T: Extension>(&self) -> bool {
        self.get_ref::<T>().is_some()
    }

    /// Returns true if this [`Extensions`] store contains the given type
    ///
    /// This only checks this [`Extensions`] store
    #[must_use]
    pub fn self_contains<T: Extension>(&self) -> bool {
        let type_id = TypeId::of::<T>();
        self.store()
            .entries
            .iter()
            .rev()
            .any(|item| item.type_id == type_id)
    }

    #[must_use]
    /// Get a reference to `T`. Walks the parent chain and the connection
    /// wrappers ([`Egress`] / [`Ingress`]) if not found locally.
    ///
    /// Search rule (single pass, newest insertion wins):
    ///
    /// 1. Iterate local entries newest -> oldest. For each entry:
    ///    - if its type matches `T`, return it,
    ///    - if it is an [`Egress<Extensions>`] or [`Ingress<Extensions>`]
    ///      wrapper, recurse into the wrapped blob with the same rule
    ///      (its own local first, then its wrappers, then its parent)
    ///      and return any match found,
    ///    - otherwise skip.
    /// 2. If still not found, recurse into the parent (same rule applied).
    ///
    /// Wrappers are spliced into the local scan in insertion order, so a
    /// connection-pointer detour inserted on this blob is treated as part of
    /// "local" for ordering purposes: a directly-inserted `T` and a wrapper
    /// containing `T` both compete by insertion time, newest wins. Parent is
    /// only consulted after the entire local scan (including wrapper
    /// recursion) finishes empty. The wrappers themselves can still be
    /// retrieved directly (or via [`Self::egress`] / [`Self::ingress`]).
    ///
    /// For a raw flat lookup, use [`Self::self_get_ref`].
    ///
    /// Returns the most recently inserted match, for the oldest, see [`Self::self_first_ref`].
    pub fn get_ref<T: Extension>(&self) -> Option<&T> {
        let target = TypeId::of::<T>();
        let egress_id = TypeId::of::<Egress<Self>>();
        let ingress_id = TypeId::of::<Ingress<Self>>();
        let store = self.store();
        if store.may_contain(type_bit(target)) {
            let chunks = store.entries.chunks();
            // Read after the chunks (see `AppendOnlyVec::push_tagged`).
            let has_wrappers = store.has_wrappers();
            for chunk in chunks.rev() {
                for ext in chunk.iter().rev() {
                    if ext.type_id == target {
                        if let Some(v) = ext.downcast_ref::<T>() {
                            return Some(v);
                        }
                    } else if has_wrappers
                        && ext.type_id == egress_id
                        && let Some(eg) = ext.downcast_ref::<Egress<Self>>()
                        && let Some(v) = eg.0.get_ref::<T>()
                    {
                        return Some(v);
                    } else if has_wrappers
                        && ext.type_id == ingress_id
                        && let Some(ig) = ext.downcast_ref::<Ingress<Self>>()
                        && let Some(v) = ig.0.get_ref::<T>()
                    {
                        return Some(v);
                    }
                }
            }
        }
        self.parent().and_then(|p| p.get_ref::<T>())
    }

    /// Raw flat [`Self::get_ref`]: returns the most recently inserted `T`, for the oldest, see [`Self::self_first_ref`].
    ///
    /// This only checks this [`Extensions`] store
    #[must_use]
    pub fn self_get_ref<T: Extension>(&self) -> Option<&T> {
        let type_id = TypeId::of::<T>();
        self.store()
            .entries
            .iter()
            .rev()
            .find(|item| item.type_id == type_id)
            .and_then(|ext| ext.downcast_ref())
    }

    #[must_use]
    /// Get an owned `Arc<T>`. Walks the parent chain and the structural
    /// connection wrappers if not found locally.
    ///
    /// See [`Self::get_ref`] for the search order.
    ///
    /// For a raw flat lookup (top-level only), use [`Self::self_get_arc`].
    pub fn get_arc<T: Extension>(&self) -> Option<Arc<T>> {
        let target = TypeId::of::<T>();
        let egress_id = TypeId::of::<Egress<Self>>();
        let ingress_id = TypeId::of::<Ingress<Self>>();
        let store = self.store();
        if store.may_contain(type_bit(target)) {
            let chunks = store.entries.chunks();
            // Read after the chunks (see `AppendOnlyVec::push_tagged`).
            let has_wrappers = store.has_wrappers();
            for chunk in chunks.rev() {
                for ext in chunk.iter().rev() {
                    if ext.type_id == target {
                        if let Some(v) = ext.cloned_downcast::<T>() {
                            return Some(v);
                        }
                    } else if has_wrappers
                        && ext.type_id == egress_id
                        && let Some(eg) = ext.downcast_ref::<Egress<Self>>()
                        && let Some(v) = eg.0.get_arc::<T>()
                    {
                        return Some(v);
                    } else if has_wrappers
                        && ext.type_id == ingress_id
                        && let Some(ig) = ext.downcast_ref::<Ingress<Self>>()
                        && let Some(v) = ig.0.get_arc::<T>()
                    {
                        return Some(v);
                    }
                }
            }
        }
        self.parent().and_then(|p| p.get_arc::<T>())
    }

    /// Raw flat [`Self::get_arc`]: returns the most recently inserted `T`
    ///
    /// This only checks this [`Extensions`] store
    #[must_use]
    pub fn self_get_arc<T: Extension>(&self) -> Option<Arc<T>> {
        let type_id = TypeId::of::<T>();
        self.store()
            .entries
            .iter()
            .rev()
            .find(|item| item.type_id == type_id)
            .and_then(|ext| ext.cloned_downcast())
    }

    /// Fetch several extension types in a single pass, returning a tuple of
    /// `Option<&T>` mirroring the requested tuple. Each slot uses the same
    /// search rule as [`Self::get_ref`] (newest-wins, walking the
    /// [`Egress`] / [`Ingress`] wrappers and the parent chain), but the whole
    /// structure is traversed only once instead of once per type.
    ///
    /// See [`Self::get_many_arc`] for an owned-[`Arc`] variant.
    pub fn get_many_ref<'a, T: GetManyRef<'a>>(&'a self) -> T::Output {
        T::get_many_ref(self)
    }

    /// Like [`Self::get_many_ref`], but returns a tuple of `Option<Arc<T>>`
    /// (cheap, owned [`Arc`] clones) instead of borrowed references, the
    /// multi-fetch counterpart of [`Self::get_arc`]. Same single-pass traversal.
    pub fn get_many_arc<T: GetManyArc>(&self) -> T::Output {
        T::get_many_arc(self)
    }

    /// Single iteration logic behind [`Self::get_many_ref`], [`Self::get_many_arc`]
    /// and `#[derive(FromExtensions)]`. Hidden and not part of the public
    /// API surface: call `get_many_ref`/`get_many_arc` or the derive instead.
    ///
    /// For each requested [`TypeId`] in `targets`, fill the matching slot in
    /// `out` with the newest matching entry, walking wrappers and the parent
    /// chain like [`Self::get_ref`]. Slots already `Some` are left untouched, so
    /// callers may pre-fill or reuse the buffer. `targets[i]` fills `out[i]`.
    ///
    /// Alongside the entry, each filled slot records its rank: the position of
    /// the entry in this single newest to oldest traversal. The newest entry
    /// visited is rank `0` and the count grows by one for every entry walked
    /// back (across wrappers and the parent chain). Comparing the ranks of two
    /// filled slots tells you which value was inserted more recently (0 = newest).
    ///
    /// A rank is a completely opaque type and should only be used to compare positions,
    /// it does not tell anything about the absolute position.
    #[doc(hidden)]
    #[inline]
    pub fn get_many_erased<'a, const N: usize>(
        &'a self,
        targets: &[TypeId; N],
        out: &mut [Option<(&'a TypeErasedExtension, usize)>; N],
    ) {
        self.get_many_targets(&Targets::new(*targets), out);
    }

    /// [`Self::get_many_erased`] for prepared `targets`, such as the ones a
    /// [`TargetPlan`] keeps between lookups.
    #[doc(hidden)]
    #[inline]
    pub fn get_many_targets<'a, const N: usize>(
        &'a self,
        targets: &Targets<N>,
        out: &mut [Option<(&'a TypeErasedExtension, usize)>; N],
    ) {
        let mut rank = 0;
        let mut remaining = out.iter().filter(|slot| slot.is_none()).count();
        self.get_many_erased_ranked(targets, out, &mut rank, &mut remaining);
    }

    /// One level of [`Self::get_many_erased`], then its wrappers and its parents
    /// in the order of [`Self::get_ref`]. `remaining` counts the slots of `out`
    /// that are still empty, and is kept up to date across the recursion.
    fn get_many_erased_ranked<'a, const N: usize>(
        &'a self,
        targets: &Targets<N>,
        out: &mut [Option<(&'a TypeErasedExtension, usize)>; N],
        rank: &mut usize,
        remaining: &mut usize,
    ) {
        if *remaining == 0 {
            return;
        }
        let store = self.store();
        if store.may_contain(targets.bits) {
            let egress_id = TypeId::of::<Egress<Self>>();
            let ingress_id = TypeId::of::<Ingress<Self>>();
            let chunks = store.entries.chunks();
            // Read after the chunks (see `AppendOnlyVec::push_tagged`): every entry they
            // yield has its bit in here.
            let has_wrappers = store.has_wrappers();
            for chunk in chunks.rev() {
                for ext in chunk.iter().rev() {
                    let current = *rank;
                    *rank += 1;

                    // Most entries are none of the targets: their slot has none.
                    let mut target = targets.head[type_slot(ext.type_id)];
                    while target != 0 {
                        let i = usize::from(target) - 1;
                        if out[i].is_none() && ext.type_id == targets.ids[i] {
                            out[i] = Some((ext, current));
                            *remaining -= 1;

                            if *remaining == 0 {
                                return;
                            }
                        }
                        target = targets.next[i];
                    }

                    if !has_wrappers {
                        continue;
                    }
                    if ext.type_id == egress_id
                        && let Some(eg) = ext.downcast_ref::<Egress<Self>>()
                    {
                        eg.0.get_many_erased_ranked(targets, out, rank, remaining);
                        if *remaining == 0 {
                            return;
                        }
                    } else if ext.type_id == ingress_id
                        && let Some(ig) = ext.downcast_ref::<Ingress<Self>>()
                    {
                        ig.0.get_many_erased_ranked(targets, out, rank, remaining);
                        if *remaining == 0 {
                            return;
                        }
                    }
                }
            }
        } else {
            // Nothing in this level is a target or a wrapper. Still count its
            // entries, so ranks stay the positions in the full traversal.
            *rank += store.entries.len();
        }
        if let Some(parent) = self.parent() {
            parent.get_many_erased_ranked(targets, out, rank, remaining);
        }
    }

    /// Recursive find-or-create: return `&T` if one exists anywhere in this
    /// this [`Extensions`] store (using [`Self::get_ref`] dispatch), otherwise
    /// insert the value produced by `create_fn` at the top level and return
    /// a reference to it.
    ///
    /// Useful when a type conceptually belongs to the scope (e.g. `ConnectionHealth`
    /// on a connection chain) and you want to reuse an existing instance rather
    /// than create a duplicate at every layer. For strict "ensure local exists",
    /// use [`Self::self_get_ref_or_insert`].
    pub fn get_ref_or_insert<T, F>(&self, create_fn: F) -> &T
    where
        T: Extension,
        F: FnOnce() -> T,
    {
        self.get_ref().unwrap_or_else(|| self.insert(create_fn()))
    }

    /// Recursive find-or-create returning an [`Arc<T>`]: see [`Self::get_ref_or_insert`].
    pub fn get_arc_or_insert<T, F>(&self, create_fn: F) -> Arc<T>
    where
        T: Extension,
        F: FnOnce() -> Arc<T>,
    {
        self.get_arc()
            .unwrap_or_else(|| self.insert_arc(create_fn()))
    }

    /// Raw flat find-or-create: return `&T` if one exists at the top level of
    /// this [`Extensions`] store, otherwise insert the value produced by
    /// `create_fn` at the top level and return a reference to it.
    ///
    /// Does not follow the parent chain. Useful when you want strict "ensure T
    /// exists on THIS blob" (e.g. materializing a direction wrapper
    /// like [`Ingress<Connection<Extensions>>`] at the outer blob).
    pub fn self_get_ref_or_insert<T, F>(&self, create_fn: F) -> &T
    where
        T: Extension,
        F: FnOnce() -> T,
    {
        self.self_get_ref()
            .unwrap_or_else(|| self.insert(create_fn()))
    }

    /// Raw flat find-or-create returning an [`Arc<T>`]: see [`Self::self_get_ref_or_insert`].
    pub fn self_get_arc_or_insert<T, F>(&self, create_fn: F) -> Arc<T>
    where
        T: Extension,
        F: FnOnce() -> Arc<T>,
    {
        self.self_get_arc()
            .unwrap_or_else(|| self.insert_arc(create_fn()))
    }

    /// Raw flat reference to the oldest inserted `T` at the top level of this
    /// [`Extensions`] store, does not walk structural wrappers.
    ///
    /// In most cases you want [`Self::get_ref`] (newest, scope-aware). Use this
    /// only when you specifically need insertion order access inside this [`Extensions`]
    /// store.
    ///
    /// Currently we don't provide a recursive variant of this method since we don't have
    /// a use case for it, and it's not exactly clear what would be considered "first".
    #[must_use]
    pub fn self_first_ref<T: Extension>(&self) -> Option<&T> {
        let type_id = TypeId::of::<T>();
        self.store()
            .entries
            .iter()
            .find(|item| item.type_id == type_id)
            .and_then(|ext| ext.downcast_ref())
    }

    /// Raw flat [`Arc<T>`] to the oldest inserted `T` at the top level, see
    /// [`Self::self_first_ref`] for caveats.
    #[must_use]
    pub fn self_first_arc<T: Extension>(&self) -> Option<Arc<T>> {
        let type_id = TypeId::of::<T>();
        self.store()
            .entries
            .iter()
            .find(|item| item.type_id == type_id)
            .and_then(|ext| ext.cloned_downcast())
    }

    /// Raw flat iteration over all inserted items of type `T` at the top level
    /// of this [`Extensions`] store, newest to oldest.
    ///
    /// The order matches [`Self::self_get_ref`] (newest-first), so
    /// `self_iter_ref::<T>().next() == self_get_ref::<T>()`.
    pub fn self_iter_ref<T: Extension>(&self) -> impl Iterator<Item = &T> {
        let type_id = TypeId::of::<T>();

        self.store()
            .entries
            .iter()
            .rev()
            .filter(move |item| item.type_id == type_id)
            .filter_map(TypeErasedExtension::downcast_ref::<T>)
    }

    /// Raw flat iteration over all inserted items of type `T` at the top level
    /// as cloned [`Arc`] values, newest to oldest.
    ///
    /// The order matches [`Self::self_get_arc`] (newest-first), so
    /// `self_iter_arc::<T>().next() == self_get_arc::<T>()`.
    pub fn self_iter_arc<T: Extension>(&self) -> impl Iterator<Item = Arc<T>> {
        let type_id = TypeId::of::<T>();

        self.store()
            .entries
            .iter()
            .rev()
            .filter(move |item| item.type_id == type_id)
            .filter_map(TypeErasedExtension::cloned_downcast::<T>)
    }

    /// Raw flat iteration over all [`TypeErasedExtension`] entries at the top
    /// level of this [`Extensions`] store.
    ///
    /// Use to efficiently combine different types of [`Extension`]s in a single
    /// iteration. [`TypeErasedExtension`] exposes methods to convert back to
    /// type `T` when it matches the erased type.
    pub fn self_iter_all(&self) -> impl Iterator<Item = &TypeErasedExtension> {
        self.store().entries.iter()
    }

    /// Iterate over all inserted items of type `T`, walking the parent chain
    /// and the structural [`Egress`] / [`Ingress`] connection wrappers.
    ///
    /// Yield order matches [`Self::get_ref`] preference (so
    /// `iter_ref::<T>().next() == get_ref::<T>()`):
    ///
    /// At each level, iterate the local entries newest -> oldest. For each
    /// entry: yield it if its type matches `T`, if it is an
    /// [`Egress<Extensions>`] or [`Ingress<Extensions>`] wrapper, recurse into
    /// the wrapped blob (same rule applied) and yield its results inline. Then
    /// recurse into the parent.
    ///
    /// For a flat top-level-only iteration use [`Self::self_iter_ref`].
    ///
    /// The iterator type is left opaque (`impl Iterator`) so the internal
    /// representation can change without breaking callers.
    pub fn iter_ref<T: Extension>(&self) -> impl Iterator<Item = &T> + '_ {
        self.iter_ref_inner::<T>()
    }

    /// Iteration yielding cloned [`Arc<T>`] values, see [`Self::iter_ref`].
    pub fn iter_arc<T: Extension>(&self) -> impl Iterator<Item = Arc<T>> + '_ {
        self.iter_arc_inner::<T>()
    }

    // TODO replace this later with a custom Iterator to avoid boxing
    fn iter_ref_inner<T: Extension>(&self) -> Box<dyn Iterator<Item = &T> + '_> {
        let target = TypeId::of::<T>();
        let egress_id = TypeId::of::<Egress<Self>>();
        let ingress_id = TypeId::of::<Ingress<Self>>();
        let local = self.store().entries.iter().rev().flat_map(
            move |ext| -> Box<dyn Iterator<Item = &T> + '_> {
                if ext.type_id == target {
                    match ext.downcast_ref::<T>() {
                        Some(v) => Box::new(core::iter::once(v)),
                        None => Box::new(core::iter::empty()),
                    }
                } else if ext.type_id == egress_id {
                    match ext.downcast_ref::<Egress<Self>>() {
                        Some(e) => e.0.iter_ref_inner::<T>(),
                        None => Box::new(core::iter::empty()),
                    }
                } else if ext.type_id == ingress_id {
                    match ext.downcast_ref::<Ingress<Self>>() {
                        Some(i) => i.0.iter_ref_inner::<T>(),
                        None => Box::new(core::iter::empty()),
                    }
                } else {
                    Box::new(core::iter::empty())
                }
            },
        );
        let parent: Box<dyn Iterator<Item = &T>> = match self.parent() {
            Some(p) => p.iter_ref_inner::<T>(),
            None => Box::new(core::iter::empty()),
        };
        Box::new(local.chain(parent))
    }

    // TODO replace this later with a custom Iterator to avoid boxing
    fn iter_arc_inner<T: Extension>(&self) -> Box<dyn Iterator<Item = Arc<T>> + '_> {
        let target = TypeId::of::<T>();
        let egress_id = TypeId::of::<Egress<Self>>();
        let ingress_id = TypeId::of::<Ingress<Self>>();
        let local = self.store().entries.iter().rev().flat_map(
            move |ext| -> Box<dyn Iterator<Item = Arc<T>> + '_> {
                if ext.type_id == target {
                    match ext.cloned_downcast::<T>() {
                        Some(v) => Box::new(core::iter::once(v)),
                        None => Box::new(core::iter::empty()),
                    }
                } else if ext.type_id == egress_id {
                    match ext.downcast_ref::<Egress<Self>>() {
                        Some(e) => e.0.iter_arc_inner::<T>(),
                        None => Box::new(core::iter::empty()),
                    }
                } else if ext.type_id == ingress_id {
                    match ext.downcast_ref::<Ingress<Self>>() {
                        Some(i) => i.0.iter_arc_inner::<T>(),
                        None => Box::new(core::iter::empty()),
                    }
                } else {
                    Box::new(core::iter::empty())
                }
            },
        );
        let parent: Box<dyn Iterator<Item = Arc<T>>> = match self.parent() {
            Some(p) => p.iter_arc_inner::<T>(),
            None => Box::new(core::iter::empty()),
        };
        Box::new(local.chain(parent))
    }

    /// Get a reference to the [`Ingress<Extensions>`] wrapper if one exists
    /// on this blob or anywhere reachable through the parent chain.
    ///
    /// Returns `None` when no ingress wrapper has been set up. For correctly
    /// constructed server-side requests this is always `Some`, server
    /// stacks insert the wrapper at the boundary where the connection becomes
    /// visible to a request, so a `None` here is almost always a framework
    /// setup bug rather than a normal state.
    ///
    /// This is just a shortcut for `extensions.get_ref::<Ingress<Extensions>>()`
    #[must_use]
    pub fn ingress(&self) -> Option<&Ingress<Self>> {
        self.get_ref::<Ingress<Self>>()
    }

    /// Get a reference to the [`Egress<Extensions>`] wrapper if one exists
    /// on this blob or anywhere reachable through the parent chain.
    /// See [`Self::ingress`] for semantics.
    ///
    /// This is just a shortcut for `extensions.get_ref::<Egress<Extensions>>()`
    #[must_use]
    pub fn egress(&self) -> Option<&Egress<Self>> {
        self.get_ref::<Egress<Self>>()
    }

    /// Clone an [`Extension`] from [`Extensions`] to another and get a `Arc` clone of it.
    pub fn clone_to<T: Extension>(&self, target: &Self) -> Option<Arc<T>> {
        let item = self.get_arc();
        if let Some(item) = item.clone() {
            target.insert_arc(item);
        };

        item
    }

    /// Clone an [`Extension`] from [`Extensions`] to another, if and only if the other
    /// [`Extensions`] store does not already contain this [`Extension`] `T`.
    ///
    /// If the other [`Extensions`] store already contains it, we return [`Extension`] `T`
    /// from the other store, otherwise we return the `T` that we transferred over.
    ///
    /// This is mainly used in connectors where [`Extension`]s that become part of the connection
    /// should be transfer from the input to the connection.
    pub fn clone_to_if_absent<T: Extension>(&self, target: &Self) -> Option<Arc<T>> {
        let item = target.get_arc::<T>();
        if item.is_some() {
            return item;
        }

        self.clone_to(target)
    }
}

/// Macro-support trait that lets a `#[derive(FromExtensions)]` group (e.g. an
/// any-of enum) be folded into a parent's single pass instead of running its own
/// traversal. Implemented by the derive, hidden and not part of the public API.
///
/// A group occupies [`Self::TARGETS`] consecutive slots in the shared buffers:
/// [`Self::from_ext_targets`] writes its candidate [`TypeId`]s at `offset`, and
/// after one [`Extensions::get_many_erased`] pass [`Self::from_ext_slots`] reads
/// the same window back. Because ranks are global across the pass, newest-wins
/// selection still holds across the whole struct.
#[doc(hidden)]
pub trait FromExtensionsGroup<'a>: Sized {
    /// Number of slots this group occupies in the shared single pass.
    const TARGETS: usize;
    /// Write the group's candidate `TypeId`s into `targets[offset..offset + TARGETS]`.
    fn from_ext_targets(targets: &mut [TypeId], offset: usize);
    /// Build the group value from the filled slots `out[offset..offset + TARGETS]`,
    /// or `None` if no candidate is present.
    fn from_ext_slots(
        out: &[Option<(&'a TypeErasedExtension, usize)>],
        offset: usize,
    ) -> Option<Self>;
}

/// Helper trait powering [`Extensions::get_many_ref`]: implemented for tuples of
/// [`Extension`] types (up to arity 12).
pub trait GetManyRef<'a>: Sized {
    /// Tuple of `Option<&'a T>` mirroring the requested tuple of types.
    type Output;

    #[doc(hidden)]
    const SEALED: seal::Seal;
    #[doc(hidden)]
    fn get_many_ref(ext: &'a Extensions) -> Self::Output;
}

/// Helper trait powering [`Extensions::get_many_arc`]; the owned-[`Arc`]
/// counterpart of [`GetManyRef`].
pub trait GetManyArc: Sized {
    /// Tuple of `Option<Arc<T>>` mirroring the requested tuple of types.
    type Output;

    #[doc(hidden)]
    const SEALED: seal::Seal;
    #[doc(hidden)]
    fn get_many_arc(ext: &Extensions) -> Self::Output;
}

macro_rules! impl_get_many {
    ($n:literal; $($T:ident => $idx:tt),+ $(,)?) => {
        impl<'a, $($T: Extension),+> GetManyRef<'a> for ($($T,)+) {
            type Output = ($(Option<&'a $T>,)+);

            const SEALED: seal::Seal = seal::Seal;
            fn get_many_ref(ext: &'a Extensions) -> Self::Output {
                let targets = [$(TypeId::of::<$T>()),+];
                let mut out: [Option<(&'a TypeErasedExtension, usize)>; $n] = [None; $n];
                ext.get_many_erased(&targets, &mut out);
                ($(out[$idx].and_then(|(e, _)| e.downcast_ref::<$T>()),)+)
            }
        }

        impl<$($T: Extension),+> GetManyArc for ($($T,)+) {
            type Output = ($(Option<Arc<$T>>,)+);

            const SEALED: seal::Seal = seal::Seal;
            fn get_many_arc(ext: &Extensions) -> Self::Output {
                let targets = [$(TypeId::of::<$T>()),+];
                let mut out: [Option<(&TypeErasedExtension, usize)>; $n] = [None; $n];
                ext.get_many_erased(&targets, &mut out);
                ($(out[$idx].and_then(|(e, _)| e.cloned_downcast::<$T>()),)+)
            }
        }
    };
}

impl_get_many!(1; A => 0);
impl_get_many!(2; A => 0, B => 1);
impl_get_many!(3; A => 0, B => 1, C => 2);
impl_get_many!(4; A => 0, B => 1, C => 2, D => 3);
impl_get_many!(5; A => 0, B => 1, C => 2, D => 3, E => 4);
impl_get_many!(6; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5);
impl_get_many!(7; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6);
impl_get_many!(8; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7);
impl_get_many!(9; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8);
impl_get_many!(10; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9);
impl_get_many!(11; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9, K => 10);
impl_get_many!(12; A => 0, B => 1, C => 2, D => 3, E => 4, F => 5, G => 6, H => 7, I => 8, J => 9, K => 10, L => 11);

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Extensions");
        if let Some(parent) = self.parent() {
            s.field("parent", parent);
        }
        s.field(
            "entries",
            &self
                .store()
                .entries
                .iter()
                .map(|e| &e.value)
                .collect::<Vec<_>>(),
        );

        s.finish()
    }
}

#[derive(Clone, Debug)]
/// A [`TypeErasedExtension`] is a type erased item which can be stored in an [`Extensions`]
///
/// Internally the value is stored inside an `Arc` so this is cheap to clone
pub struct TypeErasedExtension {
    type_id: TypeId,
    value: Arc<dyn Extension>,
}

impl TypeErasedExtension {
    /// Create a new [`TypeErasedExtension`] for `T`
    ///
    /// If the value you are inserting is an `Arc<T>`, prefer using
    /// [`Self::new_arc()`] to prevent the double indirection of storing
    /// an `Arc<Arc<T>>`. This happens because internally we use a type erased
    /// Arc to store the actual value.
    pub fn new<T: Extension>(value: T) -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            value: Arc::new(value),
        }
    }

    /// Create a new [`TypeErasedExtension`] for `Arc<T>`
    ///
    ///
    /// If the value you are inserting is not an `Arc<T>` prefer using
    /// [`Self::new()`] instead.
    pub fn new_arc<T: Extension>(value: Arc<T>) -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            value,
        }
    }

    /// Get the [`TypeId`] for the internally stored type `Arc<T>`
    pub fn type_id(&self) -> TypeId {
        self.type_id
    }

    /// Get a cloned `Arc<T>` of the internally stored type `Arc<T>`
    ///
    /// This method will return `None`, if the internally stored
    /// type `S` doesn't match the requested type `T`
    pub fn cloned_downcast<T: Extension>(&self) -> Option<Arc<T>> {
        let any = self.value.clone() as Arc<dyn Any + Send + Sync>;
        any.downcast::<T>().ok()
    }

    /// Get a reference `&T` of the internally stored type `T`
    ///
    /// This method will return `None`, if the internally stored
    /// type `S` doesn't match the requested type `T`
    pub fn downcast_ref<T: Extension>(&self) -> Option<&T> {
        let inner_any = self.value.as_ref() as &dyn Any;
        (inner_any).downcast_ref::<T>()
    }
}

#[derive(Debug, Clone, Extension)]
/// Ingress connection wrapper use by servers
pub struct Ingress<T>(pub T);

impl_deref!(Ingress);

#[derive(Debug, Clone, Extension)]
/// Egress connection wrapper use by client
pub struct Egress<T>(pub T);

impl_deref!(Egress);

// We use this syntax: [`TlsExtension`] — TLS and secure transport
// Instead of [`TlsExtension`]: TLS and secure transport
// Because otherwise we hit `link definitions are not shown in rendered documentation`

/// [`Extension`] is type which can be stored inside an [`Extensions`] store
///
/// This is has to be manually implement or can be implemented using `#[derive(Extension)]`
///
/// We have not implemented this for any container types:
/// - `Arc<T>`: sounds nice, but by not implement it, it has become impossible to misuse `Extensions::insert()`
///   with `Extensions::insert_arc()`. Otherwise this is very tricky and error prone
/// - `Vec<T>`: Collections should use the new type pattern to give it a meaningfull name, and to prevent collisions
///
/// There might be valid use cases for implementing it for other type of containers, so in case you run into these
/// open a Github issue and we can see if implementing it makes sense
///
/// # Extension Tags
///
/// Extensions can be tagged with one or more categories using the `#[extension(tags(tag1, tag2))]`
/// attribute on the derive macro. This generates implementations for the corresponding
/// marker traits below, which groups them in rust docs
///
/// - [`TlsExtension`] — TLS and secure transport
/// - [`HttpExtension`] — HTTP protocol
/// - [`NetExtension`] — Network and connection level
/// - [`UaExtension`] — User-agent emulation
/// - [`ProxyExtension`] — Proxy
/// - [`WsExtension`] — WebSocket
/// - [`DnsExtension`] — DNS resolution
/// - [`GrpcExtension`] — gRPC
///
/// ```rust,ignore
/// #[derive(Debug, Clone, Extension)]
/// #[extension(tags(tls, net))]
/// pub struct SecureTransport(..);
/// ```
///
/// Types that implement [`Extension`] manually can opt into tagged docs by implementing
/// the marker trait(s) directly:
///
/// ```rust,ignore
/// impl Extension for MyType {}
/// impl HttpExtension for MyType {}
/// ```
pub trait Extension: Any + Send + Sync + core::fmt::Debug + 'static {}

/// TLS and secure transport related extensions.
///
/// Derive with `#[extension(tags(tls))]`
pub trait TlsExtension: Extension {}

/// HTTP protocol related extensions.
///
/// Derive with `#[extension(tags(http))]`
pub trait HttpExtension: Extension {}

/// Network and connection level extensions.
///
/// Derive with `#[extension(tags(net))]`
pub trait NetExtension: Extension {}

/// User-agent emulation related extensions.
///
/// Derive with `#[extension(tags(ua))]`
pub trait UaExtension: Extension {}

/// Proxy related extensions.
///
/// Derive with `#[extension(tags(proxy))]`
pub trait ProxyExtension: Extension {}

/// WebSocket related extensions.
///
/// Derive with `#[extension(tags(ws))]`
pub trait WsExtension: Extension {}

/// DNS resolution related extensions.
///
/// Derive with `#[extension(tags(dns))]`
pub trait DnsExtension: Extension {}

/// gRPC related extensions.
///
/// Derive with `#[extension(tags(grpc))]`
pub trait GrpcExtension: Extension {}

pub trait ExtensionsRef {
    /// Get reference to the underlying [`Extensions`] store
    fn extensions(&self) -> &Extensions;
}

/// Exclusive access to an owned input's extension store.
///
/// Replacing the store permits request-local overlays without mutating stores
/// shared by cloned inputs. Individual extension values remain shared.
pub trait ExtensionsMut: ExtensionsRef {
    /// Get the replaceable extension store owned by this input.
    fn extensions_mut(&mut self) -> &mut Extensions;
}

impl ExtensionsMut for Extensions {
    fn extensions_mut(&mut self) -> &mut Extensions {
        self
    }
}

impl<T: ExtensionsMut> ExtensionsMut for &mut T {
    fn extensions_mut(&mut self) -> &mut Extensions {
        (**self).extensions_mut()
    }
}

impl<T: ExtensionsMut> ExtensionsMut for Box<T> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        (**self).extensions_mut()
    }
}

impl<T: ExtensionsMut + Unpin> ExtensionsMut for Pin<Box<T>> {
    fn extensions_mut(&mut self) -> &mut Extensions {
        self.as_mut().get_mut().extensions_mut()
    }
}

impl ExtensionsRef for Extensions {
    fn extensions(&self) -> &Extensions {
        self
    }
}

impl<T> ExtensionsRef for &T
where
    T: ExtensionsRef,
{
    #[inline(always)]
    fn extensions(&self) -> &Extensions {
        (**self).extensions()
    }
}

impl<T> ExtensionsRef for &mut T
where
    T: ExtensionsRef,
{
    #[inline(always)]
    fn extensions(&self) -> &Extensions {
        (**self).extensions()
    }
}

impl<T> ExtensionsRef for Box<T>
where
    T: ExtensionsRef,
{
    fn extensions(&self) -> &Extensions {
        (**self).extensions()
    }
}

impl<T> ExtensionsRef for Pin<Box<T>>
where
    T: ExtensionsRef,
{
    fn extensions(&self) -> &Extensions {
        (**self).extensions()
    }
}

impl<T> ExtensionsRef for Arc<T>
where
    T: ExtensionsRef,
{
    fn extensions(&self) -> &Extensions {
        (**self).extensions()
    }
}

macro_rules! impl_extensions_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+,> ExtensionsRef for crate::combinators::$id<$($param),+>
        where
            $($param: ExtensionsRef,)+
        {
            fn extensions(&self) -> &Extensions {
                match self {
                    $(crate::combinators::$id::$param(s) => s.extensions(),)+
                }
            }
        }

        impl<$($param),+,> ExtensionsMut for crate::combinators::$id<$($param),+>
        where
            $($param: ExtensionsMut,)+
        {
            fn extensions_mut(&mut self) -> &mut Extensions {
                match self {
                    $(crate::combinators::$id::$param(s) => s.extensions_mut(),)+
                }
            }
        }
    };
}

crate::combinators::impl_either!(impl_extensions_either);

mod seal {
    pub struct Seal;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::any::TypeId;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Clone, PartialEq, Eq, Extension)]
    struct TraceNote(String);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
    struct RetryBudget(u32);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
    struct ConnectionTimeoutMs(u64);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
    struct WorkerId(i32);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
    struct HealthSignal(u8);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
    struct FeatureToggle(bool);

    #[test]
    fn get_ref_returns_last_inserted() {
        let ext = Extensions::new();
        ext.insert(TraceNote("first".to_owned()));
        ext.insert(TraceNote("second".to_owned()));
        ext.insert(TraceNote("third".to_owned()));

        assert_eq!(
            ext.get_ref::<TraceNote>(),
            Some(&TraceNote("third".to_owned()))
        );
    }

    #[test]
    fn clone_shares_backing_store() {
        let ext = Extensions::new();
        ext.insert(TraceNote("first".to_owned()));

        let clone = ext.clone();
        clone.insert(TraceNote("second".to_owned()));

        assert_eq!(
            ext.get_ref::<TraceNote>(),
            Some(&TraceNote("second".to_owned()))
        );
        assert_eq!(
            clone.get_ref::<TraceNote>(),
            Some(&TraceNote("second".to_owned()))
        );
    }

    #[test]
    fn get_ref_none_when_absent() {
        let ext = Extensions::new();
        assert_eq!(ext.get_ref::<TraceNote>(), None);
    }

    #[test]
    fn get_arc_none_when_absent() {
        let ext = Extensions::new();
        assert!(ext.get_arc::<TraceNote>().is_none());
    }

    #[test]
    fn first_ref_none_when_absent() {
        let ext = Extensions::new();
        assert_eq!(ext.self_first_ref::<TraceNote>(), None);
    }

    #[test]
    fn first_arc_none_when_absent() {
        let ext = Extensions::new();
        assert!(ext.self_first_arc::<TraceNote>().is_none());
    }

    #[test]
    fn first_ref_returns_first_inserted() {
        let ext = Extensions::new();
        ext.insert(TraceNote("first".to_owned()));
        ext.insert(TraceNote("second".to_owned()));

        assert_eq!(
            ext.self_first_ref::<TraceNote>(),
            Some(&TraceNote("first".to_owned()))
        );
    }

    #[test]
    fn extend_appends_other_extensions() {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Extension)]
        struct DerivedMetric(i32);

        let source = Extensions::new();
        source.insert(WorkerId(5));
        source.insert(DerivedMetric(10));

        let target = Extensions::new();
        target.extend(&source);

        assert_eq!(target.get_ref::<WorkerId>(), Some(&WorkerId(5)));
        assert_eq!(target.get_ref::<DerivedMetric>(), Some(&DerivedMetric(10)));
    }

    #[test]
    fn insert_arc_can_be_retrieved_via_get_arc() {
        let ext = Extensions::new();
        let inserted = ext.insert_arc(Arc::new(TraceNote(String::from("hello"))));
        let retrieved = ext.get_arc::<TraceNote>();

        assert_eq!(inserted.0.as_str(), "hello");
        assert_eq!(retrieved.as_deref().map(|it| it.0.as_str()), Some("hello"));
    }

    #[test]
    fn insert_arc_can_be_retrieved_via_get_ref() {
        let ext = Extensions::new();
        ext.insert_arc(Arc::new(WorkerId(99)));
        assert_eq!(ext.get_ref::<WorkerId>(), Some(&WorkerId(99)));
    }

    #[test]
    fn contains_reports_presence_and_absence() {
        let ext = Extensions::new();
        assert!(!ext.contains::<RetryBudget>());

        ext.insert(RetryBudget(1));
        assert!(ext.contains::<RetryBudget>());
        assert!(!ext.contains::<ConnectionTimeoutMs>());
    }

    #[test]
    fn get_arc_and_first_arc_report_latest_and_oldest() {
        let ext = Extensions::new();
        ext.insert_arc(Arc::new(TraceNote(String::from("first"))));
        ext.insert_arc(Arc::new(TraceNote(String::from("second"))));

        assert_eq!(
            ext.self_first_arc::<TraceNote>()
                .as_deref()
                .map(|it| it.0.as_str()),
            Some("first")
        );
        assert_eq!(
            ext.get_arc::<TraceNote>()
                .as_deref()
                .map(|it| it.0.as_str()),
            Some("second")
        );
    }

    #[test]
    fn get_ref_or_insert_uses_existing_or_inserts_once() {
        let ext = Extensions::new();
        ext.insert(RetryBudget(5));

        let calls = AtomicUsize::new(0);
        let existing = ext.self_get_ref_or_insert(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            RetryBudget(6)
        });
        assert_eq!(existing.0, 5u32);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let missing = ext.self_get_ref_or_insert(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            ConnectionTimeoutMs(7)
        });
        assert_eq!(missing.0, 7u64);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn get_arc_or_insert_uses_existing_or_inserts_once() {
        let ext = Extensions::new();
        ext.insert_arc(Arc::new(TraceNote(String::from("stored"))));

        let calls = AtomicUsize::new(0);
        let existing = ext.self_get_arc_or_insert(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            Arc::new(TraceNote(String::from("new")))
        });
        assert_eq!(existing.0.as_str(), "stored");
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let missing = ext.self_get_arc_or_insert(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            Arc::new(RetryBudget(11))
        });
        assert_eq!(missing.0, 11u32);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn iter_all_exposes_all_items_in_insert_order() {
        let ext = Extensions::new();
        ext.insert(HealthSignal(1));
        ext.insert(FeatureToggle(true));
        ext.insert(HealthSignal(2));

        let type_ids: Vec<TypeId> = ext
            .self_iter_all()
            .map(TypeErasedExtension::type_id)
            .collect();
        assert_eq!(
            type_ids,
            vec![
                TypeId::of::<HealthSignal>(),
                TypeId::of::<FeatureToggle>(),
                TypeId::of::<HealthSignal>()
            ]
        );
    }

    #[test]
    fn iter_for_missing_type_is_empty() {
        let ext = Extensions::new();
        ext.insert(HealthSignal(1));

        assert_eq!(ext.self_iter_ref::<TraceNote>().count(), 0);
        assert_eq!(ext.self_iter_arc::<TraceNote>().count(), 0);
    }

    #[test]
    fn iter_ref_returns_items_for_present_type_in_newest_to_oldest_order() {
        let ext = Extensions::new();
        ext.insert(TraceNote(String::from("first")));
        ext.insert(HealthSignal(9));
        ext.insert(TraceNote(String::from("second")));

        let output: Vec<&str> = ext
            .self_iter_ref::<TraceNote>()
            .map(|it| it.0.as_str())
            .collect();
        assert_eq!(output, vec!["second", "first"]);
    }

    #[test]
    fn iter_arc_returns_items_for_present_type_in_newest_to_oldest_order() {
        let ext = Extensions::new();
        ext.insert(TraceNote(String::from("first")));
        ext.insert(HealthSignal(9));
        ext.insert(TraceNote(String::from("second")));

        let output: Vec<String> = ext
            .self_iter_arc::<TraceNote>()
            .map(|arc| arc.0.clone())
            .collect();
        assert_eq!(output, vec!["second".to_owned(), "first".to_owned()]);
    }

    #[test]
    fn type_erased_new_supports_downcast_ref_and_cloned_downcast() {
        let ext = TypeErasedExtension::new(TraceNote(String::from("hello")));

        assert_eq!(ext.type_id(), TypeId::of::<TraceNote>());
        assert_eq!(
            ext.downcast_ref::<TraceNote>().map(|it| it.0.as_str()),
            Some("hello")
        );
        assert_eq!(
            ext.cloned_downcast::<TraceNote>()
                .as_deref()
                .map(|it| it.0.as_str()),
            Some("hello")
        );
        assert!(ext.downcast_ref::<RetryBudget>().is_none());
        assert!(ext.cloned_downcast::<RetryBudget>().is_none());
    }

    #[test]
    fn type_erased_new_arc_supports_all_downcasts() {
        let ext = TypeErasedExtension::new_arc(Arc::new(TraceNote(String::from("hello"))));

        assert_eq!(ext.type_id(), TypeId::of::<TraceNote>());
        assert_eq!(
            ext.downcast_ref::<TraceNote>().map(|it| it.0.as_str()),
            Some("hello")
        );
        assert_eq!(
            ext.cloned_downcast::<TraceNote>()
                .as_deref()
                .map(|it| it.0.as_str()),
            Some("hello")
        );
        assert!(ext.downcast_ref::<RetryBudget>().is_none());
        assert!(ext.cloned_downcast::<RetryBudget>().is_none());
    }

    #[test]
    fn extensions_ref_blanket_impls_forward_to_underlying_extensions() {
        let base = Extensions::new();
        base.insert(RetryBudget(7));

        let by_ref: &Extensions = &base;
        assert_eq!(
            by_ref.extensions().get_ref::<RetryBudget>(),
            Some(&RetryBudget(7))
        );

        let mut base_for_mut = base.clone();
        let by_mut_ref: &mut Extensions = &mut base_for_mut;
        assert_eq!(
            by_mut_ref.extensions().get_ref::<RetryBudget>(),
            Some(&RetryBudget(7))
        );

        let boxed = Box::new(base.clone());
        assert_eq!(
            boxed.extensions().get_ref::<RetryBudget>(),
            Some(&RetryBudget(7))
        );

        let pinned = Pin::new(Box::new(base.clone()));
        assert_eq!(
            pinned.extensions().get_ref::<RetryBudget>(),
            Some(&RetryBudget(7))
        );

        let arced = Arc::new(base);
        assert_eq!(
            arced.extensions().get_ref::<RetryBudget>(),
            Some(&RetryBudget(7))
        );
    }

    #[derive(Debug, Clone, PartialEq, Eq, Extension)]
    struct ConnSocketInfo(&'static str);

    #[derive(Debug, Clone, PartialEq, Eq, Extension)]
    struct RequestId(u64);

    #[test]
    fn get_finds_local() {
        let req = Extensions::new();
        req.insert(RequestId(42));
        assert_eq!(req.get_ref::<RequestId>(), Some(&RequestId(42)));
    }

    #[test]
    fn get_walks_parent_chain() {
        let req = Extensions::new();
        req.insert(RequestId(7));

        let resp = req.fork();
        assert_eq!(resp.get_ref::<RequestId>(), Some(&RequestId(7)));
    }

    #[test]
    fn local_shadows_parent() {
        let req = Extensions::new();
        req.insert(RequestId(7));

        let attempt = req.fork();
        attempt.insert(RequestId(99));

        assert_eq!(attempt.get_ref::<RequestId>(), Some(&RequestId(99)));
    }

    #[test]
    fn fork_isolates_writes() {
        let req = Extensions::new();
        req.insert(RequestId(1));

        let attempt = req.fork();
        attempt.insert(RequestId(2));

        assert_eq!(req.get_ref::<RequestId>(), Some(&RequestId(1)));
    }

    #[test]
    fn ingress_view_walks_parent() {
        let conn_ext = Extensions::new();
        conn_ext.insert(ConnSocketInfo("client-in"));

        let req = Extensions::new();
        req.insert(Ingress(conn_ext));

        assert_eq!(
            req.ingress().and_then(|i| i.get_ref::<ConnSocketInfo>()),
            Some(&ConnSocketInfo("client-in"))
        );
    }

    #[test]
    fn egress_view_walks_parent() {
        let conn_ext = Extensions::new();
        conn_ext.insert(ConnSocketInfo("egress-side"));

        let req = Extensions::new();
        req.insert(Egress(conn_ext));

        assert_eq!(
            req.egress().and_then(|e| e.get_ref::<ConnSocketInfo>()),
            Some(&ConnSocketInfo("egress-side"))
        );
    }

    #[test]
    fn ingress_egress_disambiguate_in_mitm() {
        let in_conn = Extensions::new();
        in_conn.insert(ConnSocketInfo("in"));
        let out_conn = Extensions::new();
        out_conn.insert(ConnSocketInfo("out"));

        let req = Extensions::new();
        req.insert(Ingress(in_conn));
        req.insert(Egress(out_conn));

        assert_eq!(
            req.ingress().and_then(|i| i.get_ref::<ConnSocketInfo>()),
            Some(&ConnSocketInfo("in"))
        );
        assert_eq!(
            req.egress().and_then(|e| e.get_ref::<ConnSocketInfo>()),
            Some(&ConnSocketInfo("out"))
        );
    }

    #[test]
    fn egress_view_walks_through_parent_to_find_wrapper() {
        let conn_ext = Extensions::new();
        conn_ext.insert(ConnSocketInfo("inside-parent"));
        let req = Extensions::new();
        req.insert(Egress(conn_ext));

        let resp = req.fork();
        assert_eq!(
            resp.egress().and_then(|e| e.get_ref::<ConnSocketInfo>()),
            Some(&ConnSocketInfo("inside-parent"))
        );
    }

    #[test]
    fn ingress_egress_return_none_when_absent() {
        let req = Extensions::new();
        assert!(req.ingress().is_none());
        assert!(req.egress().is_none());
    }

    #[test]
    fn iter_ref_yields_local_then_parent_newest_to_oldest() {
        let parent = Extensions::new();
        parent.insert(RequestId(1));
        parent.insert(RequestId(2));

        let child = parent.fork();
        child.insert(RequestId(3));
        child.insert(RequestId(4));

        let ids: Vec<_> = child.iter_ref::<RequestId>().map(|r| r.0).collect();
        assert_eq!(ids, vec![4, 3, 2, 1]);
    }

    #[test]
    fn iter_ref_walks_egress_and_ingress_wrappers_inline() {
        let conn_in = Extensions::new();
        conn_in.insert(RequestId(10));
        conn_in.insert(RequestId(11));
        let conn_out = Extensions::new();
        conn_out.insert(RequestId(20));

        let req = Extensions::new();
        req.insert(RequestId(1));
        req.insert(Ingress(conn_in));
        req.insert(Egress(conn_out));

        let ids: Vec<_> = req.iter_ref::<RequestId>().map(|r| r.0).collect();
        assert_eq!(ids, vec![20, 11, 10, 1]);
    }

    #[test]
    fn local_direct_after_wrapper_shadows_wrapper() {
        let conn = Extensions::new();
        conn.insert(RequestId(99));
        let req = Extensions::new();
        req.insert(Ingress(conn));
        req.insert(RequestId(1));

        assert_eq!(req.get_ref::<RequestId>(), Some(&RequestId(1)));
    }

    #[test]
    fn wrapper_after_local_direct_shadows_direct() {
        let conn = Extensions::new();
        conn.insert(RequestId(99));
        let req = Extensions::new();
        req.insert(RequestId(1));
        req.insert(Ingress(conn));

        assert_eq!(req.get_ref::<RequestId>(), Some(&RequestId(99)));
    }

    #[test]
    fn iter_ref_first_matches_get_ref() {
        let parent = Extensions::new();
        parent.insert(RequestId(1));
        let child = parent.fork();
        child.insert(RequestId(2));

        assert_eq!(
            child.iter_ref::<RequestId>().next(),
            child.get_ref::<RequestId>()
        );
    }

    #[test]
    fn get_many_present_and_absent() {
        let ext = Extensions::new();
        ext.insert(RequestId(7));
        ext.insert(ConnSocketInfo("a"));

        let (id, sock, toggle) = ext.get_many_ref::<(RequestId, ConnSocketInfo, FeatureToggle)>();
        assert_eq!(id, Some(&RequestId(7)));
        assert_eq!(sock, Some(&ConnSocketInfo("a")));
        assert_eq!(toggle, None);
    }

    #[test]
    fn get_many_each_slot_matches_get_ref() {
        let ext = Extensions::new();
        ext.insert(RequestId(1));
        ext.insert(RequestId(2)); // newest wins
        ext.insert(ConnSocketInfo("x"));

        let (id, sock) = ext.get_many_ref::<(RequestId, ConnSocketInfo)>();
        assert_eq!(id, ext.get_ref::<RequestId>());
        assert_eq!(sock, ext.get_ref::<ConnSocketInfo>());
        assert_eq!(id, Some(&RequestId(2)));
    }

    #[test]
    fn get_many_walks_parent_chain() {
        let parent = Extensions::new();
        parent.insert(RequestId(1));
        let child = parent.fork();
        child.insert(ConnSocketInfo("x"));

        let (id, sock) = child.get_many_ref::<(RequestId, ConnSocketInfo)>();
        assert_eq!(id, Some(&RequestId(1)));
        assert_eq!(sock, Some(&ConnSocketInfo("x")));
    }

    #[test]
    fn with_base_and_chain() {
        let base = Extensions::new();
        base.insert(RequestId(1));
        base.insert(ConnSocketInfo("base"));

        let req = Extensions::new();
        req.insert(RequestId(2));
        req.insert(TraceNote("mid".to_owned()));
        let req_retry = req.fork();
        req_retry.insert(RequestId(3));

        let combined = req_retry.with_base(&base);

        assert_eq!(combined.get_ref::<RequestId>(), Some(&RequestId(3)));
        assert_eq!(
            combined.get_ref::<TraceNote>(),
            Some(&TraceNote("mid".to_owned())),
        );

        assert_eq!(
            combined.get_ref::<ConnSocketInfo>(),
            Some(&ConnSocketInfo("base")),
        );

        assert_eq!(base.get_ref::<RequestId>(), Some(&RequestId(1)));
        assert!(req_retry.get_ref::<ConnSocketInfo>().is_none());
    }

    #[test]
    fn get_many_walks_wrappers() {
        let conn = Extensions::new();
        conn.insert(ConnSocketInfo("in"));
        let req = Extensions::new();
        req.insert(RequestId(7));
        req.insert(Ingress(conn));

        let (id, sock) = req.get_many_ref::<(RequestId, ConnSocketInfo)>();
        assert_eq!(id, Some(&RequestId(7)));
        assert_eq!(sock, Some(&ConnSocketInfo("in")));
    }

    #[derive(FromExtensions)]
    struct GatherView<'a> {
        id: Option<&'a RequestId>,
        sock: Option<&'a ConnSocketInfo>,
        toggle: Option<&'a FeatureToggle>,
    }

    #[test]
    fn derive_from_extensions_gathers_pieces() {
        let ext = Extensions::new();
        ext.insert(RequestId(7));
        ext.insert(ConnSocketInfo("a"));

        let view = GatherView::from_extensions(&ext);
        assert_eq!(view.id, Some(&RequestId(7)));
        assert_eq!(view.sock, Some(&ConnSocketInfo("a")));
        assert_eq!(view.toggle, None);
        assert_eq!(view.id, ext.get_ref::<RequestId>());
    }

    #[test]
    fn derive_from_extensions_walks_parent() {
        let parent = Extensions::new();
        parent.insert(RequestId(1));
        let child = parent.fork();
        child.insert(ConnSocketInfo("x"));

        let view = GatherView::from_extensions(&child);
        assert_eq!(view.id, Some(&RequestId(1)));
        assert_eq!(view.sock, Some(&ConnSocketInfo("x")));
        assert_eq!(view.toggle, None);
    }

    #[test]
    fn get_many_arc_returns_owned_arcs() {
        let ext = Extensions::new();
        ext.insert(RequestId(7));

        let (id, sock) = ext.get_many_arc::<(RequestId, ConnSocketInfo)>();
        assert_eq!(id.as_deref(), Some(&RequestId(7)));
        assert_eq!(sock, None);
    }

    #[derive(FromExtensions)]
    struct MixedView<'a> {
        id_ref: Option<&'a RequestId>,
        sock_arc: Option<Arc<ConnSocketInfo>>,
    }

    #[test]
    fn derive_from_extensions_mixed_ref_and_arc() {
        let ext = Extensions::new();
        ext.insert(RequestId(7));
        ext.insert(ConnSocketInfo("a"));

        let view = MixedView::from_extensions(&ext);
        assert_eq!(view.id_ref, Some(&RequestId(7)));
        assert_eq!(view.sock_arc.as_deref(), Some(&ConnSocketInfo("a")));
    }

    #[derive(FromExtensions)]
    struct AllArc {
        id_ref: Option<Arc<RequestId>>,
        sock_arc: Option<Arc<ConnSocketInfo>>,
    }

    #[test]
    fn derive_from_extensions_all_arc() {
        let ext = Extensions::new();
        ext.insert(RequestId(7));
        ext.insert(ConnSocketInfo("a"));

        let view = AllArc::from_extensions(&ext);
        assert_eq!(view.id_ref.as_deref(), Some(&RequestId(7)));
        assert_eq!(view.sock_arc.as_deref(), Some(&ConnSocketInfo("a")));
    }

    #[derive(FromExtensions)]
    struct RankedView<'a> {
        id: Option<(&'a RequestId, usize)>,
        sock: Option<(&'a ConnSocketInfo, usize)>,
        toggle: Option<(&'a FeatureToggle, usize)>,
    }

    #[test]
    fn derive_from_extensions_captures_rank() {
        let ext = Extensions::new();
        ext.insert(RequestId(7)); // oldest
        ext.insert(ConnSocketInfo("a")); // newest

        let view = RankedView::from_extensions(&ext);

        assert_eq!(view.sock, Some((&ConnSocketInfo("a"), 0)));
        assert_eq!(view.id, Some((&RequestId(7), 1)));
        assert_eq!(view.toggle, None);

        assert!(view.sock.unwrap().1 < view.id.unwrap().1);
    }

    #[test]
    fn derive_from_extensions_rank_arc_variant() {
        #[derive(FromExtensions)]
        struct RankedArc {
            id: Option<(Arc<RequestId>, usize)>,
        }

        let ext = Extensions::new();
        ext.insert(ConnSocketInfo("a"));
        ext.insert(RequestId(7));

        let view = RankedArc::from_extensions(&ext);
        let (id, rank) = view.id.expect("present");
        assert_eq!(&*id, &RequestId(7));
        assert_eq!(rank, 0);
    }

    #[derive(Debug, PartialEq, Eq, FromExtensions)]
    enum AnyOf<'a> {
        Req(&'a RequestId),
        Sock(&'a ConnSocketInfo),
    }

    #[test]
    fn derive_from_extensions_enum_newest_wins() {
        let ext = Extensions::new();
        ext.insert(ConnSocketInfo("a"));
        ext.insert(RequestId(7));
        assert_eq!(
            AnyOf::from_extensions(&ext),
            Some(AnyOf::Req(&RequestId(7)))
        );

        let ext = Extensions::new();
        ext.insert(RequestId(7));
        ext.insert(ConnSocketInfo("a"));
        assert_eq!(
            AnyOf::from_extensions(&ext),
            Some(AnyOf::Sock(&ConnSocketInfo("a")))
        );

        let ext = Extensions::new();
        ext.insert(RequestId(7));
        assert_eq!(
            AnyOf::from_extensions(&ext),
            Some(AnyOf::Req(&RequestId(7)))
        );

        let ext = Extensions::new();
        ext.insert(FeatureToggle(true));
        assert_eq!(AnyOf::from_extensions(&ext), None);
    }

    #[derive(FromExtensions)]
    struct ConfigView<'a> {
        toggle: Option<&'a FeatureToggle>,
        either: Option<AnyOf<'a>>,
    }

    #[derive(Debug, PartialEq, Eq, FromExtensions)]
    enum SameType<'a> {
        First(&'a RequestId),
        Second(&'a RequestId),
    }

    #[test]
    fn derive_from_extensions_enum_same_type_ties_to_earlier_variant() {
        // Both variants name `RequestId`, so they resolve to the same entry
        // (equal rank), the tie breaks deterministically toward the earlier
        // variant, `First`.
        let ext = Extensions::new();
        ext.insert(RequestId(7));
        assert_eq!(
            SameType::from_extensions(&ext),
            Some(SameType::First(&RequestId(7)))
        );
    }

    #[test]
    fn derive_from_extensions_nested_group_field() {
        let ext = Extensions::new();
        ext.insert(FeatureToggle(true));
        ext.insert(RequestId(7));
        ext.insert(ConnSocketInfo("a"));

        let view = ConfigView::from_extensions(&ext);
        assert_eq!(view.toggle, Some(&FeatureToggle(true)));
        assert_eq!(view.either, Some(AnyOf::Sock(&ConnSocketInfo("a"))));

        let ext = Extensions::new();
        ext.insert(FeatureToggle(false));
        let view = ConfigView::from_extensions(&ext);
        assert_eq!(view.toggle, Some(&FeatureToggle(false)));
        assert_eq!(view.either, None);
    }

    #[test]
    fn derive_from_extensions_is_empty_covers_every_field() {
        let empty = Extensions::new();
        assert!(GatherView::from_extensions(&empty).is_empty());
        assert!(RankedView::from_extensions(&empty).is_empty());
        assert!(ConfigView::from_extensions(&empty).is_empty());
        let unrelated = Extensions::new();
        unrelated.insert(FeatureToggle(true));
        assert!(MixedView::from_extensions(&unrelated).is_empty());

        let inserts: [fn(&Extensions); 3] = [
            |ext| {
                ext.insert(RequestId(7));
            },
            |ext| {
                ext.insert(ConnSocketInfo("a"));
            },
            |ext| {
                ext.insert(FeatureToggle(true));
            },
        ];
        for insert in inserts {
            let ext = Extensions::new();
            insert(&ext);
            assert!(!GatherView::from_extensions(&ext).is_empty());
            assert!(!RankedView::from_extensions(&ext).is_empty());
            // Covers both a direct field and the nested group.
            assert!(!ConfigView::from_extensions(&ext).is_empty());
        }
    }

    #[test]
    fn derive_from_extensions_enum_newest_wins_across_parent() {
        let parent = Extensions::new();
        parent.insert(RequestId(7));
        let child = parent.fork();
        child.insert(ConnSocketInfo("a"));

        assert_eq!(
            AnyOf::from_extensions(&child),
            Some(AnyOf::Sock(&ConnSocketInfo("a")))
        );

        let parent = Extensions::new();
        parent.insert(ConnSocketInfo("a"));
        let child = parent.fork();
        child.insert(RequestId(7));

        assert_eq!(
            AnyOf::from_extensions(&child),
            Some(AnyOf::Req(&RequestId(7)))
        );
    }

    // The lookups skip levels and entries with the `Store` filter (its tags).
    // These tests pin that it never changes an answer: every lookup is compared
    // with a plain reference walk that has no filter, over pseudo-random chains
    // with more types than the filter has bits, so collisions are exercised.

    /// 72 distinct types: more than the bits of the `Store` filter.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Filler<const N: usize>(u32);

    impl<const N: usize> Extension for Filler<N> {}

    /// Calls the macro with the number of every [`Filler`] type.
    macro_rules! with_fillers {
        ($callback:ident) => {
            $callback!(
                0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30
                31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58
                59 60 61 62 63 64 65 66 67 68 69 70 71
            )
        };
    }

    macro_rules! filler_inserters {
        ($($n:literal)+) => {
            [$(|ext: &Extensions, value: u32| _ = ext.insert(Filler::<$n>(value))),+]
        };
    }

    macro_rules! filler_ids {
        ($($n:literal)+) => {
            [$(TypeId::of::<Filler<$n>>()),+]
        };
    }

    macro_rules! filler_finders {
        ($($n:literal)+) => {
            [$(|ext: &Extensions| ext.get_ref::<Filler<$n>>().is_some()),+]
        };
    }

    const FILLERS: [fn(&Extensions, u32); 72] = with_fillers!(filler_inserters);
    const FILLER_FINDERS: [fn(&Extensions) -> bool; 72] = with_fillers!(filler_finders);

    /// Newest-first entries in the same order as [`Extensions::get_ref`] walks
    /// them, together with the rank they have in the traversal.
    fn reference_walk<'a>(ext: &'a Extensions, out: &mut Vec<&'a TypeErasedExtension>) {
        let mut entries: Vec<_> = ext.self_iter_all().collect();
        entries.reverse();
        for entry in entries {
            out.push(entry);
            if let Some(eg) = entry.downcast_ref::<Egress<Extensions>>() {
                reference_walk(&eg.0, out);
            } else if let Some(ig) = entry.downcast_ref::<Ingress<Extensions>>() {
                reference_walk(&ig.0, out);
            }
        }
        if let Some(parent) = ext.parent() {
            reference_walk(parent, out);
        }
    }

    fn reference_get(ext: &Extensions, id: TypeId) -> Option<(&TypeErasedExtension, usize)> {
        let mut walk = Vec::new();
        reference_walk(ext, &mut walk);
        walk.into_iter()
            .enumerate()
            .find(|(_, entry)| TypeErasedExtension::type_id(entry) == id)
            .map(|(rank, entry)| (entry, rank))
    }

    struct Xorshift(u64);

    impl Xorshift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn insert_filler(ext: &Extensions, kind: u64, value: u32) {
        FILLERS[(kind % 72) as usize](ext, value);
    }

    /// A random tree of levels: forks, wrappers, and `with_base` overlays.
    fn random_chain(rng: &mut Xorshift, depth: u32) -> Extensions {
        let mut ext = Extensions::new();
        for _ in 0..rng.below(14) {
            match rng.below(12) {
                0 if depth > 0 => {
                    ext.insert(Egress(random_chain(rng, depth - 1)));
                }
                1 if depth > 0 => {
                    ext.insert(Ingress(random_chain(rng, depth - 1)));
                }
                2 if depth > 0 => ext = ext.fork(),
                _ => insert_filler(&ext, rng.next(), rng.next() as u32),
            }
        }
        if depth > 0 && rng.below(4) == 0 {
            ext = ext.with_base(&random_chain(rng, depth - 1));
        }
        ext
    }

    #[test]
    fn get_ref_matches_unfiltered_walk_on_random_chains() {
        let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15);
        for _ in 0..500 {
            let ext = random_chain(&mut rng, 3);
            macro_rules! check {
                ($($t:ty),+) => {$(
                    let expected = reference_get(&ext, TypeId::of::<$t>())
                        .and_then(|(entry, _)| entry.downcast_ref::<$t>());
                    assert_eq!(ext.get_ref::<$t>(), expected, "get_ref::<{}>", stringify!($t));
                    assert_eq!(ext.get_arc::<$t>().as_deref(), expected, "get_arc::<{}>", stringify!($t));
                    assert_eq!(ext.contains::<$t>(), expected.is_some());
                )+};
            }
            check!(
                Filler<0>,
                Filler<7>,
                Filler<13>,
                Filler<21>,
                Filler<34>,
                Filler<42>,
                Filler<55>,
                Filler<63>,
                Filler<71>
            );
            let egress = reference_get(&ext, TypeId::of::<Egress<Extensions>>()).is_some();
            assert_eq!(ext.egress().is_some(), egress);
            let ingress = reference_get(&ext, TypeId::of::<Ingress<Extensions>>()).is_some();
            assert_eq!(ext.ingress().is_some(), ingress);
        }
    }

    #[test]
    fn get_many_matches_unfiltered_walk_on_random_chains() {
        let mut rng = Xorshift(0xD1B5_4A32_D192_ED03);
        for _ in 0..500 {
            let ext = random_chain(&mut rng, 3);
            let targets = [
                TypeId::of::<Filler<2>>(),
                TypeId::of::<Filler<19>>(),
                TypeId::of::<Filler<33>>(),
                TypeId::of::<Filler<48>>(),
                TypeId::of::<Filler<60>>(),
                TypeId::of::<Filler<70>>(),
                TypeId::of::<Egress<Extensions>>(),
                TypeId::of::<Ingress<Extensions>>(),
            ];
            let mut out = [None; 8];
            ext.get_many_erased(&targets, &mut out);
            for (target, found) in targets.iter().zip(out) {
                let expected = reference_get(&ext, *target);
                assert_eq!(
                    found.map(|(entry, rank)| (entry as *const _, rank)),
                    expected.map(|(entry, rank)| (entry as *const _, rank)),
                );
            }
        }
    }

    #[test]
    fn get_many_of_more_targets_than_slots_matches_unfiltered_walk() {
        let mut rng = Xorshift(0xA076_1D64_78BD_642F);
        // every filler once, then again: several targets share a slot, and
        // duplicates ask the same question twice
        let mut targets = with_fillers!(filler_ids).to_vec();
        targets.extend_from_slice(&targets.clone());
        let targets: [TypeId; 144] = targets.try_into().unwrap();
        for _ in 0..200 {
            let ext = random_chain(&mut rng, 3);
            let mut out = [None; 144];
            ext.get_many_erased(&targets, &mut out);
            for (target, found) in targets.iter().zip(out) {
                let expected = reference_get(&ext, *target);
                assert_eq!(
                    found.map(|(entry, rank)| (entry as *const _, rank)),
                    expected.map(|(entry, rank)| (entry as *const _, rank)),
                );
            }
        }
    }

    #[test]
    fn lookups_see_the_inserts_that_completed_on_other_threads() {
        use core::sync::atomic::{AtomicUsize, Ordering};

        const WRITERS: usize = 4;
        const PER_WRITER: usize = 18;

        let ext = Extensions::new();
        let wrapped = Extensions::new();
        ext.insert(Egress(wrapped.clone()));
        let done: [AtomicUsize; WRITERS] = core::array::from_fn(|_| AtomicUsize::new(0));
        // Full passes of the reader. A writer waits for a pass that started
        // after its insert, so lookups run while inserts are being published,
        // and the last pass always checks every insert.
        let passes = AtomicUsize::new(0);
        // Cleared when the reader stops, also by a failed assertion, so the
        // writers fail with it instead of waiting forever.
        let reading = core::sync::atomic::AtomicBool::new(true);
        struct StopReading<'a>(&'a core::sync::atomic::AtomicBool);
        impl Drop for StopReading<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }

        std::thread::scope(|scope| {
            let reader = scope.spawn(|| {
                let _stop = StopReading(&reading);
                loop {
                    let inserted: [usize; WRITERS] =
                        core::array::from_fn(|w| done[w].load(Ordering::Acquire));
                    for (writer, inserted) in inserted.iter().enumerate() {
                        for i in 0..*inserted {
                            assert!(
                                FILLER_FINDERS[writer * PER_WRITER + i](&ext),
                                "writer {writer} insert {i} was done but is not found"
                            );
                        }
                    }
                    passes.fetch_add(1, Ordering::AcqRel);
                    if inserted.iter().all(|n| *n == PER_WRITER) {
                        break;
                    }
                }
            });
            for writer in 0..WRITERS {
                let (ext, wrapped, done, passes, reading) =
                    (&ext, &wrapped, &done, &passes, &reading);
                scope.spawn(move || {
                    for i in 0..PER_WRITER {
                        // half of them go straight in, half through the wrapped store
                        let target = if i % 2 == 0 { ext } else { wrapped };
                        FILLERS[writer * PER_WRITER + i](target, 0);
                        let seen = passes.load(Ordering::Acquire);
                        done[writer].store(i + 1, Ordering::Release);
                        // the reader stops after a pass that saw everything
                        if i + 1 < PER_WRITER {
                            // a pass in progress may have read `done` before the store
                            while passes.load(Ordering::Acquire) < seen + 2 {
                                assert!(reading.load(Ordering::Acquire), "the reader failed");
                                std::thread::yield_now();
                            }
                        }
                    }
                });
            }
            reader.join().unwrap();
        });
    }

    /// No view of a view: views are always made of the owning level, also
    /// when made of a view, of a fork of a view, or with a view as base.
    #[test]
    fn views_of_views_share_one_owner() {
        fn assert_views_own_nothing(ext: &Extensions) {
            if let Some(owner) = &ext.node.view_of {
                assert!(owner.node.view_of.is_none(), "view of a view");
                assert!(ext.node.entries.entries.is_empty(), "view has own entries");
            }
            if let Some(parent) = ext.parent() {
                assert_views_own_nothing(parent);
            }
        }

        let ext = Extensions::new();
        ext.insert(Filler::<0>(0));
        let base_1 = Extensions::new();
        base_1.insert(Filler::<1>(1));
        base_1.insert(Filler::<0>(100));
        let base_2 = Extensions::new();
        base_2.insert(Filler::<2>(2));
        base_2.insert(Filler::<1>(200));

        let view_1 = ext.with_base(&base_1);
        let view_2 = view_1.with_base(&base_2);
        assert_views_own_nothing(&view_2);
        assert_eq!(view_2.get_ref::<Filler<0>>(), Some(&Filler(0)));
        assert_eq!(view_2.get_ref::<Filler<1>>(), Some(&Filler(1)));
        assert_eq!(view_2.get_ref::<Filler<2>>(), Some(&Filler(2)));

        // inserting through a view of a view lands in the owner
        view_2.insert(Filler::<2>(9));
        assert_eq!(ext.get_ref::<Filler<2>>(), Some(&Filler(9)));

        let rebased_fork = view_2.fork().with_base(&Extensions::new());
        assert_views_own_nothing(&rebased_fork);
        assert_eq!(rebased_fork.get_ref::<Filler<1>>(), Some(&Filler(1)));

        let view_as_base = Extensions::new().with_base(&view_2).with_base(&view_1);
        assert_views_own_nothing(&view_as_base);
        assert_eq!(view_as_base.get_ref::<Filler<2>>(), Some(&Filler(9)));
    }

    #[test]
    fn target_plan_installs_one_plan_across_threads() {
        for _ in 0..if cfg!(miri) { 3 } else { 200 } {
            let plan: TargetPlan<2> = TargetPlan::new();
            let barrier = std::sync::Barrier::new(4);
            let plans: Vec<usize> = std::thread::scope(|scope| {
                let threads: Vec<_> = (0..4)
                    .map(|_| {
                        scope.spawn(|| {
                            barrier.wait();
                            let targets =
                                plan.get(|| [TypeId::of::<Filler<0>>(), TypeId::of::<Filler<1>>()]);
                            assert_eq!(targets.ids[1], TypeId::of::<Filler<1>>());
                            core::ptr::from_ref(targets) as usize
                        })
                    })
                    .collect();
                threads.into_iter().map(|t| t.join().unwrap()).collect()
            });
            assert!(
                plans.iter().all(|p| *p == plans[0]),
                "more than one plan installed"
            );
        }
    }

    #[test]
    fn lookups_still_find_a_type_behind_many_skipped_levels() {
        let root = Extensions::new();
        root.insert(Filler::<5>(1));
        let mut leaf = root;
        for level in 0..20 {
            leaf = leaf.fork();
            insert_filler(&leaf, 10 + level, 0);
        }
        assert_eq!(leaf.get_ref::<Filler<5>>(), Some(&Filler::<5>(1)));
        assert_eq!(leaf.get_ref::<Filler<6>>(), None);

        let (found, missing) = leaf.get_many_ref::<(Filler<5>, Filler<6>)>();
        assert_eq!(found, Some(&Filler::<5>(1)));
        assert_eq!(missing, None);
    }

    #[test]
    fn lookups_see_entries_pushed_through_a_clone_and_extend() {
        let ext = Extensions::new();
        let clone = ext.clone();
        assert_eq!(ext.get_ref::<Filler<11>>(), None);
        clone.insert(Filler::<11>(4));
        assert_eq!(ext.get_ref::<Filler<11>>(), Some(&Filler::<11>(4)));

        let other = Extensions::new();
        other.extend(&ext);
        assert_eq!(other.get_ref::<Filler<11>>(), Some(&Filler::<11>(4)));
        assert_eq!(
            other.get_many_ref::<(Filler<11>, Filler<12>)>(),
            (Some(&Filler::<11>(4)), None)
        );
    }

    #[test]
    fn wrapper_lookups_survive_the_filter() {
        let conn = Extensions::new();
        conn.insert(Filler::<9>(9));
        let request = Extensions::new();
        request.insert(Egress(conn.clone()));
        // added to the wrapped store after it was wrapped
        conn.insert(Filler::<10>(10));

        assert_eq!(request.get_ref::<Filler<9>>(), Some(&Filler::<9>(9)));
        assert_eq!(request.get_ref::<Filler<10>>(), Some(&Filler::<10>(10)));
        assert!(request.egress().is_some());
        assert!(request.ingress().is_none());
    }

    // A model of the documented semantics, independent of the storage: every
    // level is a plain list shared by the handles of that level, lookups go
    // newest first, recurse into wrappers in insertion order, then the parent.

    #[derive(Clone)]
    enum ModelEntry {
        Value(usize, u32),
        Wrapped(ModelExtensions),
    }

    #[derive(Clone)]
    struct ModelExtensions {
        level: std::rc::Rc<std::cell::RefCell<Vec<ModelEntry>>>,
        parent: Option<Box<Self>>,
    }

    impl ModelExtensions {
        fn new() -> Self {
            Self {
                level: Default::default(),
                parent: None,
            }
        }

        fn fork(&self) -> Self {
            Self {
                level: Default::default(),
                parent: Some(Box::new(self.clone())),
            }
        }

        fn with_base(&self, base: &Self) -> Self {
            Self {
                level: self.level.clone(),
                parent: Some(Box::new(match &self.parent {
                    Some(parent) => parent.with_base(base),
                    None => base.clone(),
                })),
            }
        }

        fn get(&self, kind: usize) -> Option<u32> {
            for entry in self.level.borrow().iter().rev() {
                match entry {
                    ModelEntry::Value(k, value) if *k == kind => return Some(*value),
                    ModelEntry::Wrapped(wrapped) => {
                        if let Some(value) = wrapped.get(kind) {
                            return Some(value);
                        }
                    }
                    ModelEntry::Value(..) => {}
                }
            }
            self.parent.as_ref().and_then(|parent| parent.get(kind))
        }
    }

    /// Kinds of values the model inserts: few enough to collide often.
    const MODEL_KINDS: usize = 10;

    macro_rules! filler_values {
        ($($n:literal)+) => {
            [$(|ext: &Extensions| ext.get_ref::<Filler<$n>>().map(|f| f.0)),+]
        };
    }

    macro_rules! filler_arcs {
        ($($n:literal)+) => {
            [$(|ext: &Extensions| ext.get_arc::<Filler<$n>>().map(|f| f.0)),+]
        };
    }

    macro_rules! filler_contains {
        ($($n:literal)+) => {
            [$(|ext: &Extensions| ext.contains::<Filler<$n>>()),+]
        };
    }

    macro_rules! model_kinds {
        ($callback:ident) => {
            $callback!(0 1 2 3 4 5 6 7 8 9)
        };
    }

    macro_rules! erased_values {
        ($($n:literal)+) => {
            [$(|entry: &TypeErasedExtension| entry.downcast_ref::<Filler<$n>>().map(|f| f.0)),+]
        };
    }

    const MODEL_GET: [fn(&Extensions) -> Option<u32>; MODEL_KINDS] = model_kinds!(filler_values);
    const MODEL_ERASED: [fn(&TypeErasedExtension) -> Option<u32>; MODEL_KINDS] =
        model_kinds!(erased_values);
    const MODEL_ARC: [fn(&Extensions) -> Option<u32>; MODEL_KINDS] = model_kinds!(filler_arcs);
    const MODEL_CONTAINS: [fn(&Extensions) -> bool; MODEL_KINDS] = model_kinds!(filler_contains);

    /// Whether every lookup on `ext` answers what the model does.
    fn agrees_with_model(ext: &Extensions, model: &ModelExtensions) -> bool {
        let ids: [TypeId; MODEL_KINDS] = model_kinds!(filler_ids);
        let mut many = [None; MODEL_KINDS];
        ext.get_many_erased(&ids, &mut many);
        (0..MODEL_KINDS).all(|kind| {
            let expected = model.get(kind);
            MODEL_GET[kind](ext) == expected
                && MODEL_ARC[kind](ext) == expected
                && MODEL_CONTAINS[kind](ext) == expected.is_some()
                && many[kind].and_then(|(entry, _)| MODEL_ERASED[kind](entry)) == expected
        })
    }

    /// Run a random program of `new`, `fork`, `clone`, `with_base`, typed
    /// inserts and wrapper inserts over two families of handles: connections,
    /// which never hold wrappers, and requests, which wrap connections (so no
    /// handle can reach itself). After every step, and for every handle at
    /// the end, all lookups must agree with the model.
    fn agrees_with_model_for(program: Vec<(u8, u8, u8, u16)>) -> bool {
        let mut conns: Vec<(Extensions, ModelExtensions)> =
            vec![(Extensions::new(), ModelExtensions::new())];
        let mut reqs: Vec<(Extensions, ModelExtensions)> =
            vec![(Extensions::new(), ModelExtensions::new())];
        for (op, a, b, value) in program {
            let (a, b) = (usize::from(a), usize::from(b));
            let kind = usize::from(value) % MODEL_KINDS;
            let value = u32::from(value);
            let touched = match op % 11 {
                0 => {
                    conns.push((Extensions::new(), ModelExtensions::new()));
                    conns.last()
                }
                1 => {
                    reqs.push((Extensions::new(), ModelExtensions::new()));
                    reqs.last()
                }
                2 => {
                    let (ext, model) = &conns[a % conns.len()];
                    let forked = (ext.fork(), model.fork());
                    conns.push(forked);
                    conns.last()
                }
                3 => {
                    let (ext, model) = &reqs[a % reqs.len()];
                    let forked = (ext.fork(), model.fork());
                    reqs.push(forked);
                    reqs.last()
                }
                4 => {
                    let cloned = reqs[a % reqs.len()].clone();
                    reqs.push(cloned);
                    reqs.last()
                }
                5 => {
                    let (ext, model) = &reqs[a % reqs.len()];
                    let (base, base_model) = if b % 2 == 0 {
                        &conns[b % conns.len()]
                    } else {
                        &reqs[b % reqs.len()]
                    };
                    let view = (ext.with_base(base), model.with_base(base_model));
                    reqs.push(view);
                    reqs.last()
                }
                6 => {
                    let (ext, model) = &conns[a % conns.len()];
                    let (base, base_model) = &conns[b % conns.len()];
                    let view = (ext.with_base(base), model.with_base(base_model));
                    conns.push(view);
                    conns.last()
                }
                7 => {
                    let handle = &conns[a % conns.len()];
                    FILLERS[kind](&handle.0, value);
                    handle
                        .1
                        .level
                        .borrow_mut()
                        .push(ModelEntry::Value(kind, value));
                    Some(handle)
                }
                8 => {
                    let handle = &reqs[a % reqs.len()];
                    FILLERS[kind](&handle.0, value);
                    handle
                        .1
                        .level
                        .borrow_mut()
                        .push(ModelEntry::Value(kind, value));
                    Some(handle)
                }
                _ => {
                    let (conn, conn_model) = conns[b % conns.len()].clone();
                    let handle = &reqs[a % reqs.len()];
                    if op % 11 == 9 {
                        handle.0.insert(Egress(conn));
                    } else {
                        handle.0.insert(Ingress(conn));
                    }
                    handle
                        .1
                        .level
                        .borrow_mut()
                        .push(ModelEntry::Wrapped(conn_model));
                    Some(handle)
                }
            };
            if let Some((ext, model)) = touched
                && !agrees_with_model(ext, model)
            {
                return false;
            }
        }
        conns
            .iter()
            .chain(&reqs)
            .all(|(ext, model)| agrees_with_model(ext, model))
    }

    #[test]
    fn lookups_agree_with_a_model_for_any_program() {
        quickcheck::QuickCheck::new()
            .tests(if cfg!(miri) { 3 } else { 300 })
            .rng(quickcheck::Gen::new(if cfg!(miri) { 30 } else { 120 }))
            .quickcheck(agrees_with_model_for as fn(Vec<(u8, u8, u8, u16)>) -> bool);
    }
}
