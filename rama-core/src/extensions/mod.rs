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

use core::{any::TypeId, fmt};

pub use rama_macros::{Extension, ExtensionsRef, FromExtensions};
use rama_utils::collections::AppendOnlyVec;

use crate::std::{boxed::Box, sync::Arc, vec::Vec};

mod extension;
mod get_many;
mod refs;
mod store;
mod wrappers;

pub use extension::{
    DnsExtension, Extension, ExtensionScope, ExtensionsTransfer, ExtensionsTransferAnd,
    GrpcExtension, HttpExtension, NetExtension, NoExtensionsTransfer, ProxyExtension,
    SharedExtensionsTransfer, TlsExtension, TypeErasedExtension, UaExtension, WsExtension,
};
pub use get_many::{FromExtensionsGroup, GetManyArc, GetManyRef, Target, TargetPlan, Targets};
pub use refs::{ExtensionsMut, ExtensionsRef};
use store::{Node, Store, type_bit};
pub use wrappers::{Egress, Ingress};

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
/// - H2 streams fork from underlying H2 connection (a child connection with isolated properties)
///
/// Connection's who logically map one-to-one we don't fork and we just pass the [`Extensions`]
/// up, examples are:
/// - TLS layered on top of TCP
/// - HTTP layered on top of TLS
/// - ...
///
/// A level created by [`Extensions::fork_connection`] starts a child connection
/// of the chain it was forked from, its parent connection. Lookups of
/// [`ExtensionScope::Connection`] types stop there instead of resolving a fact
/// about the parent connection, see [`Extension::scope`].
pub struct Extensions {
    node: Arc<Node>,
}

impl Default for Extensions {
    fn default() -> Self {
        Self::new()
    }
}

impl Extensions {
    /// Create an empty [`Extensions`] store with no parent.
    #[inline(always)]
    #[must_use]
    pub fn new() -> Self {
        Self::with_parent(None, false)
    }

    #[inline(always)]
    /// Create an extension level with its parent and connection boundary.
    fn with_parent(parent: Option<Self>, connection_boundary: bool) -> Self {
        // Built in place: the inline entries are most of a node and stay
        // uninitialized, so there is nothing to move into the allocation.
        let node = Arc::into_raw(Arc::<Node>::new_uninit())
            .cast::<Node>()
            .cast_mut();
        // Premise P for the blocks below: `node` is the start of a fresh `Arc`
        // allocation for a `MaybeUninit<Node>`, which has `Node`'s size and
        // alignment (std docs), and nothing else reaches it until `Arc::from_raw`.

        // SAFETY: a field place of `*node` needs `node` in bounds of an allocation
        // that holds a `Node`'s bytes: P.
        let view_of = unsafe { &raw mut (*node).view_of };
        // SAFETY: `ptr::write` needs `view_of` valid for writes and aligned: a field
        // of the `Node` slot (P). The old bytes are uninitialized and not dropped.
        unsafe { view_of.write(None) };
        // SAFETY: as for `view_of`: P.
        let parent_slot = unsafe { &raw mut (*node).parent };
        // SAFETY: as for `view_of.write`: P.
        unsafe { parent_slot.write(parent) };
        // SAFETY: as for `view_of`: P.
        let boundary_slot = unsafe { &raw mut (*node).connection_boundary };
        // SAFETY: as for `view_of.write`: P.
        unsafe { boundary_slot.write(connection_boundary) };
        // SAFETY: as for `view_of`: P.
        let entries = unsafe { &raw mut (*node).entries.entries };
        // SAFETY: `init_in_place` needs `entries` valid for writes and aligned: a
        // field of the `Node` slot (P). Nothing there is dropped.
        unsafe { AppendOnlyVec::init_in_place(entries) };
        // SAFETY: `Arc::from_raw` needs a pointer from `Arc::<U>::into_raw` with `U`
        // of `Node`'s size and alignment (P, `U = MaybeUninit<Node>`), and the value
        // valid for `Node`: every field is written above except the inline entry
        // storage of `entries`, which is `MaybeUninit` and may stay uninitialized.
        // Takes over the one strong count `into_raw` released.
        let node = unsafe { Arc::from_raw(node) };
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

    /// Snapshot the current entries and connection boundaries, sharing stored values.
    /// Later inserts into the source chain do not change this snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Self {
        let snapshot = Self::with_parent(
            self.parent().map(Self::snapshot),
            self.node.connection_boundary,
        );
        snapshot.extend(self);
        snapshot
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
        Self::with_parent(Some(self.clone()), false)
    }

    /// Create a fresh child [`Extensions`] that starts a child connection of the
    /// connection this chain describes.
    ///
    /// Same as [`Self::fork`] for [`ExtensionScope::Flow`] types: config,
    /// routing and other intent keeps resolving through. Lookups of
    /// [`ExtensionScope::Connection`] types stop at this level instead, so a
    /// fact about the parent connection (its negotiated ALPN, its TLS
    /// parameters, whether it may be reused, ...) does not answer for the
    /// child. Use it where another connection starts from this one: one
    /// established over it (a `CONNECT` tunnel, a SOCKS5 stream, a CONNECT-UDP
    /// flow), or one dialed on behalf of its request (the connection to a proxy).
    ///
    /// `transfer` decides what the child keeps of the facts the boundary would
    /// otherwise stop, see [`ExtensionsTransfer`]. Pass [`NoExtensionsTransfer`]
    /// for a plain boundary that keeps none of them.
    ///
    /// [`Self::iter_ref`] and [`Self::iter_arc`] still walk past the boundary.
    #[must_use]
    pub fn fork_connection(&self, transfer: &dyn ExtensionsTransfer) -> Self {
        let child = Self::with_parent(Some(self.clone()), true);
        transfer.transfer(self, &child);
        child
    }

    /// Whether this level was created by [`Self::fork_connection`].
    #[inline(always)]
    fn is_connection_boundary(&self) -> bool {
        self.node.connection_boundary
    }

    /// Whether a lookup of `T` stops at this level instead of continuing into
    /// the parent chain.
    #[inline(always)]
    fn ends_scope_of<T: Extension>(&self) -> bool {
        T::scope().is_connection() && self.is_connection_boundary()
    }

    /// The parent [`Extensions`] this blob was forked from, if any.
    #[inline(always)]
    #[must_use]
    pub fn parent(&self) -> Option<&Self> {
        self.node.parent.as_ref()
    }

    /// The extensions of the parent connection: the parent of the nearest
    /// [`Self::fork_connection`] level, if any.
    ///
    /// Lookups on the result stop at its own boundaries, so each answer is
    /// about that one connection.
    #[must_use]
    pub fn parent_connection(&self) -> Option<&Self> {
        let mut level = self;
        loop {
            if level.is_connection_boundary() {
                return level.parent();
            }
            level = level.parent()?;
        }
    }

    /// Each parent connection, nearest first: [`Self::parent_connection`] repeated.
    pub fn parent_connections(&self) -> impl Iterator<Item = &Self> {
        core::iter::successors(self.parent_connection(), |connection| {
            connection.parent_connection()
        })
    }

    /// Return a view of this [`Extensions`] chain layered on top of `base`.
    ///
    /// The toplevel extensions are still the same and are editable.
    /// Lookups resolve through this chain first falling back to `base`
    /// only when nothing matches.
    ///
    /// `base` answers as defaults of this connection: its connection-scoped
    /// entries, as a lookup on `base` sees them, start this chain's connection,
    /// right below its own levels and above the boundary to a parent connection.
    /// Everything else of `base` is at the bottom, below the parent connections.
    ///
    /// Use this when you have an Extensions (chain) to which you want to apply
    /// defaults, e.g. `request_extensions().with_base(&base_extension_config)`
    #[must_use]
    pub fn with_base(&self, base: &Self) -> Self {
        self.view_over(base, true)
    }

    fn view_over(&self, base: &Self, connection_defaults_pending: bool) -> Self {
        let boundary = self.node.connection_boundary;
        let splice = connection_defaults_pending && boundary;
        let parent = match self.parent() {
            Some(parent) => parent.view_over(base, connection_defaults_pending && !boundary),
            None => base.clone(),
        };
        let parent = if splice {
            let defaults = Self::with_parent(Some(parent), true);
            defaults.extend_connection_defaults(base);
            defaults
        } else {
            parent
        };
        Self {
            node: Arc::new(Node {
                view_of: Some(self.owner().clone()),
                parent: Some(parent),
                connection_boundary: boundary && !splice,
                entries: Store::default(),
            }),
        }
    }

    // The connection-scoped entries of `base` a connection lookup on it reaches,
    // oldest first: its levels down to and including its first boundary.
    fn extend_connection_defaults(&self, base: &Self) {
        if !base.is_connection_boundary()
            && let Some(parent) = base.parent()
        {
            self.extend_connection_defaults(parent);
        }
        for entry in base.store().entries.iter() {
            if entry.scope().is_connection() {
                self.store().push(entry.clone());
            }
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

    /// Extend this [`Extensions`] store with the other [`Extensions`] and every
    /// level it was forked from, oldest first, so the newest entry of a type in
    /// `other` is also the newest one here.
    ///
    /// Use it to apply a bag of settings that may be a fork of shared defaults,
    /// such as per-route settings forked from settings for every route: [`Self::extend`]
    /// would copy only the bag's own level and drop the defaults it was forked from.
    ///
    /// It copies what a lookup in `other` sees: past its first connection boundary
    /// only [`ExtensionScope::Flow`] entries, as [`ExtensionScope::Connection`] ones
    /// stop there.
    pub fn extend_chain(&self, other: &Self) {
        self.extend_chain_seen(other, false);
    }

    fn extend_chain_seen(&self, other: &Self, past_boundary: bool) {
        if let Some(parent) = other.parent() {
            self.extend_chain_seen(parent, past_boundary || other.is_connection_boundary());
        }
        for entry in other.store().entries.iter() {
            if !past_boundary || !entry.scope().is_connection() {
                self.store().push(entry.clone());
            }
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
    /// 2. If still not found, recurse into the parent (same rule applied),
    ///    unless `T` is [`ExtensionScope::Connection`] scoped and this level
    ///    was created by [`Self::fork_connection`]: then the search
    ///    stops here, a fact about the connection underneath does not answer
    ///    for the nested one.
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
        self.find::<T>().and_then(TypeErasedExtension::downcast_ref)
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
        self.find::<T>()
            .and_then(TypeErasedExtension::cloned_downcast)
    }

    /// The entry [`Self::get_ref`] and [`Self::get_arc`] resolve `T` to, see
    /// [`Self::get_ref`] for the search order.
    fn find<T: Extension>(&self) -> Option<&TypeErasedExtension> {
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
                        return Some(ext);
                    } else if has_wrappers
                        && ext.type_id == egress_id
                        && let Some(eg) = ext.downcast_ref::<Egress<Self>>()
                        && let Some(found) = eg.0.find::<T>()
                    {
                        return Some(found);
                    } else if has_wrappers
                        && ext.type_id == ingress_id
                        && let Some(ig) = ext.downcast_ref::<Ingress<Self>>()
                        && let Some(found) = ig.0.find::<T>()
                    {
                        return Some(found);
                    }
                }
            }
        }
        if self.ends_scope_of::<T>() {
            return None;
        }
        self.parent().and_then(Self::find::<T>)
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
    /// Within each connection, yield order matches [`Self::get_ref`] preference.
    ///
    /// At each level, iterate the local entries newest -> oldest. For each
    /// entry: yield it if its type matches `T`, if it is an
    /// [`Egress<Extensions>`] or [`Ingress<Extensions>`] wrapper, recurse into
    /// the wrapped blob (same rule applied) and yield its results inline. Then
    /// recurse into the parent.
    ///
    /// For a flat top-level-only iteration use [`Self::self_iter_ref`].
    ///
    /// Unlike [`Self::get_ref`] this walks past every
    /// [`Self::fork_connection`] boundary whatever the
    /// [`ExtensionScope`] of `T`, so it yields the facts of the connections
    /// underneath too, without telling which connection each belongs to. For
    /// the facts of one connection underneath use [`Self::parent_connection`].
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
    /// Walk borrowed values through the active extension scopes.
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
    /// Walk shared values through the active extension scopes.
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

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Extensions");
        s.field("connection_boundary", &self.node.connection_boundary);
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

#[cfg(test)]
mod tests {
    use core::{
        any::TypeId,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Extension)]
    pub(super) struct TraceNote(pub(super) String);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
    pub(super) struct RetryBudget(pub(super) u32);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
    pub(super) struct ConnectionTimeoutMs(pub(super) u64);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
    pub(super) struct WorkerId(pub(super) i32);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
    pub(super) struct HealthSignal(pub(super) u8);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
    pub(super) struct FeatureToggle(pub(super) bool);

    #[derive(Debug, Clone, PartialEq, Eq, Extension)]
    pub(super) struct ConnSocketInfo(pub(super) &'static str);

    #[derive(Debug, Clone, PartialEq, Eq, Extension)]
    pub(super) struct RequestId(pub(super) u64);

    // The lookups skip levels and entries with the `Store` filter (its tags).
    // These tests pin that it never changes an answer: every lookup is compared
    // with a plain reference walk that has no filter, over pseudo-random chains
    // with more types than the filter has bits, so collisions are exercised.

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Extension)]
    #[extension(scope(connection))]
    pub(super) struct NegotiatedAlpn(pub(super) u8);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Extension)]
    #[extension(tags(net), scope(connection))]
    pub(super) struct Reuse(pub(super) bool);

    #[test]
    fn snapshots_keep_entries_and_connection_boundaries() {
        let outer = Extensions::new();
        let note = outer.insert_arc(Arc::new(RetryBudget(2)));
        outer.insert(NegotiatedAlpn(1));
        let inner = outer.fork_connection(&NoExtensionsTransfer::new());
        let snapshot = inner.snapshot();
        outer.insert(RetryBudget(3));
        inner.insert(NegotiatedAlpn(2));
        assert_eq!(snapshot.get_ref::<RetryBudget>(), Some(&RetryBudget(2)));
        assert!(snapshot.get_ref::<NegotiatedAlpn>().is_none());
        assert!(Arc::ptr_eq(
            &note,
            &snapshot.get_arc::<RetryBudget>().unwrap()
        ));
        assert_eq!(
            snapshot
                .parent_connection()
                .unwrap()
                .get_ref::<NegotiatedAlpn>(),
            Some(&NegotiatedAlpn(1))
        );
    }

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
    fn extend_chain_copies_every_level_with_the_newest_winning() {
        let base = Extensions::new();
        base.insert(NegotiatedAlpn(1));
        base.insert(RetryBudget(3));
        let bag = base.fork();
        bag.insert(NegotiatedAlpn(2));

        let target = Extensions::new();
        target.extend_chain(&bag);

        assert!(target.parent().is_none());
        assert_eq!(target.get_ref::<NegotiatedAlpn>(), Some(&NegotiatedAlpn(2)));
        assert_eq!(target.get_ref::<RetryBudget>(), Some(&RetryBudget(3)));
    }

    #[test]
    fn extend_chain_keeps_what_a_connection_boundary_hides_hidden() {
        let outer = Extensions::new();
        outer.insert(NegotiatedAlpn(1));
        outer.insert(RetryBudget(3));
        let bag = outer.fork_connection(&NoExtensionsTransfer::new());
        assert!(bag.get_ref::<NegotiatedAlpn>().is_none());

        let target = Extensions::new();
        target.extend_chain(&bag);

        assert!(target.get_ref::<NegotiatedAlpn>().is_none());
        assert_eq!(target.get_ref::<RetryBudget>(), Some(&RetryBudget(3)));

        bag.insert(NegotiatedAlpn(2));
        let target = Extensions::new();
        target.extend_chain(&bag.fork());
        assert_eq!(target.get_ref::<NegotiatedAlpn>(), Some(&NegotiatedAlpn(2)));
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
    fn flow_type_resolves_across_a_nested_connection() {
        let proxy = Extensions::new();
        proxy.insert(RetryBudget(3));

        let origin = proxy.fork_connection(&NoExtensionsTransfer::new());
        assert_eq!(origin.get_ref::<RetryBudget>(), Some(&RetryBudget(3)));
        assert_eq!(
            origin.fork().get_ref::<RetryBudget>(),
            Some(&RetryBudget(3))
        );
    }

    #[test]
    fn connection_type_stops_at_a_nested_connection() {
        let proxy = Extensions::new();
        proxy.insert(NegotiatedAlpn(2));
        assert_eq!(proxy.get_ref::<NegotiatedAlpn>(), Some(&NegotiatedAlpn(2)));

        let origin = proxy.fork_connection(&NoExtensionsTransfer::new());
        assert_eq!(origin.get_ref::<NegotiatedAlpn>(), None);
        assert_eq!(origin.fork().get_ref::<NegotiatedAlpn>(), None);
    }

    #[test]
    fn connection_type_written_on_the_boundary_level_is_found() {
        let proxy = Extensions::new();
        proxy.insert(NegotiatedAlpn(2));

        let origin = proxy.fork_connection(&NoExtensionsTransfer::new());
        origin.insert(NegotiatedAlpn(1));

        assert_eq!(origin.get_ref::<NegotiatedAlpn>(), Some(&NegotiatedAlpn(1)));
        assert_eq!(
            origin.fork().get_ref::<NegotiatedAlpn>(),
            Some(&NegotiatedAlpn(1))
        );
    }

    #[test]
    fn nested_boundaries_each_stop_the_search() {
        let tcp = Extensions::new();
        tcp.insert(NegotiatedAlpn(2));
        tcp.insert(RetryBudget(3));

        let first_tunnel = tcp.fork_connection(&NoExtensionsTransfer::new());
        first_tunnel.insert(NegotiatedAlpn(1));

        let second_tunnel = first_tunnel.fork_connection(&NoExtensionsTransfer::new());
        assert_eq!(second_tunnel.get_ref::<NegotiatedAlpn>(), None);
        assert_eq!(
            second_tunnel.get_ref::<RetryBudget>(),
            Some(&RetryBudget(3))
        );
    }

    #[test]
    fn parent_connection_reads_each_connection_underneath() {
        let tcp = Extensions::new();
        tcp.insert(NegotiatedAlpn(3));

        let first_tunnel = tcp.fork_connection(&NoExtensionsTransfer::new());
        first_tunnel.insert(NegotiatedAlpn(2));

        let second_tunnel = first_tunnel.fork_connection(&NoExtensionsTransfer::new());
        let origin = second_tunnel.fork();
        origin.insert(NegotiatedAlpn(1));

        let outer = origin.parent_connection().unwrap();
        assert_eq!(outer.get_ref::<NegotiatedAlpn>(), Some(&NegotiatedAlpn(2)));
        let outermost = outer.parent_connection().unwrap();
        assert_eq!(
            outermost.get_ref::<NegotiatedAlpn>(),
            Some(&NegotiatedAlpn(3))
        );
        assert!(outermost.parent_connection().is_none());
    }

    #[test]
    fn parent_connections_yields_each_connection_nearest_first() {
        let tcp = Extensions::new();
        tcp.insert(NegotiatedAlpn(3));

        let first_tunnel = tcp.fork_connection(&NoExtensionsTransfer::new());
        first_tunnel.insert(NegotiatedAlpn(2));

        let second_tunnel = first_tunnel.fork_connection(&NoExtensionsTransfer::new());
        let origin = second_tunnel.fork();
        origin.insert(NegotiatedAlpn(1));

        let alpns: Vec<_> = origin
            .parent_connections()
            .map(|connection| connection.get_ref::<NegotiatedAlpn>())
            .collect();
        assert_eq!(alpns, [Some(&NegotiatedAlpn(2)), Some(&NegotiatedAlpn(3))]);
        assert_eq!(tcp.parent_connections().count(), 0);
    }

    #[test]
    fn parent_connection_is_none_without_a_boundary() {
        let tcp = Extensions::new();
        let stream = tcp.fork();
        assert!(stream.parent_connection().is_none());
    }

    #[test]
    fn iter_reads_through_a_nested_connection_boundary() {
        let proxy = Extensions::new();
        proxy.insert(NegotiatedAlpn(2));

        let origin = proxy.fork_connection(&NoExtensionsTransfer::new());
        origin.insert(NegotiatedAlpn(1));

        assert_eq!(
            origin
                .iter_ref::<NegotiatedAlpn>()
                .copied()
                .collect::<Vec<_>>(),
            vec![NegotiatedAlpn(1), NegotiatedAlpn(2)]
        );
        assert_eq!(
            origin
                .iter_arc::<NegotiatedAlpn>()
                .map(|alpn| *alpn)
                .collect::<Vec<_>>(),
            vec![NegotiatedAlpn(1), NegotiatedAlpn(2)]
        );
    }

    #[derive(Debug, FromExtensions)]
    struct ScopedView<'a> {
        budget: Option<&'a RetryBudget>,
        alpn: Option<&'a NegotiatedAlpn>,
        reuse: Option<Arc<Reuse>>,
    }

    #[test]
    fn every_lookup_honours_the_nested_connection_boundary() {
        let proxy = Extensions::new();
        proxy.insert(RetryBudget(3));
        proxy.insert(NegotiatedAlpn(2));
        proxy.insert(Reuse(true));

        let origin = proxy.fork_connection(&NoExtensionsTransfer::new());

        assert_eq!(origin.get_ref::<NegotiatedAlpn>(), None);
        assert!(origin.get_arc::<NegotiatedAlpn>().is_none());
        assert!(!origin.contains::<NegotiatedAlpn>());
        assert_eq!(
            origin.get_ref_or_insert(|| NegotiatedAlpn(1)),
            &NegotiatedAlpn(1)
        );
        assert_eq!(
            *origin.get_arc_or_insert(|| Arc::new(Reuse(false))),
            Reuse(false)
        );

        let (budget, alpn) = origin.get_many_ref::<(RetryBudget, NegotiatedAlpn)>();
        assert_eq!(budget, Some(&RetryBudget(3)));
        assert_eq!(alpn, Some(&NegotiatedAlpn(1)));

        let (budget, reuse) = origin.get_many_arc::<(RetryBudget, Reuse)>();
        assert_eq!(budget.as_deref(), Some(&RetryBudget(3)));
        assert_eq!(reuse.as_deref(), Some(&Reuse(false)));

        let view = ScopedView::from_extensions(&origin);
        assert_eq!(view.budget, Some(&RetryBudget(3)));
        assert_eq!(view.alpn, Some(&NegotiatedAlpn(1)));
        assert_eq!(view.reuse.as_deref(), Some(&Reuse(false)));

        let target = Extensions::new();
        let fresh = proxy.fork_connection(&NoExtensionsTransfer::new());
        assert!(fresh.clone_to::<NegotiatedAlpn>(&target).is_none());
        assert!(
            fresh
                .clone_to_if_absent::<NegotiatedAlpn>(&target)
                .is_none()
        );
        assert_eq!(
            fresh.clone_to::<RetryBudget>(&target).as_deref(),
            Some(&RetryBudget(3))
        );
    }

    #[test]
    fn get_many_fills_a_connection_slot_from_a_wrapper_above_the_boundary() {
        let peer = Extensions::new();
        peer.insert(NegotiatedAlpn(7));

        let below = Extensions::new();
        below.insert(NegotiatedAlpn(2));
        below.insert(RetryBudget(3));

        let origin = below.fork_connection(&NoExtensionsTransfer::new());
        origin.insert(Egress(peer));

        assert_eq!(origin.get_ref::<NegotiatedAlpn>(), Some(&NegotiatedAlpn(7)));
        let (budget, alpn) = origin.get_many_ref::<(RetryBudget, NegotiatedAlpn)>();
        assert_eq!(budget, Some(&RetryBudget(3)));
        assert_eq!(alpn, Some(&NegotiatedAlpn(7)));
    }

    #[test]
    fn a_boundary_inside_a_wrapper_applies_to_the_wrapped_chain() {
        let tcp = Extensions::new();
        tcp.insert(NegotiatedAlpn(2));
        tcp.insert(RetryBudget(3));
        let tunnel = tcp.fork_connection(&NoExtensionsTransfer::new());

        let req = Extensions::new();
        req.insert(Egress(tunnel));

        assert_eq!(req.get_ref::<NegotiatedAlpn>(), None);
        assert_eq!(req.get_ref::<RetryBudget>(), Some(&RetryBudget(3)));
        let (budget, alpn) = req.get_many_ref::<(RetryBudget, NegotiatedAlpn)>();
        assert_eq!(budget, Some(&RetryBudget(3)));
        assert_eq!(alpn, None);
    }

    #[test]
    fn self_lookups_ignore_the_nested_connection_boundary() {
        let proxy = Extensions::new();
        proxy.insert(NegotiatedAlpn(2));

        let origin = proxy.fork_connection(&NoExtensionsTransfer::new());
        assert_eq!(origin.self_get_ref::<NegotiatedAlpn>(), None);
        assert_eq!(
            origin.self_get_ref_or_insert(|| NegotiatedAlpn(1)),
            &NegotiatedAlpn(1)
        );
        assert_eq!(
            origin.self_get_ref::<NegotiatedAlpn>(),
            Some(&NegotiatedAlpn(1))
        );
    }

    #[test]
    fn with_base_answers_for_the_connection_behind_its_boundary() {
        let base = Extensions::new();
        base.insert(NegotiatedAlpn(2));
        base.insert(RetryBudget(3));

        let parent = Extensions::new();
        parent.insert(NegotiatedAlpn(1));
        let origin = parent.fork_connection(&NoExtensionsTransfer::new());
        let view = origin.with_base(&base);

        assert_eq!(view.get_ref::<NegotiatedAlpn>(), Some(&NegotiatedAlpn(2)));
        assert_eq!(view.get_ref::<RetryBudget>(), Some(&RetryBudget(3)));

        origin.insert(NegotiatedAlpn(4));
        assert_eq!(
            view.get_ref::<NegotiatedAlpn>(),
            Some(&NegotiatedAlpn(4)),
            "the connection's own facts win over its defaults"
        );

        let child = view.fork_connection(&NoExtensionsTransfer::new());
        assert_eq!(
            child.get_ref::<NegotiatedAlpn>(),
            None,
            "a child connection does not inherit the defaults of its parent"
        );
    }

    #[test]
    fn with_base_takes_only_what_its_base_answers_for_its_own_connection() {
        let base_parent = Extensions::new();
        base_parent.insert(NegotiatedAlpn(7));
        let base = base_parent.fork_connection(&NoExtensionsTransfer::new());

        let origin = Extensions::new().fork_connection(&NoExtensionsTransfer::new());
        let view = origin.with_base(&base);

        assert_eq!(view.get_ref::<NegotiatedAlpn>(), None);
    }

    /// 72 distinct types: more than the bits of the `Store` filter.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Filler<const N: usize>(u32);

    /// Half the fillers are connection scoped, so every lookup shape is
    /// exercised with and without a scope boundary.
    const fn filler_scope(n: usize) -> ExtensionScope {
        if n.is_multiple_of(2) {
            ExtensionScope::Flow
        } else {
            ExtensionScope::Connection
        }
    }

    impl<const N: usize> Extension for Filler<N> {
        fn scope() -> ExtensionScope {
            filler_scope(N)
        }
    }

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

    macro_rules! filler_targets {
        ($($n:literal)+) => {
            [$(Target::of::<Filler<$n>>()),+]
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
    /// them, together with the rank they have in the traversal and whether a
    /// connection scoped lookup still reaches them.
    fn reference_walk<'a>(
        ext: &'a Extensions,
        past_boundary: bool,
        out: &mut Vec<(&'a TypeErasedExtension, bool)>,
    ) {
        let mut entries: Vec<_> = ext.self_iter_all().collect();
        entries.reverse();
        for entry in entries {
            out.push((entry, !past_boundary));
            if let Some(eg) = entry.downcast_ref::<Egress<Extensions>>() {
                reference_walk(&eg.0, past_boundary, out);
            } else if let Some(ig) = entry.downcast_ref::<Ingress<Extensions>>() {
                reference_walk(&ig.0, past_boundary, out);
            }
        }
        if let Some(parent) = ext.parent() {
            reference_walk(parent, past_boundary || ext.is_connection_boundary(), out);
        }
    }

    fn reference_get(
        ext: &Extensions,
        id: TypeId,
        scope: ExtensionScope,
    ) -> Option<(&TypeErasedExtension, usize)> {
        let mut walk = Vec::new();
        reference_walk(ext, false, &mut walk);
        walk.into_iter()
            .enumerate()
            .find(|(_, (entry, in_scope))| {
                TypeErasedExtension::type_id(entry) == id && (*in_scope || !scope.is_connection())
            })
            .map(|(rank, (entry, _))| (entry, rank))
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
                3 if depth > 0 => ext = ext.fork_connection(&NoExtensionsTransfer::new()),
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
                    let expected = reference_get(&ext, TypeId::of::<$t>(), <$t>::scope())
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
            let egress = reference_get(
                &ext,
                TypeId::of::<Egress<Extensions>>(),
                ExtensionScope::Flow,
            )
            .is_some();
            assert_eq!(ext.egress().is_some(), egress);
            let ingress = reference_get(
                &ext,
                TypeId::of::<Ingress<Extensions>>(),
                ExtensionScope::Flow,
            )
            .is_some();
            assert_eq!(ext.ingress().is_some(), ingress);
        }
    }

    fn assert_matches_reference(
        ext: &Extensions,
        targets: &[Target],
        out: &[Option<(&TypeErasedExtension, usize)>],
    ) {
        let expected: Vec<_> = targets
            .iter()
            .map(|target| reference_get(ext, target.id, target.scope))
            .collect();
        for (found, expected) in out.iter().zip(&expected) {
            assert_eq!(
                found.map(|(entry, _)| core::ptr::from_ref(entry)),
                expected.map(|(entry, _)| core::ptr::from_ref(entry)),
            );
        }
        let ranks = || {
            out.iter()
                .zip(&expected)
                .filter_map(|(found, expected)| Some((found.as_ref()?.1, expected.as_ref()?.1)))
        };
        for (found_a, expected_a) in ranks() {
            for (found_b, expected_b) in ranks() {
                assert_eq!(found_a.cmp(&found_b), expected_a.cmp(&expected_b));
            }
        }
    }

    #[test]
    fn get_many_matches_unfiltered_walk_on_random_chains() {
        let mut rng = Xorshift(0xD1B5_4A32_D192_ED03);
        for _ in 0..500 {
            let ext = random_chain(&mut rng, 3);
            let targets = [
                Target::of::<Filler<2>>(),
                Target::of::<Filler<19>>(),
                Target::of::<Filler<33>>(),
                Target::of::<Filler<48>>(),
                Target::of::<Filler<60>>(),
                Target::of::<Filler<70>>(),
                Target::of::<Egress<Extensions>>(),
                Target::of::<Ingress<Extensions>>(),
            ];
            let mut out = [None; 8];
            ext.get_many_erased(&targets, &mut out);
            assert_matches_reference(&ext, &targets, &out);
        }
    }

    #[test]
    fn get_many_of_more_targets_than_slots_matches_unfiltered_walk() {
        let mut rng = Xorshift(0xA076_1D64_78BD_642F);
        // every filler once, then again: several targets share a slot, and
        // duplicates ask the same question twice
        let mut targets = with_fillers!(filler_targets).to_vec();
        targets.extend_from_slice(&targets.clone());
        let targets: [Target; 144] = targets.try_into().unwrap();
        for _ in 0..200 {
            let ext = random_chain(&mut rng, 3);
            let mut out = [None; 144];
            ext.get_many_erased(&targets, &mut out);
            assert_matches_reference(&ext, &targets, &out);
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
                                plan.get(|| [Target::of::<Filler<0>>(), Target::of::<Filler<1>>()]);
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
        connection_boundary: bool,
    }

    impl ModelExtensions {
        fn new() -> Self {
            Self {
                level: Default::default(),
                parent: None,
                connection_boundary: false,
            }
        }

        fn fork(&self) -> Self {
            Self {
                level: Default::default(),
                parent: Some(Box::new(self.clone())),
                connection_boundary: false,
            }
        }

        fn fork_connection(&self) -> Self {
            Self {
                level: Default::default(),
                parent: Some(Box::new(self.clone())),
                connection_boundary: true,
            }
        }

        fn with_base(&self, base: &Self) -> Self {
            self.view_over(base, true)
        }

        fn view_over(&self, base: &Self, connection_defaults_pending: bool) -> Self {
            let splice = connection_defaults_pending && self.connection_boundary;
            let parent = match &self.parent {
                Some(parent) => parent.view_over(
                    base,
                    connection_defaults_pending && !self.connection_boundary,
                ),
                None => base.clone(),
            };
            let parent = if splice {
                Self {
                    level: std::rc::Rc::new(std::cell::RefCell::new(base.connection_defaults())),
                    parent: Some(Box::new(parent)),
                    connection_boundary: true,
                }
            } else {
                parent
            };
            Self {
                level: self.level.clone(),
                parent: Some(Box::new(parent)),
                connection_boundary: self.connection_boundary && !splice,
            }
        }

        fn connection_defaults(&self) -> Vec<ModelEntry> {
            let mut entries = match &self.parent {
                Some(parent) if !self.connection_boundary => parent.connection_defaults(),
                _ => Vec::new(),
            };
            entries.extend(
                self.level
                    .borrow()
                    .iter()
                    .filter(|entry| {
                        matches!(entry, ModelEntry::Value(kind, _) if filler_scope(*kind).is_connection())
                    })
                    .cloned(),
            );
            entries
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
            if self.connection_boundary && filler_scope(kind).is_connection() {
                return None;
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
        let targets: [Target; MODEL_KINDS] = model_kinds!(filler_targets);
        let mut many = [None; MODEL_KINDS];
        ext.get_many_erased(&targets, &mut many);
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
            let touched = match op % 13 {
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
                9 => {
                    let (ext, model) = &conns[a % conns.len()];
                    let forked = (
                        ext.fork_connection(&NoExtensionsTransfer::new()),
                        model.fork_connection(),
                    );
                    conns.push(forked);
                    conns.last()
                }
                10 => {
                    let (ext, model) = &reqs[a % reqs.len()];
                    let forked = (
                        ext.fork_connection(&NoExtensionsTransfer::new()),
                        model.fork_connection(),
                    );
                    reqs.push(forked);
                    reqs.last()
                }
                _ => {
                    let (conn, conn_model) = conns[b % conns.len()].clone();
                    let handle = &reqs[a % reqs.len()];
                    if op % 13 == 11 {
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
