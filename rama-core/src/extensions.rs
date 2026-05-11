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

use std::any::{Any, TypeId};
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;

use rama_utils::collections::AppendOnlyVec;
use rama_utils::macros::impl_deref;

pub use rama_macros::Extension;

#[derive(Clone, Default)]
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
/// - Retry attempts fork from the original request (dont leak failed extensions)
/// - Responses fork the request (response != request)
/// - H2 streams fork from underlying H2 connection (nested connection with isolated properties)
///
/// Connection's who logically map one-to-one we don't fork and we just pass the [`Extensions`]
/// up, examples are:
/// - TLS layered on top of TCP
/// - HTTP layered on top of TLS
/// - ...
pub struct Extensions {
    extensions: Arc<AppendOnlyVec<TypeErasedExtension, 12, 3>>,
    parent: Option<Box<Self>>,
}

impl Extensions {
    /// Create an empty [`Extensions`] store with no parent.
    #[inline(always)]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a fresh child [`Extensions`] whose parent is this [`Extensions`] store.
    ///
    /// The child has its own empty top-level storage. Lookups that miss
    /// locally walk into the parent (and recursively up the chain). Inserts
    /// land on this child only, parents are never mutated through the child.
    #[must_use]
    pub fn fork(&self) -> Self {
        Self {
            extensions: Arc::new(AppendOnlyVec::new()),
            parent: Some(Box::new(self.clone())),
        }
    }

    /// The parent [`Extensions`] this blob was forked from, if any.
    #[inline(always)]
    #[must_use]
    pub fn parent(&self) -> Option<&Self> {
        self.parent.as_deref()
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
        let idx = self.extensions.push(extension);

        #[expect(
            clippy::unwrap_used,
            reason = "`downcast_ref` can only be none if TypeId doesn't match, but we just inserted this type"
        )]
        self.extensions[idx].downcast_ref::<T>().unwrap()
    }

    /// Insert a type `Arc<T>` into this [`Extensions]` store.
    ///
    /// This method returns a a cloned Arc of the value just inserted
    ///
    /// If the value you are inserting is not an `Arc<T>` or you don't
    /// need a cloned `Arc<T>` prefer using [`Self::insert()`]
    pub fn insert_arc<T: Extension>(&self, val: Arc<T>) -> Arc<T> {
        let extension = TypeErasedExtension::new_arc(val);
        let idx = self.extensions.push(extension);

        #[expect(
            clippy::unwrap_used,
            reason = "`cloned_downcast` can only be none if TypeId doesn't match, but we just inserted this type"
        )]
        self.extensions[idx].cloned_downcast::<T>().unwrap()
    }

    /// Extend this [`Extensions`] store with the other [`Extensions`].
    ///
    /// The other [`Extensions`]s will be appended behind the current ones
    pub fn extend(&self, other: &Self) {
        for ext in other.extensions.iter() {
            self.extensions.push(ext.clone());
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
        self.extensions
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
        for ext in self.extensions.iter().rev() {
            if ext.type_id == target {
                if let Some(v) = ext.downcast_ref::<T>() {
                    return Some(v);
                }
            } else if ext.type_id == egress_id
                && let Some(eg) = ext.downcast_ref::<Egress<Self>>()
                && let Some(v) = eg.0.get_ref::<T>()
            {
                return Some(v);
            } else if ext.type_id == ingress_id
                && let Some(ig) = ext.downcast_ref::<Ingress<Self>>()
                && let Some(v) = ig.0.get_ref::<T>()
            {
                return Some(v);
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
        self.extensions
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
        for ext in self.extensions.iter().rev() {
            if ext.type_id == target {
                if let Some(v) = ext.cloned_downcast::<T>() {
                    return Some(v);
                }
            } else if ext.type_id == egress_id
                && let Some(eg) = ext.downcast_ref::<Egress<Self>>()
                && let Some(v) = eg.0.get_arc::<T>()
            {
                return Some(v);
            } else if ext.type_id == ingress_id
                && let Some(ig) = ext.downcast_ref::<Ingress<Self>>()
                && let Some(v) = ig.0.get_arc::<T>()
            {
                return Some(v);
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
        self.extensions
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
    /// Currently we dont provide a recursive variant of this method since we don't have
    /// a use case for it, and it's not exactly clear what would be considered "first".
    #[must_use]
    pub fn self_first_ref<T: Extension>(&self) -> Option<&T> {
        let type_id = TypeId::of::<T>();
        self.extensions
            .iter()
            .find(|item| item.type_id == type_id)
            .and_then(|ext| ext.downcast_ref())
    }

    /// Raw flat [`Arc<T>`] to the oldest inserted `T` at the top level, see
    /// [`Self::self_first_ref`] for caveats.
    #[must_use]
    pub fn self_first_arc<T: Extension>(&self) -> Option<Arc<T>> {
        let type_id = TypeId::of::<T>();
        self.extensions
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

        self.extensions
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

        self.extensions
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
        self.extensions.iter()
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
        let local = self.extensions.iter().rev().flat_map(
            move |ext| -> Box<dyn Iterator<Item = &T> + '_> {
                if ext.type_id == target {
                    match ext.downcast_ref::<T>() {
                        Some(v) => Box::new(std::iter::once(v)),
                        None => Box::new(std::iter::empty()),
                    }
                } else if ext.type_id == egress_id {
                    match ext.downcast_ref::<Egress<Self>>() {
                        Some(e) => e.0.iter_ref_inner::<T>(),
                        None => Box::new(std::iter::empty()),
                    }
                } else if ext.type_id == ingress_id {
                    match ext.downcast_ref::<Ingress<Self>>() {
                        Some(i) => i.0.iter_ref_inner::<T>(),
                        None => Box::new(std::iter::empty()),
                    }
                } else {
                    Box::new(std::iter::empty())
                }
            },
        );
        let parent: Box<dyn Iterator<Item = &T>> = match self.parent() {
            Some(p) => p.iter_ref_inner::<T>(),
            None => Box::new(std::iter::empty()),
        };
        Box::new(local.chain(parent))
    }

    // TODO replace this later with a custom Iterator to avoid boxing
    fn iter_arc_inner<T: Extension>(&self) -> Box<dyn Iterator<Item = Arc<T>> + '_> {
        let target = TypeId::of::<T>();
        let egress_id = TypeId::of::<Egress<Self>>();
        let ingress_id = TypeId::of::<Ingress<Self>>();
        let local = self.extensions.iter().rev().flat_map(
            move |ext| -> Box<dyn Iterator<Item = Arc<T>> + '_> {
                if ext.type_id == target {
                    match ext.cloned_downcast::<T>() {
                        Some(v) => Box::new(std::iter::once(v)),
                        None => Box::new(std::iter::empty()),
                    }
                } else if ext.type_id == egress_id {
                    match ext.downcast_ref::<Egress<Self>>() {
                        Some(e) => e.0.iter_arc_inner::<T>(),
                        None => Box::new(std::iter::empty()),
                    }
                } else if ext.type_id == ingress_id {
                    match ext.downcast_ref::<Ingress<Self>>() {
                        Some(i) => i.0.iter_arc_inner::<T>(),
                        None => Box::new(std::iter::empty()),
                    }
                } else {
                    Box::new(std::iter::empty())
                }
            },
        );
        let parent: Box<dyn Iterator<Item = Arc<T>>> = match self.parent() {
            Some(p) => p.iter_arc_inner::<T>(),
            None => Box::new(std::iter::empty()),
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
}

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Extensions");
        if let Some(parent) = self.parent() {
            s.field("parent", parent);
        }
        s.field(
            "entries",
            &self.extensions.iter().map(|e| &e.value).collect::<Vec<_>>(),
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
pub trait Extension: Any + Send + Sync + std::fmt::Debug + 'static {}

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
    };
}

crate::combinators::impl_either!(impl_extensions_either);

pub trait ChainableExtensions {
    fn contains<T: Extension>(&self) -> bool;
    fn get_ref<T: Extension>(&self) -> Option<&T>;
    fn get_arc<T: Extension>(&self) -> Option<Arc<T>>;
}

impl<S, T> ChainableExtensions for (S, T)
where
    S: ExtensionsRef,
    T: ExtensionsRef,
{
    fn contains<I: Extension>(&self) -> bool {
        self.0.extensions().contains::<I>() || self.1.extensions().contains::<I>()
    }

    fn get_ref<I: Extension>(&self) -> Option<&I> {
        self.0
            .extensions()
            .get_ref::<I>()
            .or_else(|| self.1.extensions().get_ref::<I>())
    }

    fn get_arc<I: Extension>(&self) -> Option<Arc<I>> {
        self.0
            .extensions()
            .get_arc::<I>()
            .or_else(|| self.1.extensions().get_arc::<I>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::any::TypeId;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
    fn chainable_extensions_queries_both_sources() {
        let left = Extensions::new();
        let right = Extensions::new();
        left.insert(RetryBudget(1));
        right.insert(ConnectionTimeoutMs(2));

        let chain = (&left, &right);
        assert!(chain.contains::<RetryBudget>());
        assert!(chain.contains::<ConnectionTimeoutMs>());
        assert!(!chain.contains::<HealthSignal>());
        assert_eq!(chain.get_ref::<RetryBudget>(), Some(&RetryBudget(1)));
        assert_eq!(
            chain.get_ref::<ConnectionTimeoutMs>(),
            Some(&ConnectionTimeoutMs(2))
        );
        assert!(chain.get_arc::<RetryBudget>().is_some());
    }

    #[test]
    fn chainable_get_ref_prefers_first() {
        let left = Extensions::new();
        let right = Extensions::new();
        left.insert(WorkerId(1));
        right.insert(WorkerId(2));

        let chain = (&left, &right);
        assert_eq!(chain.get_ref::<WorkerId>(), Some(&WorkerId(1)));
    }

    #[test]
    fn chainable_get_ref_falls_back_to_second() {
        let left = Extensions::new();
        let right = Extensions::new();
        right.insert(WorkerId(2));

        let chain = (&left, &right);
        assert_eq!(chain.get_ref::<WorkerId>(), Some(&WorkerId(2)));
    }

    #[test]
    fn chainable_get_arc_falls_back_to_second() {
        let left = Extensions::new();
        let right = Extensions::new();
        right.insert(WorkerId(2));

        let chain = (&left, &right);
        let arc = chain.get_arc::<WorkerId>().unwrap();
        assert_eq!(*arc, WorkerId(2));
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
}
