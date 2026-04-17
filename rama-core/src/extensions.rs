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

pub use rama_macros::Extension;

#[derive(Clone, Default)]
/// A type map of protocol extensions.
///
/// [`Extension`]s are internally stored in a type erased [`Arc`]. Since values are
/// stored in an [`Arc`] there are extra methods exposed that build on top of this
/// and leverage characteristics of an [`Arc`] to expose things like cheap cloning of the Arc.
pub struct Extensions {
    extensions: Arc<AppendOnlyVec<TypeErasedExtension, 12, 3>>,
}

impl Extensions {
    /// Create an empty [`Extensions`] store.
    #[inline(always)]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a type `T` into this [`Extensions`] store.
    ///
    /// This method returns a refence to the just insert value
    ///
    /// If the value you are inserting is an `Arc<T>`, prefer using
    /// [`Self::insert_arc()`] to prevent the double indirection of storing
    /// an `Arc<Arc<T>>`. This happens because internally we use a type erased
    /// Arc to store the actual value.
    pub fn insert<T: Extension>(&self, val: T) -> &T {
        let extension = TypeErasedExtension::new(val);
        let idx = self.extensions.push(extension);

        #[allow(
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

        #[allow(
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
    #[must_use]
    pub fn contains<T: Extension>(&self) -> bool {
        let type_id = TypeId::of::<T>();
        self.extensions
            .iter()
            .rev()
            .any(|item| item.type_id == type_id)
    }

    #[must_use]
    /// Get a reference to the most recently insert item of type `T`, or insert in case no item was found
    ///
    /// If an owned `Arc<T>` is needed prefer using [`Self::get_arc()`]
    ///
    /// [`Self::get_ref`] will return the last added item `T`, in most cases this is exactly what you want, but
    /// if you need the oldest item `T` use [`Self::first_ref`]
    pub fn get_ref<T: Extension>(&self) -> Option<&T> {
        let type_id = TypeId::of::<T>();
        self.extensions
            .iter()
            .rev()
            .find(|item| item.type_id == type_id)
            .and_then(|ext| ext.downcast_ref())
    }

    #[must_use]
    /// Get an owned `Arc<T>` of the most recently insert item of type `T`, or insert in case no item was found
    ///
    /// If a reference is needed prefer using [`Self::get_ref()`]
    ///
    /// [`Self::get_arc`] will return the last added item `T`, in most cases this is exactly what you want, but
    /// if you need the oldest item `T` use [`Self::first_arc`]
    pub fn get_arc<T: Extension>(&self) -> Option<Arc<T>> {
        let type_id = TypeId::of::<T>();
        self.extensions
            .iter()
            .rev()
            .find(|item| item.type_id == type_id)
            .and_then(|ext| ext.cloned_downcast())
    }

    /// Get a reference to the most recently insert item of type `T`, or insert in case no item was found
    ///
    /// If an owned `Arc<T>` is needed or inserting prefer using [`Self::get_arc_or_insert()`]
    pub fn get_ref_or_insert<T, F>(&self, create_fn: F) -> &T
    where
        T: Extension,
        F: FnOnce() -> T,
    {
        self.get_ref().unwrap_or_else(|| self.insert(create_fn()))
    }

    /// Get an owned `Arc<T>` of the most recently insert item of type `T`, or insert in case no item was found
    ///
    /// If a reference is needed or the type being inserted in not an `Arc<T>` prefer using [`Self::get_ref_or_insert()`]
    pub fn get_arc_or_insert<T, F>(&self, create_fn: F) -> Arc<T>
    where
        T: Extension,
        F: FnOnce() -> Arc<T>,
    {
        self.get_arc()
            .unwrap_or_else(|| self.insert_arc(create_fn()))
    }

    /// Get a shared reference to the oldest inserted item of type `T`
    ///
    /// If an owned `Arc<T>` is needed prefer using [`Self::get_arc()`]
    ///
    /// [`Self::first_ref`] will return the first added item `T`, in most cases this is not what you want,
    /// instead use [`Self::get_ref`] to get the most recently inserted item `T`
    #[must_use]
    pub fn first_ref<T: Extension>(&self) -> Option<&T> {
        let type_id = TypeId::of::<T>();
        self.extensions
            .iter()
            .find(|item| item.type_id == type_id)
            .and_then(|ext| ext.downcast_ref())
    }

    #[must_use]
    /// Get an owned `Arc<T>` of the oldest inserted item of type `T`
    ///
    /// If a reference is needed prefer using [`Self::first_ref()`]
    ///
    /// [`Self::first_arc`] will return the first added item `T`, in most cases this is not what you want,
    /// instead use [`Self::get_arc`] to get the most recently inserted item `T`
    pub fn first_arc<T: Extension>(&self) -> Option<Arc<T>> {
        let type_id = TypeId::of::<T>();
        self.extensions
            .iter()
            .find(|item| item.type_id == type_id)
            .and_then(|ext| ext.cloned_downcast())
    }

    /// Iterate over all the inserted items of type `T` as shared references.
    ///
    /// Items are ordered from oldest to newest.
    pub fn iter_ref<T: Extension>(&self) -> impl Iterator<Item = &T> {
        let type_id = TypeId::of::<T>();

        self.extensions
            .iter()
            .filter(move |item| item.type_id == type_id)
            .filter_map(TypeErasedExtension::downcast_ref::<T>)
    }

    /// Iterate over all the inserted items of type `T` as cloned [`Arc`] values.
    ///
    /// Items are ordered from oldest to newest.
    pub fn iter_arc<T: Extension>(&self) -> impl Iterator<Item = Arc<T>> {
        let type_id = TypeId::of::<T>();

        self.extensions
            .iter()
            .filter(move |item| item.type_id == type_id)
            .filter_map(TypeErasedExtension::cloned_downcast::<T>)
    }

    /// Iter over all the [`TypeErasedExtension`]
    ///
    /// This can be used to efficiently combine different types of [`Extension`]s in
    /// only a single iteration. [`TypeErasedExtension`] exposes methods to easily
    /// convert it back to type `T` if it matches the erasaed type stored internally.
    pub fn iter_all(&self) -> impl Iterator<Item = &TypeErasedExtension> {
        self.extensions.iter()
    }
}

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_list();
        for ext in self.extensions.iter() {
            d.entry(&ext.value);
        }
        d.finish()
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

// TODO remove this once we start using input<>

#[derive(Debug, Clone, Extension)]
/// Wrapper type that can be inserted by leaf-like services
/// when returning an output, to have the input extensions be accessible and preserved.
pub struct InputExtensions(pub Extensions);

#[derive(Debug, Clone, Extension)]
pub struct Ingress<T>(pub T);

#[derive(Debug, Clone, Extension)]
pub struct Egress<T>(pub T);

#[derive(Debug, Clone, Extension)]
pub struct Connection<T>(pub T);

#[derive(Debug, Clone, Extension)]
pub struct Stream<T>(pub T);

#[derive(Debug, Clone, Extension)]
pub struct Input<T>(pub T);

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
        assert_eq!(ext.first_ref::<TraceNote>(), None);
    }

    #[test]
    fn first_arc_none_when_absent() {
        let ext = Extensions::new();
        assert!(ext.first_arc::<TraceNote>().is_none());
    }

    #[test]
    fn first_ref_returns_first_inserted() {
        let ext = Extensions::new();
        ext.insert(TraceNote("first".to_owned()));
        ext.insert(TraceNote("second".to_owned()));

        assert_eq!(
            ext.first_ref::<TraceNote>(),
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
            ext.first_arc::<TraceNote>()
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
        let existing = ext.get_ref_or_insert(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            RetryBudget(6)
        });
        assert_eq!(existing.0, 5u32);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let missing = ext.get_ref_or_insert(|| {
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
        let existing = ext.get_arc_or_insert(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            Arc::new(TraceNote(String::from("new")))
        });
        assert_eq!(existing.0.as_str(), "stored");
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let missing = ext.get_arc_or_insert(|| {
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

        let type_ids: Vec<TypeId> = ext.iter_all().map(TypeErasedExtension::type_id).collect();
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

        assert_eq!(ext.iter_ref::<TraceNote>().count(), 0);
        assert_eq!(ext.iter_arc::<TraceNote>().count(), 0);
    }

    #[test]
    fn iter_ref_returns_items_for_present_type_in_oldest_to_newest_order() {
        let ext = Extensions::new();
        ext.insert(TraceNote(String::from("first")));
        ext.insert(HealthSignal(9));
        ext.insert(TraceNote(String::from("second")));

        let output: Vec<&str> = ext
            .iter_ref::<TraceNote>()
            .map(|it| it.0.as_str())
            .collect();
        assert_eq!(output, vec!["first", "second"]);
    }

    #[test]
    fn iter_arc_returns_items_for_present_type_in_oldest_to_newest_order() {
        let ext = Extensions::new();
        ext.insert(TraceNote(String::from("first")));
        ext.insert(HealthSignal(9));
        ext.insert(TraceNote(String::from("second")));

        let output: Vec<String> = ext
            .iter_arc::<TraceNote>()
            .map(|arc| arc.0.clone())
            .collect();
        assert_eq!(output, vec!["first".to_owned(), "second".to_owned()]);
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
}
