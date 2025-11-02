#![allow(clippy::disallowed_types)]
//! Extensions passed to and between services
//!
//! # State
//!
//! [`rama`] supports two kinds of states:
//!
//! 1. static state: this state can be a part of the service struct or captured by a closure
//! 2. dynamic state: these can be injected as [`Extensions`]s in Requests/Responses/Connections if it [`ExtensionsMut`]
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
//! use rama_core::extensions::Extensions;
//!
//! let mut ext = Extensions::default();
//! ext.insert(5i32);
//! assert_eq!(ext.get::<i32>(), Some(&5i32));
//! ```

use rama_utils::macros::generate_set_and_with;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::fmt;
use std::hash::{BuildHasherDefault, Hasher};
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;

#[cfg(debug_assertions)]
use std::any::type_name;

type AnyMap = HashMap<TypeId, Box<dyn AnyClone + Send + Sync>, BuildHasherDefault<IdHasher>>;
#[cfg(debug_assertions)]
type TypeIdMap = HashMap<TypeId, String, BuildHasherDefault<IdHasher>>;

// With TypeIds as keys, there's no need to hash them. They are already hashes
// themselves, coming from the compiler. The IdHasher just holds the u64 of
// the TypeId, and then returns it, instead of doing any bit fiddling.
#[derive(Default)]
struct IdHasher(u64);

impl Hasher for IdHasher {
    fn write(&mut self, _: &[u8]) {
        unreachable!("TypeId calls write_u64");
    }

    #[inline(always)]
    fn write_u64(&mut self, id: u64) {
        self.0 = id;
    }

    #[inline(always)]
    fn finish(&self) -> u64 {
        self.0
    }
}

/// A type map of protocol extensions.
///
/// `Extensions` can be used by `Request` and `Response` to store
/// extra data derived from the underlying protocol.
#[derive(Clone, Default)]
pub struct Extensions {
    // If extensions are never used, no need to carry around an empty HashMap.
    // That's 3 words. Instead, this is only 1 word.
    map: Option<Box<AnyMap>>,
    #[cfg(debug_assertions)]
    type_map: Option<Box<TypeIdMap>>,
    parent_extensions: Option<Arc<Extensions>>,
}

impl Extensions {
    /// Create an empty `Extensions`.
    #[inline(always)]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            map: None,
            #[cfg(debug_assertions)]
            type_map: None,
            parent_extensions: None,
        }
    }

    #[must_use]
    /// Convert [`Extensions`] into a frozen/readonly variant
    pub fn into_frozen_extensions(self) -> Arc<Self> {
        Arc::new(self)
    }

    generate_set_and_with! {
        /// Set parent extensions
        pub fn parent_extensions(mut self, frozen_extensions: Option<Arc<Extensions>>) -> Self {
            self.parent_extensions = frozen_extensions;
            self
        }
    }

    /// Insert a type into this `Extensions`.
    ///
    /// If a extension of this type already existed, it will
    /// be returned.
    pub fn insert<T: Clone + Send + Sync + 'static>(&mut self, val: T) -> Option<T> {
        #[cfg(debug_assertions)]
        self.type_map
            .get_or_insert_with(Box::default)
            .insert(TypeId::of::<T>(), type_name::<T>().to_owned());

        self.map
            .get_or_insert_with(Box::default)
            .insert(TypeId::of::<T>(), Box::new(val))
            .and_then(|boxed| boxed.into_any().downcast().ok().map(|boxed| *boxed))
    }

    /// Insert a type into this `Extensions` and get mutable reference
    pub fn insert_mut<T: Clone + Send + Sync + 'static>(&mut self, val: T) -> &mut T {
        self.insert(val);
        self.get_mut().unwrap()
    }

    /// Insert a type only into this `Extensions`, if the value is `Some(T)`.
    ///
    /// See [`Self::insert`] for more information.
    pub fn maybe_insert<T: Clone + Send + Sync + 'static>(
        &mut self,
        mut val: Option<T>,
    ) -> Option<T> {
        val.take().and_then(|val| self.insert(val))
    }

    /// Extend these extensions with another Extensions.
    pub fn extend(&mut self, other: Self) {
        #[cfg(debug_assertions)]
        if let Some(other_map) = other.type_map {
            let map = self.type_map.get_or_insert_with(Box::default);
            #[allow(clippy::useless_conversion)]
            map.extend(other_map.into_iter());
        }

        if let Some(other_map) = other.map {
            let map = self.map.get_or_insert_with(Box::default);
            #[allow(clippy::useless_conversion)]
            map.extend(other_map.into_iter());
        }
    }

    /// Clear the `Extensions` of all inserted extensions.
    pub fn clear(&mut self) {
        #[cfg(debug_assertions)]
        if let Some(map) = self.type_map.as_mut() {
            map.clear();
        }

        if let Some(map) = self.map.as_mut() {
            map.clear();
        }
    }

    /// Returns true if the `Extensions` or parents contains the given type.
    #[must_use]
    pub fn contains<T: Send + Sync + 'static>(&self) -> bool {
        self.map
            .as_ref()
            .map(|map| map.contains_key(&TypeId::of::<T>()))
            .unwrap_or_else(|| {
                self.parent_extensions
                    .as_ref()
                    .map(|parent| parent.contains::<T>())
                    .unwrap_or_default()
            })
    }

    /// Get a shared reference to a type previously inserted on this `Extensions` or any of the parents
    #[must_use]
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.map
            .as_ref()
            .and_then(|map| map.get(&TypeId::of::<T>()))
            .and_then(|boxed| (**boxed).as_any().downcast_ref())
            .or_else(|| {
                self.parent_extensions
                    .as_ref()
                    .and_then(|parent| parent.get())
            })
    }

    /// Get an exclusive reference to a type previously inserted on this `Extensions`.
    pub fn get_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        self.map
            .as_mut()
            .and_then(|map| map.get_mut(&TypeId::of::<T>()))
            .and_then(|boxed| (**boxed).as_any_mut().downcast_mut())
    }
}

impl fmt::Debug for Extensions {
    #[cfg(debug_assertions)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let items = self.map.as_ref().map(|map| {
            map.keys()
                .map(|key| {
                    self.type_map
                        .as_ref()
                        .and_then(|type_map| type_map.get(key))
                        .unwrap()
                })
                .collect::<Vec<&String>>()
        });

        f.debug_struct("Extensions")
            .field("items", &items)
            .field("parent_extensions", &self.parent_extensions)
            .finish()
    }

    #[cfg(not(debug_assertions))]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extensions").finish()
    }
}

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

pub trait ExtensionsMut: ExtensionsRef {
    /// Get mutable reference to the underlying [`Extensions`] store
    fn extensions_mut(&mut self) -> &mut Extensions;

    // TODO once we have a proper solution to travel across boundaries this will be removed
    // This will happen in the very near future so this api should not be used
    fn take_extensions(&mut self) -> Extensions {
        std::mem::take(self.extensions_mut())
    }
}

impl ExtensionsMut for Extensions {
    fn extensions_mut(&mut self) -> &mut Extensions {
        self
    }
}

impl<T> ExtensionsMut for &mut T
where
    T: ExtensionsMut,
{
    #[inline(always)]
    fn extensions_mut(&mut self) -> &mut Extensions {
        (**self).extensions_mut()
    }
}

impl<T> ExtensionsMut for Box<T>
where
    T: ExtensionsMut,
{
    fn extensions_mut(&mut self) -> &mut Extensions {
        (**self).extensions_mut()
    }
}

impl<T> ExtensionsMut for Pin<Box<T>>
where
    T: ExtensionsMut,
{
    fn extensions_mut(&mut self) -> &mut Extensions {
        let pinned_t = self.as_mut();
        // SAFETY: `extensions_mut` only has a mutable reference to a specific
        // field and does not move T itself, so this is safe
        unsafe {
            let t_mut = pinned_t.get_unchecked_mut();
            t_mut.extensions_mut()
        }
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

pub trait ChainableExtensions {
    fn contains<T: Send + Sync + 'static>(&self) -> bool;
    fn get<T: Send + Sync + 'static>(&self) -> Option<&T>;
}

impl<S, T> ChainableExtensions for (S, T)
where
    S: ExtensionsRef,
    T: ExtensionsRef,
{
    fn contains<I: Send + Sync + 'static>(&self) -> bool {
        self.0.extensions().contains::<I>() || self.1.extensions().contains::<I>()
    }

    fn get<I: Send + Sync + 'static>(&self) -> Option<&I> {
        self.0
            .extensions()
            .get::<I>()
            .or_else(|| self.1.extensions().get::<I>())
    }
}

impl<S, T, U> ChainableExtensions for (S, T, U)
where
    S: ExtensionsRef,
    T: ExtensionsRef,
    U: ExtensionsRef,
{
    fn contains<I: Send + Sync + 'static>(&self) -> bool {
        (&self.0, &self.1).contains::<I>() || self.2.extensions().contains::<I>()
    }

    fn get<I: Send + Sync + 'static>(&self) -> Option<&I> {
        self.0
            .extensions()
            .get::<I>()
            .or_else(|| self.1.extensions().get::<I>())
            .or_else(|| self.2.extensions().get::<I>())
    }
}

trait AnyClone: Any {
    fn clone_box(&self) -> Box<dyn AnyClone + Send + Sync>;
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

impl<T: Clone + Send + Sync + 'static> AnyClone for T {
    fn clone_box(&self) -> Box<dyn AnyClone + Send + Sync> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl Clone for Box<dyn AnyClone + Send + Sync> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

#[derive(Debug, Clone)]
/// Wrapper type that can be injected into the dynamic extensions of a "Response",
/// in order to preserve the [`Context`]'s extensions of the _Request_
/// which was used to produce the _Response_.
pub struct RequestContextExt(Extensions);

impl From<Extensions> for RequestContextExt {
    fn from(value: Extensions) -> Self {
        Self(value)
    }
}

impl From<RequestContextExt> for Extensions {
    fn from(value: RequestContextExt) -> Self {
        value.0
    }
}

impl AsRef<Extensions> for RequestContextExt {
    fn as_ref(&self) -> &Extensions {
        &self.0
    }
}

impl AsMut<Extensions> for RequestContextExt {
    fn as_mut(&mut self) -> &mut Extensions {
        &mut self.0
    }
}

impl Deref for RequestContextExt {
    type Target = Extensions;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl DerefMut for RequestContextExt {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[test]
fn test_extensions() {
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    struct MyType(i32);

    let mut extensions = Extensions::new();

    extensions.insert(5i32);
    extensions.insert(MyType(10));

    assert_eq!(extensions.get(), Some(&5i32));

    let mut ext2 = extensions.clone();

    ext2.insert(true);

    assert_eq!(ext2.get(), Some(&5i32));
    assert_eq!(ext2.get(), Some(&MyType(10)));
    assert_eq!(ext2.get(), Some(&true));

    // test extend
    let mut extensions = Extensions::new();
    extensions.insert(5i32);
    extensions.insert(MyType(10));

    let mut extensions2 = Extensions::new();
    extensions2.extend(extensions);
    assert_eq!(extensions2.get(), Some(&5i32));
    assert_eq!(extensions2.get(), Some(&MyType(10)));

    // test clear
    extensions2.clear();
    assert_eq!(extensions2.get::<i32>(), None);
    assert_eq!(extensions2.get::<MyType>(), None);
}

#[test]
fn test_extensions_chaining() {
    let mut conn_extensions = Extensions::new();
    conn_extensions.insert(String::new());

    let conn_extensions = conn_extensions.into_frozen_extensions();

    let req_extensions = Extensions::new().with_parent_extensions(conn_extensions);
    assert!(req_extensions.get::<String>().is_some());
}
