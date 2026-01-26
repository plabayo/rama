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

use std::any::Any;
use std::pin::Pin;
use std::sync::Arc;

/// A type map of protocol extensions.
///
/// `Extensions` can be used by `Request` and `Response` to store
/// extra data derived from the underlying protocol.
#[derive(Clone, Default, Debug)]
pub struct Extensions {
    // TODO potentially optimize this storage https://github.com/plabayo/rama/issues/746
    extensions: Vec<StoredExtension>,
}

#[derive(Clone, Debug)]
struct StoredExtension(std::any::TypeId, Box<dyn ExtensionType>);

impl Extensions {
    /// Create an empty [`Extensions`] store.
    #[inline(always)]
    #[must_use]
    pub fn new() -> Self {
        Self { extensions: vec![] }
    }

    /// Insert a type into this [`Extensions]` store.
    pub fn insert<T: Extension + Clone>(&mut self, val: T) -> &T {
        let extension = StoredExtension(std::any::TypeId::of::<T>(), Box::new(val));
        self.extensions.push(extension);

        let ext = &self.extensions[self.extensions.len() - 1];
        #[allow(clippy::expect_used, reason = "see expect msg")]
        (*ext.1)
            .as_any()
            .downcast_ref()
            .expect("we just inserted this")
    }

    /// Extend this [`Extensions`] store with the [`Extensions`] from the provided store
    pub fn extend(&mut self, extensions: Self) {
        self.extensions.extend(extensions.extensions);
    }

    /// Returns true if the [`Extensions`] store contains the given type.
    #[must_use]
    pub fn contains<T: Extension + Clone>(&self) -> bool {
        let type_id = std::any::TypeId::of::<T>();
        self.extensions.iter().rev().any(|item| item.0 == type_id)
    }

    /// Get a shared reference to the most recently insert item of type T
    ///
    /// Note: [`Self::get`] will return the last added item T, in most cases this is exactly what you want, but
    /// if you need the oldest item T use [`Self::first`]
    #[must_use]
    pub fn get<T: Extension + Clone>(&self) -> Option<&T> {
        let type_id = std::any::TypeId::of::<T>();
        self.extensions
            .iter()
            .rev()
            .find(|item| item.0 == type_id)
            .and_then(|ext| (*ext.1).as_any().downcast_ref())
    }

    /// Get a shared reference to the most recently insert item of type T, or insert in case no item was found
    ///
    /// Note: [`Self::get`] will return the last added item T, in most cases this is exactly what you want, but
    /// if you need the oldest item T use [`Self::first`]
    pub fn get_or_insert<T, F>(&mut self, create_fn: F) -> &T
    where
        T: Extension + Clone,
        F: FnOnce() -> T,
    {
        let type_id = std::any::TypeId::of::<T>();

        let stored = self
            .extensions
            .iter()
            .rev()
            .find(|item| item.0 == type_id)
            .and_then(|ext| (*ext.1).as_any().downcast_ref());

        if let Some(found) = stored {
            // SAFETY: We are returning a reference tied to 'a.
            // We have a valid reference to 'found' from 'self', and we are
            // returning immediately, so no mutable borrow of 'self' occurs
            // in this code path. This is needed until polonius (next gen typechecker) is live
            return unsafe { &*(found as *const T) };
        }

        self.insert(create_fn())
    }

    /// Get a shared reference to the oldest inserted item of type T
    ///
    /// Note: [`Self::first`] will return the first added item T, in most cases this is not what you want,
    /// instead use [`Self::get`] to get the most recently inserted item T
    #[must_use]
    pub fn first<T: Extension + Clone>(&self) -> Option<&T> {
        let type_id = std::any::TypeId::of::<T>();
        self.extensions
            .iter()
            .find(|item| item.0 == type_id)
            .and_then(|ext| (*ext.1).as_any().downcast_ref())
    }

    /// Iterate over all the inserted items of type T
    ///
    /// Note: items are ordered from oldest to newest
    pub fn iter<T: Extension + Clone>(&self) -> impl Iterator<Item = &T> {
        let type_id = std::any::TypeId::of::<T>();

        // Note: unsafe downcast_ref_unchecked is not stabilized yet, so we have to use the safe version with unwrap
        #[allow(
            clippy::unwrap_used,
            reason = "`downcast_ref` can only be none if TypeId doesn't match, but we already filter on that first"
        )]
        self.extensions
            .iter()
            .filter(move |item| item.0 == type_id)
            .map(|ext| (*ext.1).as_any().downcast_ref().unwrap())
    }
}

/// [`Extension`] is type which can be stored inside an [`Extensions`] store
///
/// Currently this trait has no internal logic, but over time this might change
/// and this might be extended to support more advanced use cases. For now this
/// is still usefull because it shows all the [`Extension`]s we have grouped in
/// the exported rust-docs.
pub trait Extension: Any + Send + Sync + std::fmt::Debug + 'static {}

// TODO remove this blacket impl and require everyone to implement this (with derive impl)
impl<T> Extension for T where T: Any + Send + Sync + std::fmt::Debug + 'static {}

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
    fn contains<T: Extension + Clone>(&self) -> bool;
    fn get<T: Extension + Clone>(&self) -> Option<&T>;
}

impl<S, T> ChainableExtensions for (S, T)
where
    S: ExtensionsRef,
    T: ExtensionsRef,
{
    fn contains<I: Extension + Clone>(&self) -> bool {
        self.0.extensions().contains::<I>() || self.1.extensions().contains::<I>()
    }

    fn get<I: Extension + Clone>(&self) -> Option<&I> {
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
    fn contains<I: Extension + Clone>(&self) -> bool {
        (&self.0, &self.1).contains::<I>() || self.2.extensions().contains::<I>()
    }

    fn get<I: Extension + Clone>(&self) -> Option<&I> {
        self.0
            .extensions()
            .get::<I>()
            .or_else(|| self.1.extensions().get::<I>())
            .or_else(|| self.2.extensions().get::<I>())
    }
}

trait ExtensionType: Extension {
    fn clone_box(&self) -> Box<dyn ExtensionType>;
    fn as_any(&self) -> &dyn Any;
}

impl<T: Extension + Clone> ExtensionType for T {
    fn clone_box(&self) -> Box<dyn ExtensionType> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl Clone for Box<dyn ExtensionType> {
    fn clone(&self) -> Self {
        (**self).clone_box()
    }
}

#[derive(Debug, Clone)]
/// Wrapper type that can be inserted by leaf-like services
/// when returning an output, to have the input extensions be accessible and preserved.
pub struct InputExtensions(pub Extensions);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_should_return_last_added_extension() {
        let mut ext = Extensions::new();
        ext.insert("first".to_owned());
        ext.insert("second".to_owned());

        assert_eq!(*ext.get::<String>().unwrap(), "second".to_owned());

        let mut split = ext.clone();
        split.insert("split".to_owned());

        assert_eq!(*ext.get::<String>().unwrap(), "second".to_owned());
        assert_eq!(*split.get::<String>().unwrap(), "split".to_owned());
    }

    #[test]
    fn first_should_return_first_added_extension() {
        let mut ext = Extensions::new();
        ext.insert("first".to_owned());
        ext.insert("second".to_owned());

        assert_eq!(*ext.first::<String>().unwrap(), "first".to_owned());
    }

    #[test]
    fn iter_should_work() {
        let mut ext = Extensions::new();
        ext.insert("first".to_owned());
        ext.insert(4);
        ext.insert(true);
        ext.insert("second".to_owned());

        let output: Vec<String> = ext.iter::<String>().cloned().collect();
        assert_eq!(output[0], "first".to_owned());
        assert_eq!(output[1], "second".to_owned());

        let first_bool = ext.iter::<bool>().next().unwrap();
        assert!(*first_bool);
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
    }
}
