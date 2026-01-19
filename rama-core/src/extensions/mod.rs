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
//! let ext = Extensions::default();
//! ext.insert(5i32);
//! assert_eq!(ext.get::<i32>(), Some(&5i32));
//! ```

use std::any::{Any, TypeId};
use std::pin::Pin;
use std::sync::Arc;

use rama_error::OpaqueError;
pub use rama_utils::collections::AppendOnlyVec;

use crate::stream;

#[derive(Debug, Clone, Default)]
/// A type map of protocol extensions.
///
/// `Extensions` can be used by `Request` and `Response` to store
/// extra data derived from the underlying protocol.
pub struct Extensions {
    extensions: Arc<AppendOnlyVec<TypeErasedExtension, 8, 3>>,
}

impl Extensions {
    /// Create an empty [`Extensions`] store.
    #[inline(always)]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a type into this [`Extensions]` store.
    pub fn insert<T: Extension>(&self, val: T) -> &T {
        let extension = TypeErasedExtension::new(val);
        let idx = self.extensions.push(extension);

        // SAFETY: this is safe since we just stored item T, so we know this is the
        // correct type
        self.extensions[idx].downcast_ref::<T>().unwrap()
    }

    /// Insert a type into this [`Extensions]` store.
    pub fn insert_arc<T: Extension>(&self, val: Arc<T>) -> Arc<T> {
        let extension = TypeErasedExtension::new(val);
        let idx = self.extensions.push(extension);

       self.extensions[idx].cloned_downcast::<T>().unwrap()
    }

    /// Extend this [`Extensions`] store with the [`Extensions`] from the provided store
    pub fn extend(&self, extensions: Self) {
        for ext in extensions.extensions.iter() {
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
    pub fn get_ref<T: Extension>(&self) -> Option<&T> {
        let type_id = TypeId::of::<T>();
        self.extensions
            .iter()
            .rev()
            .find(|item| item.type_id == type_id)
            .and_then(|ext| 
                ext.downcast_ref()
            )
    }

    #[must_use]
    pub fn get_arc<T: Extension>(&self) -> Option<Arc<T>> {
        let type_id = TypeId::of::<T>();
        self.extensions
            .iter()
            .rev()
            .find(|item| item.type_id == type_id)
            .and_then(|ext| 
                // SAFETY we just filtered on type_id so we know this is the correct type
                ext.cloned_downcast())
    }

    /// Get a shared reference to the most recently insert item of type T, or insert in case no item was found
    ///
    /// Note: [`Self::get`] will return the last added item T, in most cases this is exactly what you want, but
    /// if you need the oldest item T use [`Self::first`]
    pub fn get_ref_or_insert<T, F>(&self, create_fn: F) -> &T
    where
        T: Clone + Send + Sync + std::fmt::Debug + 'static,
        F: FnOnce() -> T,
    {
        self.get_ref().unwrap_or_else(|| self.insert(create_fn()))
    }

    pub fn get_arc_or_insert<T, F>(&self, create_fn: F) -> Arc<T>
    where
        T: Clone + Send + Sync + std::fmt::Debug + 'static,
        F: FnOnce() -> Arc<T>,
    {
        self.get_arc()
            .unwrap_or_else(|| self.insert_arc(create_fn()))
    }

    /// Get a shared reference to the oldest inserted item of type T
    ///
    /// Note: [`Self::first`] will return the first added item T, in most cases this is not what you want,
    /// instead use [`Self::get`] to get the most recently inserted item T
    #[must_use]
    pub fn first_ref<T: Extension>(&self) -> Option<&T> {
        let type_id = TypeId::of::<T>();
        self.extensions
            .iter()
            .find(|item| item.type_id == type_id)
            .and_then(|ext| 
                // SAFETY we just filtered on type_id so we know this is the correct type
                ext.downcast_ref())

    }

    #[must_use]
    pub fn first_arc<T: Extension>(&self) -> Option<Arc<T>> {
        let type_id = TypeId::of::<T>();
        self.extensions
            .iter()
            .find(|item| item.type_id == type_id)
            .and_then(|ext|ext.cloned_downcast())
    }

    /// Iterate over all the inserted items of type T
    ///
    /// Note: items are ordered from oldest to newest
    pub fn iter<T: Extension>(&self) -> impl Iterator<Item = &Arc<T>> {
        let type_id = TypeId::of::<T>();

        // Note: unsafe downcast_ref_unchecked is not stabilized yet, so we have to use the safe version with unwrap
        #[allow(
            clippy::unwrap_used,
            reason = "`downcast_ref` can only be none if TypeId doesn't match, but we already filter on that first"
        )]
        self.extensions
            .iter()
            .filter(move |item| item.type_id == type_id)
            .map(|ext|ext.downcast_arc_ref().unwrap())

    }


    /// Stream iterator over all the inserted items of type T
    ///
    /// Note: items are ordered from oldest to newest
    pub fn stream_iter<T: Extension>(&self) -> stream::Iter<impl Iterator<Item = &Arc<T>>> {
        stream::iter(self.iter())
    }

    pub fn iter_all(&self) -> impl Iterator<Item = &TypeErasedExtension> {
        self.extensions.iter()
    }
}

#[derive(Clone, Debug)]
/// A [`TypeErasedExtension`] is a type erased item which can be stored in an [`ExtensionStore`]
pub struct TypeErasedExtension {
    type_id: TypeId,
    value: Arc<dyn Extension>,
}

impl TypeErasedExtension {
    /// Create a new [`TypeErasedExtension`]
    pub fn new<T: Extension>(value: T) -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            value: Arc::new(value),
        }
    }

    /// Create a new [`TypeErasedExtension`]
    pub fn new_arc<T: Extension>(value: Arc<T>) -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            value,
        }
    }

    pub fn type_id(&self) -> TypeId {
        self.type_id
    }


    pub fn cloned_downcast<T: Extension>(&self) -> Option<Arc<T>> {
        let any = self.value.clone() as Arc<dyn Any + Send + Sync>;
        any.downcast::<T>().ok()
    }


    pub fn downcast_arc_ref<T: Extension>(&self) -> Option<& Arc<T>> {

        let any = &self.value as &dyn Any;
        any.downcast_ref::<Arc<T>>()
    }



    pub fn downcast_ref<T: Extension>(&self) -> Option<& T> {
        let inner_any = self.value.as_ref() as &dyn Any;
        (inner_any).downcast_ref::<T>()
    }


}



pub trait Extension: Any + Send + Sync + std::fmt::Debug + 'static {}
// TODO remove this blacket impl and require everyone to implement this
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
    fn contains<T: Extension>(&self) -> bool;
    fn get<T: Extension>(&self) -> Option<&T>;
}

impl<S, T> ChainableExtensions for (S, T)
where
    S: ExtensionsRef,
    T: ExtensionsRef,
{
    fn contains<I: Extension>(&self) -> bool {
        self.0.extensions().contains::<I>() || self.1.extensions().contains::<I>()
    }

    fn get<I: Extension>(&self) -> Option<&I> {
        self.0
            .extensions()
            .get_ref::<I>()
            .or_else(|| self.1.extensions().get_ref::<I>())
    }
}

// impl<S, T, U> ChainableExtensions for (S, T, U)
// where
//     S: ExtensionsRef,
//     T: ExtensionsRef,
//     U: ExtensionsRef,
// {
//     fn contains<I: Send + Sync + 'static>(&self) -> bool {
//         (&self.0, &self.1).contains::<I>() || self.2.extensions().contains::<I>()
//     }

//     fn get<I: Send + Sync + 'static>(&self) -> Option<&I> {
//         self.0
//             .extensions()
//             .get::<I>()
//             .or_else(|| self.1.extensions().get::<I>())
//             .or_else(|| self.2.extensions().get::<I>())
//     }
// }

#[derive(Debug, Clone)]
/// Wrapper type that can be inserted by leaf-like services
/// when returning an output, to have the input extensions be accessible and preserved.
pub struct InputExtensions(pub Extensions);

#[derive(Debug, Clone)]
pub struct OutputExtensions(pub Extensions);

#[derive(Debug, Clone)]
pub struct EgressConnectionExtensions(pub Extensions);

#[derive(Debug, Clone)]
pub struct IngressConnectionExtensions(pub Extensions);

#[derive(Debug, Clone)]
pub struct EgressStreamExtensions(pub Extensions);

#[derive(Debug, Clone)]
pub struct IngressStreamExtensions(pub Extensions);

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn get_should_return_last_added_extension() {
//         let ext = Extensions::default();
//         ext.insert("first".to_owned());
//         ext.insert("second".to_owned());

//         assert_eq!(*ext.get::<String>().unwrap(), "second".to_owned());

//         let mut split = ext.clone();
//         split.insert("split".to_owned());

//         assert_eq!(*ext.get::<String>().unwrap(), "second".to_owned());
//         assert_eq!(*split.get::<String>().unwrap(), "split".to_owned());
//     }

//     #[test]
//     fn first_should_return_first_added_extension() {
//         let ext = Extensions::default();
//         ext.insert("first".to_owned());
//         ext.insert("second".to_owned());

//         assert_eq!(*ext.first::<String>().unwrap(), "first".to_owned());
//     }

//     #[test]
//     fn iter_should_work() {
//         let ext = Extensions::default();
//         ext.insert("first".to_owned());
//         ext.insert(4);
//         ext.insert(true);
//         ext.insert("second".to_owned());

//         let output: Vec<String> = ext.iter::<String>().cloned().collect();
//         assert_eq!(output[0], "first".to_owned());
//         assert_eq!(output[1], "second".to_owned());

//         let first_bool = ext.iter::<bool>().next().unwrap();
//         assert!(*first_bool);
//     }

//     #[test]
//     fn test_extensions() {
//         #[derive(Clone, Debug, PartialEq, Eq, Hash)]
//         struct MyType(i32);

//         let extensions = Extensions::default();

//         extensions.insert(5i32);
//         extensions.insert(MyType(10));

//         assert_eq!(extensions.get(), Some(&5i32));

//         let ext2 = extensions.clone();

//         ext2.insert(true);

//         assert_eq!(ext2.get(), Some(&5i32));
//         assert_eq!(ext2.get(), Some(&MyType(10)));
//         assert_eq!(ext2.get(), Some(&true));

//         // test extend
//         let extensions = Extensions::default();
//         extensions.insert(5i32);
//         extensions.insert(MyType(10));

//         let extensions2 = Extensions::default();
//         extensions2.extend(extensions);
//         assert_eq!(extensions2.get(), Some(&5i32));
//         assert_eq!(extensions2.get(), Some(&MyType(10)));
//     }
// }
