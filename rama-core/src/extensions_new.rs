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
use std::sync::Arc;

use rama_utils::collections::AppendOnlyVec;

use crate::extensions::Extension;

#[derive(Debug, Clone, Default)]
/// A type map of protocol extensions.
///
/// [`Extension`]s are internally stored in a type erased [`Arc`]. Since values are
/// stored in an [`Arc`] there are extra methods exposed that build on top of this
/// and leverage characteristics of an [`Arc`] to expose things like cheap cloning of the Arc.
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

    /// Insert a type `T` into this [`Extensions`] store.
    ///
    /// This method returns a refence to the just insert value
    ///
    /// If the value you are inserting is an Arc<T>, prefer using
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
        let extension = TypeErasedExtension::new(val);
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
    // TODO switch this to &Self once everything is migrated
    pub fn extend(&self, other: Self) {
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

    // TODO this will be removed in a followup PR, together with removing blacket impl for Extension trait
    #[must_use]
    pub fn get<T: Extension>(&self) -> Option<&T> {
        self.get_ref()
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

    /// Iterate over all the inserted items of type `T`
    ///
    /// Items are ordered from oldest to newest and exposed as `&Arc<T>`. This means they
    /// can easily be cloned as [`Arc<T>`] or used as references with [`Arc::as_ref()`]
    pub fn iter<T: Extension>(&self) -> impl Iterator<Item = &Arc<T>> {
        let type_id = TypeId::of::<T>();

        #[allow(
            clippy::unwrap_used,
            reason = "`downcast_arc_ref` can only be none if TypeId doesn't match, but we already filter on that first"
        )]
        self.extensions
            .iter()
            .filter(move |item| item.type_id == type_id)
            .map(|ext| ext.downcast_arc_ref().unwrap())
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
    /// If the value you are inserting is an Arc<T>, prefer using
    /// [`Self::new_arc()`] to prevent the double indirection of storing
    /// an `Arc<Arc<T>>`. This happens because internally we use a type erased
    /// Arc to store the actual value.
    pub fn new<T: Extension>(value: T) -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            value: Arc::new(value),
        }
    }

    /// Create a new [`TypeErasedExtension`] for `Arc<T>``
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

    /// Get a reference `&Arc<T>` to the internally stored type `Arc<T>`
    ///
    /// This method will return `None`, if the internally stored
    /// type `S` doesn't match the requested type `T`
    pub fn downcast_arc_ref<T: Extension>(&self) -> Option<&Arc<T>> {
        let any = &self.value as &dyn Any;
        any.downcast_ref::<Arc<T>>()
    }

    /// Get a reference `&T` of the internally stored type `Arc<T>`
    ///
    /// This method will return `None`, if the internally stored
    /// type `S` doesn't match the requested type `T`
    pub fn downcast_ref<T: Extension>(&self) -> Option<&T> {
        let inner_any = self.value.as_ref() as &dyn Any;
        (inner_any).downcast_ref::<T>()
    }
}

#[derive(Debug, Clone)]
pub struct Ingress<T>(pub T);

#[derive(Debug, Clone)]
pub struct Egress<T>(pub T);

#[derive(Debug, Clone)]
pub struct Connection<T>(pub T);

#[derive(Debug, Clone)]
pub struct Stream<T>(T);

#[derive(Debug, Clone)]
pub struct Input<T>(T);

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
