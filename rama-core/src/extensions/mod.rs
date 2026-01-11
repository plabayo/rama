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

pub use rama_utils::collections::AppendOnlyVec;
use tokio::time::Instant;

#[derive(Debug, Clone)]
/// Combined view of all extensions that apply at a specific place
pub struct Extensions {
    stores: Vec<ExtensionStore>,
}

impl Default for Extensions {
    fn default() -> Self {
        Self::new("unknown_name")
    }
}

impl Extensions {
    pub fn new(name: &'static str) -> Self {
        let store = ExtensionStore::new(name);
        Self {
            stores: vec![store],
        }
    }

    #[must_use]
    pub fn new_from_current(&self, name: &'static str) -> Self {
        let store = ExtensionStore::new(name);
        let mut stores = self.stores.clone();
        stores.insert(0, store);
        Self { stores }
    }

    pub fn add_new_store(&mut self, store: ExtensionStore) {
        self.stores.push(store);
    }

    // TODO we could make this use &mut self, so we can still signal if this should be
    // readonly or not. But do we ever have a need of making extensions readonly? Seems
    // that we always have an owned version of it either way...
    pub fn insert<T: Extension>(&self, val: T) {
        self.main_store().insert(val);
    }

    pub fn main_store(&self) -> &ExtensionStore {
        &self.stores[0]
    }

    pub fn get<T: Extension>(&self) -> Option<&T> {
        self.get_inner::<T>()
            .and_then(|stored| stored.extension.downcast_ref::<T>())
    }

    pub fn get_arc<T: Extension>(&self) -> Option<Arc<T>> {
        self.get_inner::<T>()
            .and_then(|stored| stored.extension.cloned_downcast::<T>())
    }

    fn get_inner<T: Extension>(&self) -> Option<&StoredExtension> {
        let type_id = TypeId::of::<T>();

        let mut latest: Option<&StoredExtension> = None;

        // Here we iterate all stores one by one, we probably want to interleave this and do this smarter or concurrently
        for store in &self.stores {
            for stored in store.storage.iter().rev() {
                // No need to keep searching if we already have a match that is newer then we are now
                if let Some(latest) = latest
                    && stored.timestamp < latest.timestamp
                {
                    break;
                }
                if stored.extension.type_id == type_id {
                    // We already checked that this is the most recent one in our first if clause,
                    // and we also checked if the type_it matched, so when we get here we have a match
                    latest = Some(stored);
                    break;
                }
            }
        }

        latest
    }

    pub fn contains<T: Extension>(&self) -> bool {
        let type_id = TypeId::of::<T>();

        for store in &self.stores {
            if store
                .storage
                .iter()
                .rev()
                .any(|stored| stored.extension.type_id == type_id)
            {
                return true;
            }
        }

        false
    }

    pub fn iter<'a, T: Extension>(&'a self) -> impl Iterator<Item = &'a T> + 'a {
        #[allow(
            clippy::unwrap_used,
            reason = "type_id_filter guarantees that this case will succeed"
        )]
        self.iter_inner(Self::type_id_filter::<T>)
            .map(|item| item.1.extension.downcast_ref::<T>().unwrap())
    }

    pub fn iter_arc<'a, T: Extension>(&'a self) -> impl Iterator<Item = Arc<T>> + 'a {
        #[allow(
            clippy::unwrap_used,
            reason = "type_id_filter guarantees that this case will succeed"
        )]
        self.iter_inner(Self::type_id_filter::<T>)
            .map(|item| item.1.extension.cloned_downcast::<T>().unwrap())
    }

    fn type_id_filter<T: Extension>(stored: &StoredExtension) -> bool {
        let type_id = TypeId::of::<T>();
        stored.extension.type_id != type_id
    }

    pub fn iter_all_stored<'a>(
        &'a self,
    ) -> impl Iterator<Item = (&'static str, &'a StoredExtension)> + 'a {
        self.iter_inner(|_| false)
    }

    // TODO do we want to make a struct and potentially impl double sided iterator for this
    fn iter_inner<'a, F>(
        &'a self,
        filter: F,
    ) -> impl Iterator<Item = (&'static str, &'a StoredExtension)> + 'a
    where
        F: Fn(&StoredExtension) -> bool + 'static,
    {
        let mut cursors = vec![0; self.stores.len()];

        std::iter::from_fn(move || {
            let mut best_store = None;
            let mut earliest_time = None;

            for (i, store) in self.stores.iter().enumerate() {
                let storage = &store.storage;
                while cursors[i] < storage.len() && filter(&storage[cursors[i]]) {
                    cursors[i] += 1;
                }

                if cursors[i] == storage.len() {
                    continue;
                }

                let item = &storage[cursors[i]];

                if earliest_time.is_none_or(|t| item.timestamp < t) {
                    earliest_time = Some(item.timestamp);
                    best_store = Some(i);
                }
            }

            if let Some(i) = best_store {
                let stored = &self.stores[i].storage[cursors[i]];
                cursors[i] += 1;

                return Some((self.stores[i].name, stored));
            }

            None
        })
    }

    // TODO instead of extensions do we just add the provided extensions store to the list over stores?

    /// Extend this [`Extensions`] store with the [`Extension`]s from the provided store
    ///
    /// Warning: this will override the timestamp of the extensions to Instant::now,
    /// this is need to make sure our datastructure is always ordered by timestamp
    pub fn extend(&mut self, extensions: Self) {
        self.main_store().extend(extensions.main_store());
        // TODO we can just use a ref here, but do we want to?
        drop(extensions);
    }
}

#[derive(Debug, Clone)]
/// Single extensions store, this is readonly and appendonly, we use &self for everything
pub struct ExtensionStore {
    // again no string later, but for proto type this works
    name: &'static str,
    storage: Arc<AppendOnlyVec<StoredExtension, 30, 3>>,
}

impl ExtensionStore {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            storage: Default::default(),
        }
    }

    /// Insert a new value in this [`ExtensionStore`]
    pub fn insert<T: Extension>(&self, value: T) {
        let extension = StoredExtension {
            extension: TypeErasedExtension::new(value),
            timestamp: Instant::now(),
        };
        self.storage.push(extension);
    }

    /// Extend this [`Extensions`] store with the [`Extension`]s from the provided store
    ///
    /// Warning: this will override the timestamp of the extensions to Instant::now,
    /// this is need to make sure our datastructure is always ordered by timestamp
    pub fn extend(&self, extensions: &Self) {
        let now = Instant::now();
        for stored in extensions.storage.iter() {
            self.storage.push(StoredExtension {
                extension: stored.extension.clone(),
                timestamp: now,
            });
        }
    }
}

#[derive(Clone, Debug)]
pub struct StoredExtension {
    extension: TypeErasedExtension,
    timestamp: Instant,
}

#[derive(Clone, Debug)]
/// A [`TypeErasedExtension`] is a type erased item which can be stored in an [`ExtensionStore`]
pub struct TypeErasedExtension {
    type_id: TypeId,
    value: Arc<dyn Extension>,
}

impl TypeErasedExtension {
    /// Create a new [`TypeErasedExtension`]
    fn new<T: Extension>(value: T) -> Self {
        Self {
            type_id: TypeId::of::<T>(),
            value: Arc::new(value),
        }
    }

    fn cloned_downcast<T: Extension>(&self) -> Option<Arc<T>> {
        let any = self.value.clone() as Arc<dyn Any + Send + Sync>;
        any.clone().downcast::<T>().ok()
    }

    fn downcast_ref<T: Extension>(&self) -> Option<&T> {
        let inner_any = self.value.as_ref() as &dyn Any;
        (inner_any).downcast_ref::<T>()
    }
}

pub trait Extension: Any + Send + Sync + std::fmt::Debug + 'static {}
// TODO remove this blacket impl and require everyone to implement this
impl<T> Extension for T where T: Any + Send + Sync + std::fmt::Debug + 'static {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug)]
    struct NoRetry;

    #[derive(Clone, Debug)]
    struct TargetHttpVersion;

    #[derive(Clone, Debug)]
    struct ConnectionInfo;

    #[derive(Clone, Debug)]
    struct RequestInfoInner;

    #[derive(Clone, Debug)]
    struct BrokenConnection;

    #[derive(Clone, Debug)]
    struct IsHealth(bool);

    #[test]
    fn setup() {
        let mut request = Extensions::new("request");

        request.insert(NoRetry);
        request.insert(TargetHttpVersion);

        // println!("request extensions {request:?}");

        // 1. now we go to connector setup
        // 2. we create the extensions for our connector
        // 3. we add request extensions to this, and vice versa
        let connection = Extensions::new("connection");

        // We add connector extensions also to our request
        request.add_new_store(connection.main_store().clone());

        // In connector setup now we only edit connection extension
        connection.insert(ConnectionInfo);
        connection.insert(IsHealth(true));

        // We also have access to request to read thing, but all connection specific things
        // should add this point be copied over the connection which should survive a single request
        // flow. Here this would be TargetHttpVersion since this is used by connector.

        // if Some(version) = request.get::<TargetHttpVersion>() {
        //     connection.insert(version)
        // }

        request.insert(RequestInfoInner);

        // This should have the complete view, unified view is basically a combined time sorted view
        // all events/extensions added in correct order
        // println!("request extensions: {:#?}", request.unified_view());

        // This should only see intial request extensions and the connection extensions
        // println!("connection extensions: {:#?}", connection.unified_view());

        // println!("is healthy {:?}", request.get::<IsHealth>().unwrap().0);

        // // Now our connection's internal state machine detect it is broken
        // // and inserts this in extensions, our request should also be able to see this
        connection.insert(BrokenConnection);
        connection.insert(IsHealth(false));

        // let timeline = request.iter_all_stored().collect::<Vec<_>>();
        // println!("request extensions: {:#?}", timeline);

        // println!("is healthy {:?}", request.get_arc::<IsHealth>().unwrap().0);
        assert!(!request.get_arc::<IsHealth>().unwrap().0);

        let _history: Vec<_> = request.iter::<IsHealth>().collect();
        // println!("health history {history:#?}");
    }

    #[test]
    fn basic() {
        let request = Extensions::default();
        request.insert(IsHealth(true));
        // println!("is healthy {:?}", request.get_arc::<IsHealth>());
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
            .get::<I>()
            .or_else(|| self.1.extensions().get::<I>())
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
