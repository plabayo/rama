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

use std::any::{Any, TypeId};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;

/// A type map of protocol extensions.
///
/// `Extensions` can be used by `Request` and `Response` to store
/// extra data derived from the underlying protocol.
#[derive(Clone, Default)]
pub struct Extensions {
    // TODO optimize this storage
    extensions: Vec<Extension>,
}

#[derive(Clone, Debug)]
struct Extension(TypeId, Box<dyn ExtensionType>);

impl Extensions {
    /// Create an empty `Extensions`.
    #[inline(always)]
    #[must_use]
    pub fn new() -> Self {
        Self {
            extensions: vec![],
            // parent_extensions: Arc::new([]),
        }
    }

    /// Insert a type into this `Extensions`.
    pub fn insert<T>(&mut self, val: T) -> &mut Self
    where
        T: Clone + Send + Sync + std::fmt::Debug + 'static,
    {
        let extension = Extension(TypeId::of::<T>(), Box::new(val));
        self.extensions.push(extension);
        self
    }

    /// Insert a type into this `Extensions`.
    pub fn maybe_insert<T>(&mut self, val: Option<T>) -> &mut Self
    where
        T: Clone + Send + Sync + std::fmt::Debug + 'static,
    {
        if let Some(val) = val {
            self.insert(val);
        }
        self
    }

    pub fn extend(&mut self, extensions: Self) -> &mut Self {
        self.extensions.extend(extensions.extensions);
        self
    }

    /// Returns true if the `Extensions` or parents contains the given type.
    #[must_use]
    pub fn contains<T: Send + Sync + 'static>(&self) -> bool {
        let type_id = TypeId::of::<T>();
        self.extensions.iter().rev().any(|item| item.0 == type_id)
    }

    /// Get a shared reference to a type previously inserted on this `Extensions` or any of the parents
    #[must_use]
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        let type_id = TypeId::of::<T>();
        self.extensions
            .iter()
            .rev()
            .find(|item| item.0 == type_id)
            .map(|ext| &ext.1)
            .and_then(|boxed| (**boxed).as_any().downcast_ref())
    }
}

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Extensions")
            .field("extensions", &self.extensions)
            .finish()
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

trait ExtensionType: Any + Send + Sync + std::fmt::Debug {
    fn clone_box(&self) -> Box<dyn ExtensionType>;
    fn as_any(&self) -> &dyn Any;
}

impl<T: Clone + Send + Sync + std::fmt::Debug + 'static> ExtensionType for T {
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
