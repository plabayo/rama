//! Context passed to and between services as input.
//!
//! # State
//!
//! [`rama`] supports two kinds of states:
//!
//! 1. static state: this state can be a part of the service struct or captured by a closure
//! 2. dynamic state: these can be injected as [`Extensions`]s using methods such as [`Context::insert`]
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
//!
//! The [`Context`] can be extended with additional data using the [`Extensions`] type.
//!
//! [`Context`]: crate::Context
//! [`Extensions`]: crate::context::Extensions
//!
//! ```
//! use rama_core::Context;
//!
//! let mut ctx = Context::default();
//! ctx.insert(5i32);
//! assert_eq!(ctx.get::<i32>(), Some(&5i32));
//! ```

use crate::graceful::ShutdownGuard;
use crate::rt::Executor;
use std::ops::{Deref, DerefMut};
use tokio::task::JoinHandle;

mod extensions;
#[doc(inline)]
pub use extensions::Extensions;

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

#[derive(Debug, Default, Clone)]
/// Context passed to and between services as input.
///
/// See [`crate::context`] for more information.
pub struct Context {
    executor: Executor,
    extensions: Extensions,
}

#[derive(Debug)]
/// Component parts of [`Context`].
pub struct Parts {
    pub executor: Executor,
    pub extensions: Extensions,
}

impl Context {
    #[must_use]
    /// Create a new [`Context`] with the given state.
    pub fn new(executor: Executor) -> Self {
        Self {
            executor,
            extensions: Extensions::new(),
        }
    }

    #[must_use]
    pub fn from_parts(parts: Parts) -> Self {
        Self {
            executor: parts.executor,
            extensions: parts.extensions,
        }
    }

    #[must_use]
    pub fn into_parts(self) -> Parts {
        Parts {
            executor: self.executor,
            extensions: self.extensions,
        }
    }

    #[must_use]
    /// Get a reference to the executor.
    pub fn executor(&self) -> &Executor {
        &self.executor
    }

    /// Set a new [`Executor`] to the [`Context`].
    pub fn set_executor(&mut self, exec: Executor) -> &mut Self {
        self.executor = exec;
        self
    }

    /// Set a new [`Executor`] to the [`Context`].
    #[must_use]
    pub fn with_executor(mut self, exec: Executor) -> Self {
        self.executor = exec;
        self
    }

    /// Spawn a future on the current executor,
    /// this is spawned gracefully in case a shutdown guard has been registered.
    pub fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        self.executor.spawn_task(future)
    }

    #[must_use]
    /// Returns true if the `Context` contains the given type.
    ///
    /// Use [`Self::get`] in case you want to have access to the type
    /// or [`Self::get_mut`] if you also need to mutate it.
    pub fn contains<T: Send + Sync + 'static>(&self) -> bool {
        self.extensions.contains::<T>()
    }

    #[must_use]
    /// Get a shared reference to an extension.
    ///
    /// An extension is a type that implements `Send + Sync + 'static`,
    /// and can be used to inject dynamic data into the [`Context`].
    ///
    /// Extensions are specific to this [`Context`]. It will be cloned when the [`Context`] is cloned,
    /// but extensions inserted using [`Context::insert`] will not be visible the
    /// original [`Context`], or any other cloned [`Context`].
    ///
    /// Please use the statically typed state (see [`Context::state`]) for data that is shared between
    /// all context clones.
    ///
    /// # Example
    ///
    /// ```
    /// # use rama_core::Context;
    /// # let mut ctx = Context::default();
    /// # ctx.insert(5i32);
    /// assert_eq!(ctx.get::<i32>(), Some(&5i32));
    /// ```
    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.extensions.get::<T>()
    }

    /// Get an exclusive reference to an extension.
    ///
    /// An extension is a type that implements `Send + Sync + 'static`,
    /// and can be used to inject dynamic data into the [`Context`].
    ///
    /// Extensions are specific to this [`Context`]. It will be cloned when the [`Context`] is cloned,
    /// but extensions inserted using [`Context::insert`] will not be visible the
    /// original [`Context`], or any other cloned [`Context`].
    ///
    /// Please use the statically typed state (see [`Context::state`]) for data that is shared between
    /// all context clones.
    ///
    /// # Example
    ///
    /// ```
    /// # use rama_core::Context;
    /// # let mut ctx = Context::default();
    /// # ctx.insert(5i32);
    /// let x = ctx.get_mut::<i32>().unwrap();
    /// assert_eq!(*x, 5i32);
    /// *x = 8;
    /// assert_eq!(*x, 8i32);
    /// assert_eq!(ctx.get::<i32>(), Some(&8i32));
    /// ```
    pub fn get_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        self.extensions.get_mut::<T>()
    }

    /// Inserts a value into the map computed from `f` into if it is [`None`],
    /// then returns an exclusive reference to the contained value.
    ///
    /// # Example
    ///
    /// ```
    /// # use rama_core::Context;
    /// let mut ctx = Context::default();
    /// let value: &i32 = ctx.get_or_insert_with(|| 42);
    /// assert_eq!(*value, 42);
    /// let existing_value: &mut i32 = ctx.get_or_insert_with(|| 0);
    /// assert_eq!(*existing_value, 42);
    /// ```
    pub fn get_or_insert_with<T: Clone + Send + Sync + 'static>(
        &mut self,
        f: impl FnOnce() -> T,
    ) -> &mut T {
        self.extensions.get_or_insert_with(f)
    }

    /// Inserts a value into the map computed from `f` into if it is [`None`],
    /// then returns an exclusive reference to the contained value.
    ///
    /// Use the cheaper [`Self::get_or_insert_with`] in case you do not need access to
    /// the [`Context`] for the creation of `T`, as this function comes with
    /// an extra cost.
    ///
    /// # Example
    ///
    /// ```
    /// # use rama_core::Context;
    /// # #[derive(Debug, Clone)]
    /// struct State {
    ///     mul: i32,
    /// }
    /// let mut ctx = Context::default();
    /// ctx.insert(State{ mul: 2 });
    /// let value: &i32 = ctx.get_or_insert_with_ctx(|ctx| ctx.get::<State>().unwrap().mul * 21);
    /// assert_eq!(*value, 42);
    /// let existing_value: &mut i32 = ctx.get_or_insert_default();
    /// assert_eq!(*existing_value, 42);
    /// ```
    pub fn get_or_insert_with_ctx<T: Clone + Send + Sync + 'static>(
        &mut self,
        f: impl FnOnce(&Self) -> T,
    ) -> &mut T {
        if self.extensions.contains::<T>() {
            // NOTE: once <https://github.com/rust-lang/polonius>
            // is merged into rust we can use directly `if let Some(v) = self.extensions.get_mut()`,
            // until then we need this work around.
            return self.extensions.get_mut().unwrap();
        }
        let v = f(self);
        self.extensions.insert(v);
        self.extensions.get_mut().unwrap()
    }

    /// Try to insert a value into the map computed from `f` into if it is [`None`],
    /// then returns an exclusive reference to the contained value.
    ///
    /// Similar to [`Self::get_or_insert_with_ctx`] but fallible.
    pub fn get_or_try_insert_with_ctx<T: Clone + Send + Sync + 'static, E>(
        &mut self,
        f: impl FnOnce(&Self) -> Result<T, E>,
    ) -> Result<&mut T, E> {
        if self.extensions.contains::<T>() {
            // NOTE: once <https://github.com/rust-lang/polonius>
            // is merged into rust we can use directly `if let Some(v) = self.extensions.get_mut()`,
            // until then we need this work around.
            return Ok(self.extensions.get_mut().unwrap());
        }
        let v = f(self)?;
        self.extensions.insert(v);
        Ok(self.extensions.get_mut().unwrap())
    }

    /// Inserts a value into the map computed from converting `U` into `T if no value was already inserted is [`None`],
    /// then returns an exclusive reference to the contained value.
    pub fn get_or_insert_from<T, U>(&mut self, src: U) -> &mut T
    where
        T: Clone + Send + Sync + 'static,
        U: Into<T>,
    {
        self.extensions.get_or_insert_from(src)
    }

    /// Retrieves a value of type `T` from the context.
    ///
    /// If the value does not exist, the provided value is inserted
    /// and an exclusive reference to it is returned.
    ///
    /// See [`Context::get`] for more details.
    ///
    /// # Example
    ///
    /// ```
    /// # use rama_core::Context;
    /// let mut ctx = Context::default();
    /// ctx.insert(5i32);
    ///
    /// assert_eq!(*ctx.get_or_insert::<i32>(10), 5);
    /// assert_eq!(*ctx.get_or_insert::<f64>(2.5), 2.5);
    /// ```
    pub fn get_or_insert<T: Send + Sync + Clone + 'static>(&mut self, fallback: T) -> &mut T {
        self.extensions.get_or_insert(fallback)
    }

    /// Get an extension or `T`'s [`Default`].
    ///
    /// See [`Context::get`] for more details.
    ///
    /// # Example
    ///
    /// ```
    /// # use rama_core::Context;
    /// # let mut ctx = Context::default();
    /// # ctx.insert(5i32);
    ///
    /// assert_eq!(*ctx.get_or_insert_default::<i32>(), 5i32);
    /// assert_eq!(*ctx.get_or_insert_default::<f64>(), 0f64);
    /// ```
    pub fn get_or_insert_default<T: Clone + Default + Send + Sync + 'static>(&mut self) -> &mut T {
        self.extensions.get_or_insert_default()
    }

    /// Insert an extension into the [`Context`].
    ///
    /// If a extension of this type already existed, it will
    /// be returned.
    ///
    /// See [`Context::get`] for more details regarding extensions.
    ///
    /// # Example
    ///
    /// ```
    /// # use rama_core::Context;
    /// let mut ctx = Context::default();
    ///
    /// assert_eq!(ctx.insert(5i32), None);
    /// assert_eq!(ctx.get::<i32>(), Some(&5i32));
    ///
    /// assert_eq!(ctx.insert(4i32), Some(5i32));
    /// assert_eq!(ctx.get::<i32>(), Some(&4i32));
    /// ```
    pub fn insert<T: Clone + Send + Sync + 'static>(&mut self, extension: T) -> Option<T> {
        self.extensions.insert(extension)
    }

    /// Insert a type only into this [`Context`], if the extension is `Some(T)`.
    ///
    /// See [`Self::insert`] for more information.
    pub fn maybe_insert<T: Clone + Send + Sync + 'static>(
        &mut self,
        extension: Option<T>,
    ) -> Option<T> {
        self.extensions.maybe_insert(extension)
    }

    #[must_use]
    /// Return the entire dynamic state of the [`Context`] by reference.
    ///
    /// Useful only in case you have a function which works with [`Extensions`] rather
    /// then the [`Context`] itself. In case you want to have access to a specific dynamic state,
    /// it is more suitable to use [`Context::get`] directly.
    pub fn extensions(&self) -> &Extensions {
        &self.extensions
    }

    /// Return the entire dynamic state of the [`Context`] by mutable reference.
    ///
    /// Useful only in case you have a function which works with [`Extensions`] rather
    /// then the [`Context`] itself. In case you want to have access to a specific dynamic state,
    /// it is more suitable to use [`Context::get_or_insert`] or [`Context::insert`] directly.
    ///
    /// # Rollback
    ///
    /// Extensions do not have "rollback" support. In case you are not yet certain if you want to keep
    /// the to be inserted [`Extensions`], you are better to create a new [`Extensions`] object using
    /// [`Extensions::default`] and use [`Context::extend`] once you wish to commit the new
    /// dynamic data into the [`Context`].
    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.extensions
    }

    /// Extend The [`Context`] [`Extensions`] with another [`Extensions`].
    ///
    /// # Example
    ///
    /// ```
    /// # use rama_core::{context::Extensions, Context};
    /// let mut ctx = Context::default();
    /// let mut ext = Extensions::default();
    ///
    /// ctx.insert(true);
    /// ext.insert(5i32);
    /// ctx.extend(ext);
    ///
    /// assert_eq!(ctx.get::<bool>(), Some(&true));
    /// assert_eq!(ctx.get::<i32>(), Some(&5i32));
    /// ```
    pub fn extend(&mut self, extensions: Extensions) {
        self.extensions.extend(extensions);
    }

    /// Clear the [`Context`] of all inserted [`Extensions`].
    ///
    /// # Example
    ///
    /// ```
    /// # use rama_core::Context;
    /// let mut ctx = Context::default();
    ///
    /// ctx.insert(5i32);
    /// assert_eq!(ctx.get::<i32>(), Some(&5i32));
    ///
    /// ctx.clear();
    /// assert_eq!(ctx.get::<i32>(), None);
    /// ```
    pub fn clear(&mut self) {
        self.extensions.clear();
    }

    /// Remove an extension from this [`Context`]
    pub fn remove<T: Clone + Send + Sync + 'static>(&mut self) -> Option<T> {
        self.extensions.remove()
    }

    #[must_use]
    /// Get a reference to the shutdown guard,
    /// if and only if the context was created within a graceful environment.
    pub fn guard(&self) -> Option<&ShutdownGuard> {
        self.executor.guard()
    }
}
