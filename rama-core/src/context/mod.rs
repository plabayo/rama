//! Context passed to and between services as input.
//!
//! # State
//!
//! [`rama`] supports two kinds of states:
//!
//! 1. type-safe state: this is the `S` generic parameter in [`Context`] and is to be used
//!    as much as possible, given its existence and type properties can be validated at compile time
//! 2. dynamic state: these can be injected as [`Extensions`]s using methods such as [`Context::insert`]
//!
//! As a rule of thumb one should use the type-safe state (1) in case:
//!
//! - the state is always expected to exist at the point the middleware/service is called
//! - the state is specific to the app or middleware
//! - and the state can be constructed in a default/empty state
//!
//! The latter is important given the state is often created (or at least reserved) prior to
//! it is actually being populated by the relevant middleware. This is not the case for app-specific state
//! such as Database pools which are created since the start and shared among many different tasks.
//!
//! The rule could be be simplified to "if you need to `.unwrap()` you probably want type-safe state instead".
//! It's however just a guideline and not a hard rule. As maintainers of [`rama`] we'll do our best to respect it though,
//! and we recommend you to do the same.
//!
//! Any state that is optional, and especially optional state injected by middleware, can be inserted using extensions.
//! It is however important to try as much as possible to then also consume this state in an approach that deals
//! gracefully with its absence. Good examples of this are header-related inputs. Headers might be set or not,
//! and so absence of [`Extensions`]s that might be created as a result of these might reasonably not exist.
//! It might of course still mean the app returns an error response when it is absent, but it should not unwrap/panic.
//!
//! [`rama`]: crate
//!
//! ## State Wraps
//!
//! [`rama`] was built from the ground up to operate on and between different layers of the network stack.
//! This has also an impact on state. Because sure, typed state is nice, but state leakage is not. What do I mean with that?
//!
//! When creating a `TcpListener` with state you are essentially creating and injecting state, which will remain
//! as "read-only" for the enire life cycle of that `TcpListener` and to be made available for every incoming _tcp_ connection,
//! as well as the application requests (Http requests). This is great for stuff that is okay to share, but it is not desired
//! for state that you wish to have a narrower scope. Examples are state that are tied to a single _tcp_ connection and thus
//! you do not wish to keep a global cache for this, as it would either be shared or get overly complicated to ensure
//! you keep things separate and clean.
//!
//! The solution is to wrap your state.
//!
//! > Example: [http_conn_state.rs](https://github.com/plabayo/rama/tree/main/examples/http_conn_state.rs)
//!
//! The above example shows how can use the [`#as_ref(wrap)`] property within an `#[derive(AsRef)]` derived "state" struct,
//! to wrap in a type-safe manner the "app-global" state within the "conn-specific" (tcp) state. This allows you to have
//! state freshly created for each connection while still having ease of access to the global state.
//!
//! Note though that you do not need the `AsRef` macro or even trait implementation to get this kind of access in your
//! own app-specific leaf services. It is however useful — and at times even a requirement — in case you want your
//! middleware stack to also include generic middleware that expect `AsRef<T>` trait bounds for type-safe access to
//! state from within a middleware. E.g. in case your middleware expects a data source for some specific data type,
//! it is of no use to have that middleware compile without knowing for sure that data source is made available
//! to that middleware.
//!
//! # Example
//!
//! ```
//! use rama_core::Context;
//! use std::sync::Arc;
//!
//! #[derive(Debug)]
//! struct ServiceState {
//!     value: i32,
//! }
//!
//! let state = Arc::new(ServiceState{ value: 5 });
//! let ctx = Context::with_state(state);
//! ```
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
//!
//! ## Example: State AsRef
//!
//! The state can be accessed as a reference using the [`AsRef`] trait.
//!
//! ```
//! use rama_core::{Context, context};
//! use std::sync::Arc;
//! use std::convert::AsRef;
//!
//! #[derive(Debug)]
//! struct ProxyDatabase;
//!
//! #[derive(Debug, context::AsRef)]
//! struct ServiceState {
//!     db: ProxyDatabase,
//! }
//!
//! let state = Arc::new(ServiceState{ db: ProxyDatabase });
//! let ctx = Context::with_state(state);
//!
//! let db: &ProxyDatabase = ctx.state().as_ref();
//! ```

use crate::graceful::ShutdownGuard;
use crate::rt::Executor;
use std::{fmt, future::Future, sync::Arc};
use tokio::task::JoinHandle;

pub use ::rama_macros::AsRef;

mod extensions;
#[doc(inline)]
pub use extensions::Extensions;

mod state;

/// Context passed to and between services as input.
///
/// See [`crate::context`] for more information.
pub struct Context<S> {
    state: Arc<S>,
    executor: Executor,
    extensions: Extensions,
}

impl<S: fmt::Debug> fmt::Debug for Context<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("state", &self.state)
            .field("executor", &self.executor)
            .field("extensions", &self.extensions)
            .finish()
    }
}

impl Default for Context<()> {
    fn default() -> Self {
        Self::new(Arc::new(()), Executor::default())
    }
}

impl<S> Clone for Context<S> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            executor: self.executor.clone(),
            extensions: self.extensions.clone(),
        }
    }
}

impl<S> Context<S> {
    /// Create a new [`Context`] with the given state.
    pub fn new(state: Arc<S>, executor: Executor) -> Self {
        Self {
            state,
            executor,
            extensions: Extensions::new(),
        }
    }

    /// Create a new [`Context`] with the given state and default extension.
    pub fn with_state(state: Arc<S>) -> Self {
        Self::new(state, Executor::default())
    }

    /// Get a reference to the state.
    pub fn state(&self) -> &S {
        &self.state
    }

    /// Get a cloned reference to the state.
    pub fn state_clone(&self) -> Arc<S> {
        self.state.clone()
    }

    /// Map the state from one type to another.
    pub fn map_state<F, W>(self, f: F) -> Context<W>
    where
        F: FnOnce(Arc<S>) -> Arc<W>,
    {
        Context {
            state: f(self.state),
            executor: self.executor,
            extensions: self.extensions,
        }
    }

    /// Get a reference to the executor.
    pub fn executor(&self) -> &Executor {
        &self.executor
    }

    /// Spawn a future on the current executor,
    /// this is spawned gracefully in case a shutdown guard has been registered.
    pub fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future<Output: Send + 'static> + Send + 'static,
    {
        self.executor.spawn_task(future)
    }

    /// Returns true if the `Context` contains the given type.
    ///
    /// Use [`Self::get`] in case you want to have access to the type
    /// or [`Self::get_mut`] if you also need to mutate it.
    pub fn contains<T: Send + Sync + 'static>(&self) -> bool {
        self.extensions.contains::<T>()
    }

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
    /// # use std::sync::Arc;
    /// # #[derive(Debug, Clone)]
    /// struct State {
    ///     mul: i32,
    /// }
    /// let mut ctx = Context::with_state(Arc::new(State{ mul: 2 }));
    /// ctx.insert(true);
    /// let value: &i32 = ctx.get_or_insert_with_ctx(|ctx| ctx.state().mul * 21);
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

    /// Get a reference to the shutdown guard,
    /// if and only if the context was created within a graceful environment.
    pub fn guard(&self) -> Option<&ShutdownGuard> {
        self.executor.guard()
    }
}
