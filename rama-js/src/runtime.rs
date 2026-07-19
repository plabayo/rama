use std::fmt;

use rama_utils::macros::generate_set_and_with;

use crate::console::Console;
use crate::engine::{Engine, EngineConfig, GlobalEntry};
use crate::error::JsError;
use crate::func::JsFn;
use crate::host::JsHostObject;
use crate::namespace::JsNamespace;
use crate::snapshot::JsSnapshotLimits;
use crate::value::{JsStr, JsValue};

/// A javascript runtime, executing scripts on the current thread.
///
/// Create one via [`JsRuntime::builder`], or use [`JsRuntime::eval_once`]
/// for a one-off script evaluation with the default configuration.
///
/// A runtime is single-threaded (`!Send`); services which need to
/// evaluate scripts from async (`Send`) contexts use a
/// [`JsEngine`][crate::JsEngine] instead.
pub struct JsRuntime {
    engine: Engine,
}

impl fmt::Debug for JsRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsRuntime").finish_non_exhaustive()
    }
}

impl JsRuntime {
    /// Create a [`JsRuntimeBuilder`] to configure a new runtime.
    #[must_use]
    pub fn builder() -> JsRuntimeBuilder {
        JsRuntimeBuilder::default()
    }

    /// Evaluate a single script with the default runtime configuration,
    /// returning the value of its final expression.
    pub fn eval_once(src: impl AsRef<str>) -> Result<JsValue, JsError> {
        Self::builder().build()?.eval(src)
    }

    /// Evaluate a script, returning the value of its final expression.
    ///
    /// State (globals, function definitions, ...) persists across
    /// evaluations within the same runtime.
    pub fn eval(&mut self, src: impl AsRef<str>) -> Result<JsValue, JsError> {
        self.engine.eval(src.as_ref())
    }

    /// Call a global function (defined by a previously evaluated
    /// script, or registered as a host function) with the given arguments.
    pub fn call<I, V>(&mut self, name: impl AsRef<str>, args: I) -> Result<JsValue, JsError>
    where
        I: IntoIterator<Item = V>,
        V: Into<JsValue>,
    {
        let args: Vec<JsValue> = args.into_iter().map(Into::into).collect();
        self.engine.call(name.as_ref(), &args)
    }

    /// Returns `true` if a global function with the given name exists.
    pub fn has_global_fn(&mut self, name: impl AsRef<str>) -> bool {
        self.engine.has_global_fn(name.as_ref())
    }

    /// Install a Rust-owned native object as a global in this runtime.
    ///
    /// This operation is deliberately runtime-local: native objects are not
    /// accepted by [`JsRuntimeBuilder`], because a reusable builder may back
    /// concurrent [`JsEngine`][crate::JsEngine] executions.
    pub fn set_host_global<T>(
        &mut self,
        name: impl Into<JsStr>,
        object: JsHostObject<T>,
    ) -> Result<(), JsError>
    where
        T: Send + 'static,
    {
        let name = name.into();
        self.engine.set_host_global(&name, object.into_erased())
    }
}

/// Opaque lowered form of a global registration; see [`IntoJsGlobal`].
pub struct JsGlobal(pub(crate) GlobalEntry);

impl fmt::Debug for JsGlobal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsGlobal").finish_non_exhaustive()
    }
}

/// Everything that can be registered as a global on a
/// [`JsRuntimeBuilder`]: values convertible [`Into<JsValue>`]
/// as well as [`JsNamespace`] host objects.
pub trait IntoJsGlobal {
    /// Lower into the global registration entry.
    fn into_global_entry(self) -> JsGlobal;
}

impl<T: Into<JsValue>> IntoJsGlobal for T {
    fn into_global_entry(self) -> JsGlobal {
        JsGlobal(GlobalEntry::Value(self.into()))
    }
}

impl IntoJsGlobal for JsNamespace {
    fn into_global_entry(self) -> JsGlobal {
        JsGlobal(GlobalEntry::Namespace(self.into_entries()))
    }
}

/// Builder to configure and create a [`JsRuntime`].
///
/// Cloneable, so it can double as a reusable blueprint: registered
/// values share their backing storage and host functions are shared,
/// making clones cheap. This is what [`JsEngine`][crate::JsEngine]
/// uses to build a fresh runtime per execution.
#[derive(Default, Clone)]
pub struct JsRuntimeBuilder {
    strict: bool,
    recursion_limit: Option<usize>,
    loop_iteration_limit: Option<u64>,
    stack_size_limit: Option<usize>,
    snapshot_limits: JsSnapshotLimits,
    globals: Vec<(JsStr, GlobalEntry)>,
}

impl fmt::Debug for JsRuntimeBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsRuntimeBuilder")
            .field("strict", &self.strict)
            .field("recursion_limit", &self.recursion_limit)
            .field("loop_iteration_limit", &self.loop_iteration_limit)
            .field("stack_size_limit", &self.stack_size_limit)
            .field("snapshot_limits", &self.snapshot_limits)
            .field("globals", &self.globals.len())
            .finish()
    }
}

impl JsRuntimeBuilder {
    generate_set_and_with! {
        /// Evaluate all scripts in strict mode,
        /// regardless of `"use strict"` directives.
        pub fn strict(mut self, strict: bool) -> Self {
            self.strict = strict;
            self
        }
    }

    generate_set_and_with! {
        /// Limit the depth of recursive calls within scripts.
        ///
        /// Exceeding it fails the evaluation with
        /// [`JsErrorKind::LimitExceeded`][crate::JsErrorKind::LimitExceeded].
        pub fn recursion_limit(mut self, limit: Option<usize>) -> Self {
            self.recursion_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Limit the number of iterations any single loop may run within scripts.
        ///
        /// Exceeding it fails the evaluation with
        /// [`JsErrorKind::LimitExceeded`][crate::JsErrorKind::LimitExceeded].
        pub fn loop_iteration_limit(mut self, limit: Option<u64>) -> Self {
            self.loop_iteration_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Limit the size of the script value stack.
        ///
        /// Exceeding it fails the evaluation with
        /// [`JsErrorKind::LimitExceeded`][crate::JsErrorKind::LimitExceeded].
        pub fn stack_size_limit(mut self, limit: Option<usize>) -> Self {
            self.stack_size_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Configure resource limits for values copied out of the JS engine.
        ///
        /// These limits apply to results, thrown values, and host-function
        /// arguments. The safe defaults are defined by [`JsSnapshotLimits`].
        pub fn snapshot_limits(mut self, limits: JsSnapshotLimits) -> Self {
            self.snapshot_limits = limits;
            self
        }
    }

    /// Register a global: a value convertible [`Into<JsValue>`],
    /// or a [`JsNamespace`] host object.
    #[must_use]
    pub fn with_global(mut self, name: impl Into<JsStr>, global: impl IntoJsGlobal) -> Self {
        self.set_global(name, global);
        self
    }

    /// Register a global: a value convertible [`Into<JsValue>`],
    /// or a [`JsNamespace`] host object.
    pub fn set_global(&mut self, name: impl Into<JsStr>, global: impl IntoJsGlobal) -> &mut Self {
        self.globals
            .push((name.into(), global.into_global_entry().0));
        self
    }

    /// Register a global host function with typed,
    /// extractor-style arguments (see [`JsFn`]).
    #[must_use]
    pub fn with_fn<A, F: JsFn<A>>(mut self, name: impl Into<JsStr>, f: F) -> Self {
        self.set_fn(name, f);
        self
    }

    /// Register a global host function with typed,
    /// extractor-style arguments (see [`JsFn`]).
    pub fn set_fn<A, F: JsFn<A>>(&mut self, name: impl Into<JsStr>, f: F) -> &mut Self {
        self.globals
            .push((name.into(), GlobalEntry::Fn(f.into_raw_host_fn())));
        self
    }

    /// Build the configured [`JsRuntime`].
    pub fn build(self) -> Result<JsRuntime, JsError> {
        let engine = Engine::new(self.into_engine_config())?;
        Ok(JsRuntime { engine })
    }

    pub(crate) fn into_engine_config(self) -> EngineConfig {
        let mut globals = self.globals;
        if !globals.iter().any(|(name, _)| name == "console") {
            globals.insert(
                0,
                (
                    JsStr::new_static("console"),
                    Console::void().into_global_entry().0,
                ),
            );
        }

        EngineConfig {
            strict: self.strict,
            recursion_limit: self.recursion_limit,
            loop_iteration_limit: self.loop_iteration_limit,
            stack_size_limit: self.stack_size_limit,
            snapshot_limits: self.snapshot_limits,
            globals,
        }
    }
}
