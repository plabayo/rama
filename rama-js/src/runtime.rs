use std::fmt;
use std::time::Duration;

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
/// [`JsWorker`][crate::JsWorker] instead.
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

    /// Compile and validate the private engine component, if it has not been
    /// initialized in this process yet.
    ///
    /// Applications may call this during startup to keep the one-time Wasm
    /// compilation cost out of a latency-sensitive first evaluation.
    pub fn warm_up() -> Result<(), JsError> {
        Engine::warm_up()
    }

    /// Evaluate a single script with the default runtime configuration,
    /// returning the value of its final expression.
    pub fn eval_once(src: impl AsRef<str>) -> Result<JsValue, JsError> {
        Self::builder().build()?.eval(src)
    }

    /// Evaluate a script, returning the value of its final expression.
    ///
    /// Each source is evaluated as a classic Script. State, including
    /// top-level lexical declarations and global function definitions,
    /// persists across evaluations within the same runtime.
    ///
    /// Scheduled promise jobs and other microtasks are drained before the
    /// operation returns. Their work consumes the same fuel and wall-clock
    /// budget as the script which scheduled them.
    pub fn eval(&mut self, src: impl AsRef<str>) -> Result<JsValue, JsError> {
        self.engine.eval(src.as_ref())
    }

    /// Execute a script while discarding its final expression value.
    ///
    /// This avoids materializing a value snapshot when only script side
    /// effects are relevant.
    pub fn exec(&mut self, src: impl AsRef<str>) -> Result<(), JsError> {
        self.engine.exec(src.as_ref())
    }

    /// Call a global function with the given arguments.
    ///
    /// Reachable functions are `function`-declared globals, `var`-assigned
    /// function values, and registered host functions — anything that lands
    /// as an own property of the global object. Top-level `let`/`const`/
    /// `class` bindings live in the script's declarative scope, not on the
    /// global object, so `const f = () => …` is **not** callable by name
    /// (it resolves to [`JsErrorKind::NotFound`][crate::JsErrorKind::NotFound]);
    /// use a `function` declaration or assign to a `var`/global.
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

    /// Returns `true` once an operation trapped inside the WebAssembly engine,
    /// for example after exhausting fuel, time, stack, or memory. The script
    /// was aborted mid-execution, so every later operation
    /// fails with [`JsErrorKind::Setup`][crate::JsErrorKind::Setup].
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.engine.is_poisoned()
    }

    /// Install a Rust-owned native object as a global in this runtime.
    ///
    /// This operation is deliberately runtime-local: native objects are not
    /// accepted by [`JsRuntimeBuilder`], because a reusable builder may back
    /// multiple runtimes.
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
/// making clones cheap. One blueprint can back any number of
/// [`JsRuntime`]s and [`JsWorker`][crate::JsWorker]s.
#[derive(Clone)]
pub struct JsRuntimeBuilder {
    strict: bool,
    loop_iteration_limit: Option<u64>,
    execution_time_limit: Option<Duration>,
    memory_limit: usize,
    snapshot_limits: JsSnapshotLimits,
    globals: Vec<(JsStr, GlobalEntry)>,
}

impl Default for JsRuntimeBuilder {
    fn default() -> Self {
        Self {
            strict: false,
            loop_iteration_limit: Some(Self::DEFAULT_LOOP_ITERATION_LIMIT),
            execution_time_limit: None,
            memory_limit: Self::DEFAULT_MEMORY_LIMIT,
            snapshot_limits: JsSnapshotLimits::default(),
            globals: Vec::new(),
        }
    }
}

impl fmt::Debug for JsRuntimeBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsRuntimeBuilder")
            .field("strict", &self.strict)
            .field("loop_iteration_limit", &self.loop_iteration_limit)
            .field("execution_time_limit", &self.execution_time_limit)
            .field("memory_limit", &self.memory_limit)
            .field("snapshot_limits", &self.snapshot_limits)
            .field("globals", &self.globals.len())
            .finish()
    }
}

impl JsRuntimeBuilder {
    /// Default instruction-fuel budget, expressed in approximate loop
    /// iterations for compatibility with the original API.
    pub const DEFAULT_LOOP_ITERATION_LIMIT: u64 = 1_000_000;
    /// Default maximum memory available to the private WebAssembly engine.
    pub const DEFAULT_MEMORY_LIMIT: usize = rama_utils::octets::mib(64);

    generate_set_and_with! {
        /// Evaluate all scripts in strict mode,
        /// regardless of `"use strict"` directives.
        pub fn strict(mut self, strict: bool) -> Self {
            self.strict = strict;
            self
        }
    }

    generate_set_and_with! {
        /// Limit script work with deterministic WebAssembly instruction fuel.
        ///
        /// The value is scaled to preserve the existing approximate loop-count
        /// configuration. Unlike the original per-frame guard, the budget is
        /// cumulative across the complete evaluation or function call.
        ///
        /// Defaults to [`Self::DEFAULT_LOOP_ITERATION_LIMIT`]; `None` removes
        /// the limit entirely. Exceeding it fails the evaluation with
        /// [`JsErrorKind::LimitExceeded`][crate::JsErrorKind::LimitExceeded].
        pub fn loop_iteration_limit(mut self, limit: Option<u64>) -> Self {
            self.loop_iteration_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Set the maximum memory available to the private WebAssembly engine.
        ///
        /// This includes the JavaScript heap and engine state. Memory growth
        /// beyond the limit traps inside the WebAssembly container and poisons
        /// the runtime. Defaults to [`Self::DEFAULT_MEMORY_LIMIT`].
        pub fn memory_limit(mut self, limit: usize) -> Self {
            self.memory_limit = limit;
            self
        }
    }

    generate_set_and_with! {
        /// Wall-clock limit on each evaluation or call.
        ///
        /// Wasmtime epoch interruption bounds all execution inside the engine
        /// component, including parsing, compilation, built-ins, snapshotting,
        /// and drained microtasks. The check is coarse-grained and does not run
        /// while a registered Rust host callback is executing.
        ///
        /// Exceeding it fails the evaluation with
        /// [`JsErrorKind::LimitExceeded`][crate::JsErrorKind::LimitExceeded]
        /// and poisons the runtime ([`JsRuntime::is_poisoned`]): the engine
        /// was aborted mid-execution, so every later operation fails with
        /// [`JsErrorKind::Setup`][crate::JsErrorKind::Setup]. A
        /// [`JsWorker`][crate::JsWorker] whose runtime got poisoned exits,
        /// failing pending jobs fast (fail-loud, like a panicking host
        /// function).
        ///
        /// The frozen `__rama_js_call__` global remains reserved for API
        /// compatibility and never exposes host data.
        ///
        /// Defaults to `None`: no time limit.
        pub fn execution_time_limit(mut self, limit: Option<Duration>) -> Self {
            self.execution_time_limit = limit;
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
            loop_iteration_limit: self.loop_iteration_limit,
            execution_time_limit: self.execution_time_limit,
            memory_limit: self.memory_limit,
            snapshot_limits: self.snapshot_limits,
            globals,
        }
    }
}
