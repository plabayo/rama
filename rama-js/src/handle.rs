use std::fmt;
use std::sync::Arc;

use crate::error::{JsError, JsErrorKind};
use crate::runtime::{JsRuntime, JsRuntimeBuilder};
use crate::value::JsValue;

/// A `Send + Sync`, cheap-to-clone handle for executing javascript
/// from async contexts, without sharing any script state between
/// executions.
///
/// A [`JsEngine`] holds a [`JsRuntimeBuilder`] as its blueprint.
/// Every [`run`][Self::run] builds a **fresh** [`JsRuntime`] from that
/// blueprint, so executions can never observe each other's side effects.
/// [`run`][Self::run] delegates synchronous javascript execution to
/// Tokio's blocking executor. [`run_blocking`][Self::run_blocking] is
/// available when the caller wants to choose the execution environment.
#[derive(Clone)]
pub struct JsEngine {
    blueprint: Arc<JsRuntimeBuilder>,
}

impl fmt::Debug for JsEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsEngine")
            .field("blueprint", &self.blueprint)
            .finish()
    }
}

impl JsEngine {
    /// Create a new engine with the given builder as its blueprint.
    #[must_use]
    pub fn new(builder: JsRuntimeBuilder) -> Self {
        Self {
            blueprint: Arc::new(builder),
        }
    }

    /// Execute the given closure with a fresh [`JsRuntime`] on the
    /// current thread.
    ///
    /// Javascript evaluation is synchronous. This method makes that
    /// explicit and lets callers place it on their own thread or executor.
    pub fn run_blocking<T, F>(&self, f: F) -> Result<T, JsError>
    where
        F: FnOnce(&mut JsRuntime) -> Result<T, JsError>,
    {
        let mut runtime = (*self.blueprint).clone().build()?;
        f(&mut runtime)
    }

    /// Execute the given closure with a fresh [`JsRuntime`] using
    /// [`tokio::task::spawn_blocking`].
    ///
    /// State created by the closure (globals, function definitions, ...)
    /// lives only for the duration of this single execution.
    pub async fn run<T, F>(&self, f: F) -> Result<T, JsError>
    where
        F: FnOnce(&mut JsRuntime) -> Result<T, JsError> + Send + 'static,
        T: Send + 'static,
    {
        let engine = self.clone();
        tokio::task::spawn_blocking(move || engine.run_blocking(f))
            .await
            .map_err(|err| JsError::new(JsErrorKind::Setup, format!("js task failed: {err}")))?
    }

    /// Evaluate a script on a fresh [`JsRuntime`] built from this
    /// engine's blueprint, returning the value of its final expression.
    ///
    /// The source moves to the blocking executor, but does not have to be
    /// converted into a `String`; owned strings, `Arc<str>`, and static
    /// string slices can all be passed without an extra allocation.
    pub async fn eval<S>(&self, src: S) -> Result<JsValue, JsError>
    where
        S: AsRef<str> + Send + 'static,
    {
        self.run(move |runtime| runtime.eval(src.as_ref())).await
    }

    /// Evaluate a script synchronously on a fresh runtime.
    pub fn eval_blocking(&self, src: impl AsRef<str>) -> Result<JsValue, JsError> {
        self.run_blocking(|runtime| runtime.eval(src))
    }
}
