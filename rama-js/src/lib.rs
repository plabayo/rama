//! Embedded JavaScript execution for Rama.
//!
//! This crate provides a small, engine-agnostic API to evaluate JavaScript,
//! in two execution modes:
//!
//! - [`JsRuntime`]: direct script execution on the current thread;
//! - [`JsWorker`]: a long-lived runtime owned by a dedicated worker thread —
//!   compile a script once, then call into it per request from async code.
//!   This is the model browsers and proxies use for configuration scripts.
//!   Executions needing a fresh, side-effect-free runtime instead spawn a
//!   [`JsWorker`] (or [`JsRuntime`]) per script from a shared
//!   [`JsRuntimeBuilder`] blueprint.
//!
//! Host (FFI) functions are registered on the [`JsRuntimeBuilder`] with
//! extractor-style typed arguments (see [`JsFn`]), and values cross the
//! script boundary as engine-agnostic [`JsValue`]s.
//! Rust-owned resources can instead be exposed without conversion through a
//! runtime-local [`JsHostObject`], with typed methods and properties.
//!
//! Strings cross the boundary as UTF-8: unpaired UTF-16 surrogates are
//! replaced with U+FFFD, which collapses js object keys differing only in
//! such surrogates into one (last value wins, like any duplicate key).
//!
//! The JS engine used is an implementation detail of this crate: no engine
//! types are exposed in the public API, so the engine can be swapped or made
//! pluggable without breaking changes.
//!
//! # Limits are guardrails, not a sandbox
//!
//! Runtime limits ([`JsRuntimeBuilder`]) bound recursion depth, the value
//! stack, and loop iterations per function activation; snapshot limits
//! ([`JsSnapshotLimits`]) bound values copied across the boundary. They
//! catch runaway scripts, but are no defense against deliberately hostile
//! ones: each function call gets a fresh loop budget, native built-ins
//! (`Array.prototype.fill`, string concatenation, ...) and engine-heap
//! allocations are not metered, and a [`JsWorker`] timeout releases the
//! caller without interrupting the job.
//!
//! The opt-in
//! [execution time limit][JsRuntimeBuilder::set_execution_time_limit] adds a
//! wall-clock bound on *bytecode* execution, at the cost of poisoning the
//! runtime when it fires. It cannot reach anywhere the engine is not
//! executing bytecode: work inside a native built-in — including a script
//! callback the built-in invokes, as `Array.prototype.map` does — runs to
//! completion, and heap use stays unmetered. A script can therefore still
//! occupy its thread far longer than the limit says.
//!
//! The backstop for that is the [`JsWorker`] timeout, which abandons a
//! worker whose job overran (see [`JsWorker::is_abandoned`]) so callers get
//! an error instead of queueing behind work that may never finish. The
//! thread itself keeps running: spawn a replacement worker, and expect a
//! hostile script to cost you one leaked thread each time. Bound how often
//! you are willing to do that. Only run scripts trusted at least as much as
//! your configuration files.

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod engine;

mod console;
mod error;
mod func;
mod host;
mod namespace;
mod runtime;
mod serde;
mod snapshot;
mod value;
mod worker;

pub use console::Console;
pub use error::{JsError, JsErrorKind};
pub use func::{JsArgs, JsFn, JsFnOutput};
pub use host::{
    JsHostClass, JsHostClassBuilder, JsHostFn, JsHostFnMut, JsHostGetter, JsHostHandle,
    JsHostObject, JsHostObjectBuilder, JsHostSetter,
};
pub use namespace::JsNamespace;
pub use runtime::{IntoJsGlobal, JsGlobal, JsRuntime, JsRuntimeBuilder};
pub use serde::{Serde, SerdeOutput};
pub use snapshot::JsSnapshotLimits;
pub use value::{JsArg, JsArray, JsObject, JsStr, JsValue};
pub use worker::{JsWorker, JsWorkerBuilder};
