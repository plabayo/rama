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
//! # Compilation startup
//!
//! The embedded WebAssembly engine component is compiled once per process,
//! with parallel compilation where the platform supports it. Applications can
//! call [`JsRuntime::warm_up`] during startup to move that work out of a
//! latency-sensitive first evaluation. The optional `disk-cache` feature adds
//! `JsRuntime::warm_up_with_disk_cache`, which can reuse compiled code across
//! process starts from an application-selected directory confined to a trusted
//! filesystem root.
//!
//! # Isolation and limits
//!
//! The JavaScript engine runs inside a private WebAssembly component with no
//! ambient WASI capabilities. WebAssembly stack checks contain recursive
//! parser, compiler, and runtime code; store memory limits bound the engine
//! heap; instruction fuel and epoch deadlines bound guest execution. A trap
//! poisons only that [`JsRuntime`], while the host process remains available.
//! With clock and entropy capabilities absent, `Date.now()` and `Math.random()`
//! are deterministic snapshot values rather than access to the host clock or
//! randomness. Register explicit host functions when a script should receive
//! either capability.
//!
//! Runtime limits ([`JsRuntimeBuilder`]) and snapshot limits
//! ([`JsSnapshotLimits`]) are still guardrails rather than a complete security
//! boundary. Wasmtime and the engine component are part of the trusted
//! computing base, and registered Rust host functions run outside WebAssembly:
//! fuel, epochs, and guest memory accounting cannot interrupt or contain a
//! blocking, panicking, or memory-hungry host callback.
//!
//! The opt-in
//! [execution time limit][JsRuntimeBuilder::set_execution_time_limit] adds a
//! wall-clock bound on guest execution, including parsing, compilation,
//! built-ins, bytecode, value conversion, and drained microtasks. The epoch
//! timer is coarse and a trap poisons the runtime. It does not run while Rust
//! host code is executing.
//!
//! The backstop for that is the [`JsWorker`] timeout, which abandons a
//! worker whose job overran (see [`JsWorker::is_abandoned`]) so callers get
//! an error instead of queueing behind work that may never finish. A guest
//! operation is eventually stopped by its runtime limits; a Rust host callback
//! which never returns can still strand the worker thread.

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
