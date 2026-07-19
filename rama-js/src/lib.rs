//! Embedded JavaScript execution for Rama.
//!
//! This crate provides a small, engine-agnostic API to evaluate JavaScript:
//! a [`JsRuntime`] for one-off or repeated script execution on the current
//! thread, and a [`JsEngine`] — a cheap-to-clone `Send + Sync` handle which
//! builds a fresh, side-effect-free runtime per execution, for use within
//! services. Async execution uses Tokio's blocking executor; callers can
//! instead use the explicit blocking API with an executor of their choice.
//!
//! Host (FFI) functions are registered on the [`JsRuntimeBuilder`] with
//! extractor-style typed arguments (see [`JsFn`]), and values cross the
//! script boundary as engine-agnostic [`JsValue`]s.
//! Rust-owned resources can instead be exposed without conversion through a
//! runtime-local [`JsHostObject`], with typed methods and properties.
//!
//! The JS engine used is an implementation detail of this crate: no engine
//! types are exposed in the public API, so the engine can be swapped or made
//! pluggable without breaking changes.

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod engine;
mod handle;

mod console;
mod error;
mod func;
mod host;
mod namespace;
mod runtime;
mod serde;
mod snapshot;
mod value;

pub use console::Console;
pub use error::{JsError, JsErrorKind};
pub use func::{JsArgs, JsFn, JsFnOutput};
pub use handle::JsEngine;
pub use host::{
    JsHostFn, JsHostFnMut, JsHostGetter, JsHostHandle, JsHostObject, JsHostObjectBuilder,
    JsHostSetter,
};
pub use namespace::JsNamespace;
pub use runtime::{IntoJsGlobal, JsGlobal, JsRuntime, JsRuntimeBuilder};
pub use serde::{Serde, SerdeOutput};
pub use snapshot::JsSnapshotLimits;
pub use value::{JsArg, JsArray, JsObject, JsStr, JsValue};
