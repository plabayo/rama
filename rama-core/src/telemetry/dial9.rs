//! [dial9] runtime telemetry — building blocks for defining custom events.
//!
//! Behind the `dial9` cargo feature, this module is a transparent
//! re-export of the [`dial9-trace-format`] crate so other rama crates and
//! consumer code can define [`TraceEvent`] types without taking a direct
//! dependency on dial9.
//!
//! Enabling this feature alone does **not** require `tokio_unstable`. Only
//! consumers that wire a real [`dial9-tokio-telemetry::TracedRuntime`] into
//! their runtime — so that recording the events actually emits something —
//! need that flag.
//!
//! ## How sub-crates use it
//!
//! The `#[derive(TraceEvent)]` proc macro generates code that references
//! `::dial9_trace_format::...` paths absolutely. To avoid every rama
//! sub-crate adding a direct dependency, sub-crates that opt into `dial9`
//! re-alias this module as `dial9_trace_format` at their own crate root:
//!
//! ```ignore
//! #[cfg(feature = "dial9")]
//! #[doc(hidden)]
//! pub use ::rama_core::telemetry::dial9 as dial9_trace_format;
//! ```
//!
//! With that in place, the derive's generated `::dial9_trace_format::*`
//! paths resolve to this re-export.
//!
//! ## Why expose dial9 from rama
//!
//! Defining flow / connection / handshake events across the rama crate
//! family in a single, self-describing trace format makes downstream
//! analysis (with `dial9-viewer` or custom tools) materially easier than
//! re-encoding the same fields per crate. The events become a stable
//! observability surface that consumers can opt into.
//!
//! [dial9]: https://github.com/dial9-rs/dial9-tokio-telemetry
//! [`dial9-trace-format`]: https://docs.rs/dial9-trace-format
//! [`dial9-tokio-telemetry::TracedRuntime`]: https://docs.rs/dial9-tokio-telemetry

#[doc(inline)]
pub use ::dial9_trace_format::*;
