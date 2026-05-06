//! [dial9] runtime telemetry — building blocks for defining custom events.
//!
//! Behind the `dial9` cargo feature, this module re-exports the
//! [`dial9-trace-format`] crate as the [`trace_format`] sub-module so
//! other rama crates and consumer code can refer to its items via
//! `rama_core::telemetry::dial9::trace_format::*` instead of taking a
//! direct dependency on `dial9-trace-format` for trait/type imports.
//!
//! Enabling this feature alone does **not** require `tokio_unstable`. Only
//! consumers that wire a real [`dial9-tokio-telemetry::TracedRuntime`] into
//! their runtime — so that recording the events actually emits something —
//! need that flag.
//!
//! ## Caveat: the `#[derive(TraceEvent)]` proc macro
//!
//! The upstream derive currently emits absolute `::dial9_trace_format::*`
//! paths which Rust's resolver only honors when that crate is a direct
//! dependency. Until the derive grows a `crate = "..."` attribute (PR
//! pending upstream), every crate that uses `#[derive(TraceEvent)]` still
//! needs its own (optional) direct dep on `dial9-trace-format`. The
//! [`trace_format`] re-export here is for trait references, type
//! annotations, and manual `TraceEvent` implementations — those *do* go
//! through this path.
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
pub use ::dial9_trace_format as trace_format;
