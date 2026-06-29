//! Streaming JSON tools for Rama.
//!
//! This crate is intentionally independent from HTTP. It provides a strict,
//! incremental JSON tokenizer and JSONPath building/parsing primitives used by
//! HTTP body layers, TCP stream tools, CLI output selectors, and direct
//! application code.
//!
//! The JSONPath syntax is based on RFC 9535. Rama supports the RFC selectors
//! that can be matched from a forward streaming value path: member selectors,
//! non-negative array indexes, positive array slices, wildcards, selector
//! lists, and descendant segments. Filters and negative/end-relative array
//! selectors are intentionally rejected until a buffered/evaluated mode can
//! implement their full semantics.

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod capture;
pub mod path;
pub mod rewrite;
pub mod select;
pub mod tokenizer;

mod error;

pub use error::{JsonError, JsonErrorKind};
