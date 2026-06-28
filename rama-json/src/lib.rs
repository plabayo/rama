//! Streaming JSON tools for Rama.
//!
//! This crate is intentionally independent from HTTP. It provides a strict,
//! incremental JSON tokenizer and JSONPath building/parsing primitives that can
//! later be used by HTTP body layers, TCP stream tools, CLI output selectors,
//! and direct application code.
//!
//! The JSONPath syntax is based on RFC 9535. The first implementation slice
//! supports the selectors needed for exact paths and common wildcard matching;
//! the public AST is shaped so the remaining RFC features can be added without
//! changing the top-level API.

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod path;
pub mod rewrite;
pub mod select;
pub mod tokenizer;

mod error;

pub use error::{JsonError, JsonErrorKind};
