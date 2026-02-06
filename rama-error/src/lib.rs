//! Error utilities for Rama and its users.
//!
//! This crate is used by the end user `rama` crate and by developers building on
//! top of Rama.
//!
//! Learn more about Rama:
//!
//! - GitHub: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>
//!
//! # Errors in Rust
//!
//! Rust has two closely related concepts that are both often called errors:
//!
//! - `Result<T, E>` is a control flow type that represents either success (`Ok(T)`)
//!   or failure (`Err(E)`).
//! - [`std::error::Error`] is a trait for values that can be displayed and can
//!   reference a source error.
//!
//! `Result<T, E>` does not require `E` to implement [`std::error::Error`]. This
//! means `Err(E)` is not always an error in the semantic sense.
//!
//! A common example is web middleware that uses `Result<Response, Response>`,
//! where the `Err` value is an early response such as a 403, not a failure. In
//! such cases, the `Err` value is not an error at all.
//!
//! In Rama we try to avoid that ambiguity. As a rule of thumb, if something is an
//! error, it should behave like one. That becomes most relevant in generic
//! middleware, where the wrapped service `S` can have any error type. Middleware
//! needs a way to report its own failures even when it cannot construct values of
//! the wrapped error type.
//!
//! This crate provides the building blocks to handle those situations in a
//! principled and ergonomic way.
//!
//! # Type erasure
//!
//! The [`BoxError`] type alias is a boxed `std::error::Error` trait object.
//!
//! It is used when the concrete error type is not important, only the fact that
//! an error occurred. This is useful at abstraction boundaries such as middleware
//! layers and public APIs.
//!
//! Boxed errors can be downcast to inspect their concrete type, but only at the
//! top level. Downcasting does not walk the error source chain.
//!
//! # Error extension
//!
//! The [`ErrorExt`] trait provides extension methods for working with errors.
//! These methods are implemented for all types that can be converted into a
//! [`BoxError`].
//!
//! The provided methods allow you to enrich errors with:
//!
//! - additional context values via [`ErrorExt::context`]
//! - structured key value context via [`ErrorExt::context_field`]
//! - lazy variants to avoid computing context unless needed via
//!   [`ErrorExt::with_context`] and [`ErrorExt::with_context_field`]
//! - a captured backtrace via [`ErrorExt::backtrace`]
//!
//! Context is stored as fields and rendered in a log friendly key value style.
//! Values are always quoted and escaped to avoid ambiguity in logs, even if the
//! value contains whitespace, commas, or newlines.
//!
//! # Error context on `Result` and `Option`
//!
//! The [`ErrorContext`] trait extends [`Result`] and [`Option`] with methods for
//! attaching context at the call site.
//!
//! - For `Result<T, E>`, context is added to the error variant, producing
//!   `Result<T, BoxError>`.
//! - For `Option<T>`, `None` is converted into an error, also producing
//!   `Result<T, BoxError>`.
//!
//! Context can be added as an unkeyed value or as a keyed field, and it can be
//! added eagerly or lazily.
//!
//! This makes it easy to keep errors lightweight at the source while still
//! attaching useful information at higher layers. It also enables idiomatic use
//! of the `?` operator to short circuit with a context enriched error.
//!
//! ## Error context examples
//!
//! ### Option examples
//!
//! ```rust
//! use rama_error::{ErrorContext, ErrorExt};
//!
//! # fn main() -> Result<(), rama_error::BoxError> {
//! let value = Some(42);
//! let value = value.context("value is None")?;
//! assert_eq!(value, 42);
//!
//! let value: Option<usize> = None;
//! let err = value.context_field("missing", "answer").unwrap_err();
//! assert!(format!("{err}").contains(r#"missing="answer""#));
//! # Ok(())
//! # }
//! ```
//!
//! ### Result examples
//!
//! ```rust
//! use rama_error::{ErrorContext, ErrorExt};
//!
//! fn parse(input: &str) -> Result<usize, std::num::ParseIntError> {
//!     input.parse()
//! }
//!
//! # fn main() -> Result<(), rama_error::BoxError> {
//! let value = parse("42").context("parsing answer")?;
//! assert_eq!(value, 42);
//!
//! let err = parse("nope")
//!     .context_field("input", "nope")
//!     .with_context(|| "expected a number")
//!     .unwrap_err();
//!
//! let s = format!("{err}");
//! assert!(s.contains(r#"input="nope""#));
//! assert!(s.contains(r#""expected a number""#));
//! # Ok(())
//! # }
//! ```
//!
//! # Backtraces
//!
//! [`ErrorExt::backtrace`] captures a [`std::backtrace::Backtrace`] at the point
//! it is called and wraps the error with it.
//!
//! In normal formatting the error prints as the underlying error.
//! In alternate formatting (`{:#}`) the backtrace is included.
//!
//! ```rust
//! use rama_error::ErrorExt;
//!
//! let err = std::io::Error::other("boom")
//!     .context_field("path", "/tmp/data")
//!     .backtrace();
//!
//! assert_eq!(format!("{err}"), "boom | path=\"/tmp/data\"");
//! let pretty = format!("{err:#}");
//! assert!(pretty.contains("Backtrace:"));
//! ```
//!
//! # Error composition
//!
//! In some cases it is useful to model failures using explicit, domain specific
//! error types. Rama does not impose a specific strategy here.
//!
//! If you need custom error types, define them as regular Rust types and implement
//! [`std::error::Error`] for them. The article <https://sabrinajewson.org/blog/errors>
//! provides an excellent overview of modern error design in Rust.
//!
//! For repeated patterns, `macro_rules` macros can be a good fit. As inspiration,
//! you can look at the HTTP rejection macros used in Rama, which are derived from
//! Axum's extract logic:
//!
//! <https://github.com/plabayo/rama/blob/main/rama-http/src/utils/macros/http_error.rs>
//!
//! You can also use crates like [`thiserror`](https://docs.rs/thiserror) or
//! [`anyhow`](https://docs.rs/anyhow) if they fit your project.

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

use std::error::Error as StdError;

/// Alias for a type-erased error type.
///
/// See the [module level documentation](crate) for more information.
pub type BoxError = Box<dyn StdError + Send + Sync>;

mod ext;
pub use ext::{ErrorContext, ErrorExt};
