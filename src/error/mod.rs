//! Error utilities for rama and its users.
//!
//! Errors in Rust are a bit ambiguous:
//!
//! - the infamous `Result<T, E>` is a type that can either be `Ok(T)` or `Err(E)`, where `E` is
//!   the error type in case something went wrong.
//! - the [`std::error::Error`] trait is a trait that represents errors that can be displayed and
//!   have a source (cause).
//!
//! The ambiguity comes from the fact that the [`std::error::Error`] trait is not required to be
//! implemented for the error type `E` in the `Result<T, E>` type. This means that one can have
//! a `Result<T, E>` where `E` is not an error type. A common example of something else it can be
//! is that it has the same type as the `T` type, which is not an error type. E.g. in case of a web
//! service middleware a firewall could return a 403 Http response as the `Err` variant of the
//! `Result<T, Response>`. Where `T` is most likely also a `Response` type. In which
//! case you might as well have `Result<Response, Infallible>`.
//!
//! Within Web Services we usually do not want an error type, as it does not make any sense.
//! This is because the server has to respond something (unless you simply want to kill the connection),
//! and so it makes much more sense to enforce the code type-wise to always return a response.
//!
//! The most tricky scenario, if you can call it that, is what to do for middleware services.
//! These situations are tricky because they can wrap any generic `S` type, where `S` is the
//! service type. This means that the error type can be anything, and so it is not possible to
//! create values of that type for scenarios where the error comes from the middleware itself.
//!
//! There are several possibilities here and we'll go over them next. But before we do that,
//! I do want to emphasise that while Rust's `Result<T, E>` does not enforce that `E` is an error
//! type, it is still a good practice to use an error type for the `E` type. And that is also
//! that as a rule of thumb we do in Rama.
//!
//! ## Type Erasure
//!
//! The [`BoxError`] type alias is a boxed Error trait object and can be used to represent any error that
//! implements the [`std::error::Error`] trait and is used for cases where it is usually not
//! that important what specific error type is returned, but rather that an error occurred.
//! Boxed errors do allow to _downcast_ to check for concrete error types, but this checks
//! only the top-level error and not the cause chain.
//!
//! ## Error Extension
//!
//! The [`ErrorExt`] trait provides a set of methods to work with errors. These methods are
//! implemented for all types that implement the [`std::error::Error`] trait. The methods are
//! used to add context to an error, add a backtrace to an error, and to convert an error into
//! an opaque error.
//!
//! ## Opaque Error
//!
//! The [`OpaqueError`] type is a type-erased error that can be used to represent any error
//! that implements the [`std::error::Error`] trait. Using the [`OpaqueError::from_display`]
//! you can even create errors from a displayable type.
//!
//! The other advantage of [`OpaqueError`] over [`BoxError`]
//! is that it is Sized and can be used in places where a `Sized`` type is required,
//! while [`BoxError`] is `?Sized` and can give you a hard time in certain scenarios.
//!
//! ## `error` macro
//!
//! The `error` macro is a convenient way to create an [`OpaqueError`]
//! from an error, format string or displayable type.
//!
//! ### `error` macro Example
//!
//! ```rust
//! use rama::error::{error, ErrorExt, OpaqueError};
//!
//! let error = error!("error").context("foo");
//! assert_eq!(error.to_string(), "foo: error");
//!
//! let error = error!("error {}", 404).context("foo");
//! assert_eq!(error.to_string(), "foo: error 404");
//!
//! #[derive(Debug)]
//! struct CustomError;
//!
//! impl std::fmt::Display for CustomError {
//!   fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
//!      write!(f, "entity not found")
//!   }
//! }
//!
//! impl std::error::Error for CustomError {}
//!
//! let error = error!(CustomError).context("foo");
//!
//! assert_eq!(error.to_string(), "foo: entity not found");
//! ```
//!
//! ## Error Context
//!
//! The [`ErrorContext`] allows you to add a context to [`Result`]
//! and [`Option`] types:
//!
//! - For [`Result`] types, the context is added to the error variant,
//!   turning `Result<T, E>` into `Result<T, OpaqueError>`;
//! - For [`Option`] types, the context is used as a DisplayError when
//!   the open is `None`, turning `Option<T>` into `Result<T, OpaqueError>`.
//!
//! This is useful when you want to add custom context.
//! And can also be combined with other [`ErrorExt`] methods,
//! such as [`ErrorExt::backtrace`] to add even more info to the error case,
//! if there is one.
//!
//! It is also an easy way to turn an option value into the inner value,
//! short-circuiting using `?` with the new context (Display) error
//! when the option was `None`.
//!
//! ### Error Context Example
//!
//! Option Example:
//!
//! ```rust
//! use rama::error::{ErrorContext, ErrorExt};
//!
//! let value = Some(42);
//! let value = match value.context("value is None") {
//!    Ok(value) => assert_eq!(value, 42),
//!    Err(error) => panic!("unexpected error: {error}"),
//! };
//!
//! let value: Option<usize> = None;
//! let result = value.context("value is None");
//! assert!(result.is_err());
//! ```
//!
//! Result Example:
//!
//! ```rust
//! use rama::error::{ErrorContext, ErrorExt, OpaqueError};
//!
//! let value: Result<_, OpaqueError> = Ok(42);
//! let value = match value.context("get the answer") {
//!   Ok(value) => assert_eq!(value, 42),
//!   Err(error) => panic!("unexpected error: {error}"),
//! };
//!
//! let value: Result<usize, _> = Err(OpaqueError::from_display("error"));
//! let result = value.context("get the answer");
//! assert!(result.is_err());
//! ```
//!
//! ## Error Composition
//!
//! Sometimes it can be useful to compose errors with more
//! expressive error types. In such cases [`OpaqueError`] is... too opaque.
//!
//! In an early design of Rama we considered adding a `compose_error` function macro
//! that would allow to create error types in a similar manner as [the `thiserror` crate](https://docs.rs/thiserror),
//! but we decided against it as it would be an abstraction too much.
//!
//! Rama was created to give developers the full power of the Rust language to develop
//! proxies, and by extension also web services and http clients. In a similar line of thought
//! it is also important that one has all tools available to create the error types for their purpose.
//!
//! As such, if you want your own custom error types we recommend just creating them
//! as you would any other type in Rust. The blog article <https://sabrinajewson.org/blog/errors>
//! gives a good overview and background on this topic.
//!
//! You can declare your own `macro_rules` in case there are common patterns for the services
//! and middlewares that you are writing for your project. For inspiration you can
//! see the http rejection macros we borrowed and modified from
//! [Axum's extract logic](https://github.com/tokio-rs/axum/blob/5201798d4e4d4759c208ef83e30ce85820c07baa/axum-core/src/macros.rs):
//! <https://github.com/plabayo/rama/blob/main/src/utils/macros/http_error.rs>
//!
//! And of course... if you really want, against our advice in,
//! you can use [the `thiserror` crate](https://docs.rs/thiserror),
//! or even [the `anyhow` crate](https://docs.rs/anyhow). All is possible.

use std::error::Error as StdError;

/// Alias for a type-erased error type.
///
/// See the [module level documentation](crate::error) for more information.
pub type BoxError = Box<dyn StdError + Send + Sync>;

mod ext;
pub use ext::{ErrorContext, ErrorExt, OpaqueError};

mod macros;
#[doc(inline)]
pub use crate::__error as error;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_macro_error_string() {
        let error = error!("error").context("foo");
        assert_eq!(error.to_string(), "foo: error");
    }

    #[test]
    fn test_macro_error_format_string() {
        let error = error!("error {}", 404).context("foo");
        assert_eq!(error.to_string(), "foo: error 404");
    }

    #[derive(Debug)]
    struct CustomError;

    impl std::fmt::Display for CustomError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "entity not found")
        }
    }

    impl std::error::Error for CustomError {}

    #[test]
    fn test_macro_error_from_error() {
        let error = error!(CustomError).context("foo");
        assert_eq!(error.to_string(), "foo: entity not found");
    }
}
