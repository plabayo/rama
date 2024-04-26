//! This module provides the [`Error`] type, a wrapper around a dynamic error type.
//!
//! Due to the limitations of auto-trait implementations, the [`Error`] type cannot
//! be automatically created using `From` or `Into` (?). Instead, the [`Error`]
//! constructors must be used or the [`ErrorContext`] extension trait.

use std::{
    fmt::{self, Debug, Display},
    ops::{Deref, DerefMut},
};

mod context;
use context::ContextError;
#[doc(inline)]
pub use context::ErrorContext;

mod wrapper;
use wrapper::{BoxedError, DisplayError, MessageError};

mod chain;
#[doc(inline)]
pub use chain::Chain;

pub use std::error::Error as StdError;

/// Type alias for a boxed standard lib error that's `Send + Sync + 'static`.
pub type BoxError = Box<dyn StdError + Send + Sync + 'static>;

mod kind;

mod macros;
#[doc(inline)]
pub use crate::__error as error;

/// `Result<T, Error>`
///
/// This is a reasonable return type to use throughout your application but also
/// for `fn main`; if you do, failures will be printed along with any
/// [context][ErrorContext] and a backtrace if one was captured.
///
/// `rama::error::Result` may be used with one *or* two type parameters.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Equivalent to Ok::<_, rama::error::Result>(value).
///
/// This simplifies creation of an rama::error::Result in places where type inference
/// cannot deduce the `E` type of the result &mdash; without needing to write
/// `Ok::<_, rama::error::Error>(value)`.
///
/// One might think that `rama::error::Result::Ok(value)` would work in such cases
/// but it does not.
///
/// ```console
/// error[E0282]: type annotations needed for `std::result::Result<i32, E>`
///   --> src/main.rs:11:13
///    |
/// 11 |     let _ = rama::error::Result::Ok(1);
///    |         -   ^^^^^^^^^^^^^^^^^^ cannot infer type for type parameter `E` declared on the enum `Result`
///    |         |
///    |         consider giving this pattern the explicit type `std::result::Result<i32, E>`, where the type parameter `E` is specified
/// ```
#[allow(non_snake_case)]
pub fn Ok<T>(t: T) -> Result<T> {
    Result::Ok(t)
}

/// The `Error` type, a wrapper around a dynamic error type.
pub struct Error {
    inner: BoxedError,
}

impl Error {
    /// Create a new error object from any error type.
    ///
    /// The error type must be threadsafe and `'static`, so that the `Error`
    /// will be as well.
    #[must_use]
    pub fn new<E>(error: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Error::from_std(error)
    }

    /// Create a new error object from a printable error message.
    #[must_use]
    pub fn msg<M>(message: M) -> Self
    where
        M: Display + Debug + Send + Sync + 'static,
    {
        Error::from_adhoc(message)
    }

    pub(crate) fn from_std<E>(error: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self {
            inner: BoxedError(Box::new(error)),
        }
    }

    pub(crate) fn from_boxed(error: impl Into<BoxError>) -> Self {
        Self {
            inner: BoxedError(error.into()),
        }
    }

    #[cold]
    pub(crate) fn from_adhoc<M>(message: M) -> Self
    where
        M: Display + Debug + Send + Sync + 'static,
    {
        let error = MessageError(message);
        Self {
            inner: BoxedError(Box::new(error)),
        }
    }

    #[cold]
    pub(crate) fn from_display<M>(message: M) -> Self
    where
        M: Display + Send + Sync + 'static,
    {
        let error = DisplayError(message);
        Self {
            inner: BoxedError(Box::new(error)),
        }
    }

    #[cold]
    pub(crate) fn from_context<C, E>(context: C, error: E) -> Self
    where
        C: Display + Send + Sync + 'static,
        E: StdError + Send + Sync + 'static,
    {
        let error: ContextError<C, E> = ContextError { context, error };
        Self {
            inner: BoxedError(Box::new(error)),
        }
    }

    /// Wrap the error value with additional context.
    ///
    /// For attaching context to a `Result` as it is propagated, the
    /// [`ErrorContext`] extension trait may be more convenient than
    /// this function.
    ///
    /// The primary reason to use `error.context(...)` instead of
    /// `result.context(...)` via the [`ErrorContext`] trait would be if the context
    /// needs to depend on some data held by the underlying error:
    ///
    /// ```
    /// # use std::fmt::{self, Debug, Display};
    /// #
    /// # type T = ();
    /// #
    /// # impl std::error::Error for ParseError {}
    /// # impl Debug for ParseError {
    /// #     fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
    /// #         unimplemented!()
    /// #     }
    /// # }
    /// # impl Display for ParseError {
    /// #     fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
    /// #         unimplemented!()
    /// #     }
    /// # }
    /// #
    /// use rama::error::Result;
    /// use std::fs::File;
    /// use std::path::Path;
    ///
    /// struct ParseError {
    ///     line: usize,
    ///     column: usize,
    /// }
    ///
    /// fn parse_impl(file: File) -> Result<T, ParseError> {
    ///     # const IGNORE: &str = stringify! {
    ///     ...
    ///     # };
    ///     # unimplemented!()
    /// }
    ///
    /// pub fn parse(path: impl AsRef<Path>) -> Result<T> {
    ///     let file = File::open(&path)?;
    ///     parse_impl(file).map_err(|error| {
    ///         let context = format!(
    ///             "only the first {} lines of {} are valid",
    ///             error.line, path.as_ref().display(),
    ///         );
    ///         rama::error::Error::new(error).context(context)
    ///     })
    /// }
    /// ```
    #[must_use]
    pub fn context<C>(self, context: C) -> Self
    where
        C: Display + Send + Sync + 'static,
    {
        let error: ContextError<C, Error> = ContextError {
            context,
            error: self,
        };
        Self {
            inner: BoxedError(Box::new(error)),
        }
    }

    /// An iterator of the chain of source errors contained by this Error.
    ///
    /// This iterator will visit every error in the cause chain of this error
    /// object, beginning with the error that this error object was created
    /// from.
    ///
    /// # Example
    ///
    /// ```
    /// use anyhow::Error;
    /// use std::io;
    ///
    /// pub fn underlying_io_error_kind(error: &Error) -> Option<io::ErrorKind> {
    ///     for cause in error.chain() {
    ///         if let Some(io_error) = cause.downcast_ref::<io::Error>() {
    ///             return Some(io_error.kind());
    ///         }
    ///     }
    ///     None
    /// }
    /// ```
    #[cold]
    pub fn chain(&self) -> Chain {
        Chain::new(self.inner.as_ref())
    }

    /// Returns true if `E` is the type held by this error object.
    ///
    /// Use [`chain()`][Error::chain] in case you also want to check this
    /// for any of the error's causes.
    pub fn is<E: StdError + Send + Sync + 'static>(&self) -> bool {
        self.inner.is::<E>()
    }

    /// Attempts to downcast the error object to a concrete type.
    pub fn downcast<E: StdError + Send + Sync + 'static>(self) -> Result<E> {
        self.inner
            .downcast()
            .map_err(|error| Error { inner: error })
    }

    /// Attempts to downcast the reference to this error object to a concrete type.
    ///
    /// Use [`chain()`][Error::chain] in case you want to do this for any of the error's causes.
    pub fn downcast_ref<E: StdError + Send + Sync + 'static>(&self) -> Option<&E> {
        self.inner.downcast_ref()
    }

    /// Attempts to downcast the exclusive reference to this error object to a concrete type.
    pub fn downcast_mut<E: StdError + Send + Sync + 'static>(&mut self) -> Option<&mut E> {
        self.inner.downcast_mut()
    }

    /// The lowest level cause of this error & this error's cause's
    /// cause's cause etc.
    ///
    /// The root cause is the last error in the iterator produced by
    /// [`chain()`][Error::chain].
    pub fn root_cause(&self) -> &(dyn StdError + 'static) {
        self.chain().last().unwrap()
    }
}

impl Deref for Error {
    type Target = dyn StdError + Send + Sync + 'static;

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl DerefMut for Error {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.deref_mut()
    }
}

impl Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.inner, formatter)
    }
}

impl Debug for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(&self.inner, formatter)
    }
}

impl<E> From<E> for Error
where
    E: StdError + Send + Sync + 'static,
{
    fn from(error: E) -> Self {
        Error::from_std(error)
    }
}

impl From<Error> for BoxError {
    fn from(error: Error) -> BoxError {
        error.inner.0
    }
}

// Not public API. Referenced by macro-generated code.
#[doc(hidden)]
pub mod __private {
    use super::Error;

    #[doc(hidden)]
    pub mod kind {
        #[doc(hidden)]
        pub use crate::error::kind::{AdhocKind, TraitKind};

        #[doc(hidden)]
        pub use crate::error::kind::BoxedKind;
    }

    #[doc(hidden)]
    #[inline]
    #[cold]
    pub fn format_err(args: std::fmt::Arguments) -> Error {
        let fmt_arguments_as_str = args.as_str();

        if let Some(message) = fmt_arguments_as_str {
            // error!("literal"), can downcast to &'static str
            Error::msg(message)
        } else {
            // error!("interpolate {var}"), can downcast to String
            Error::msg(std::fmt::format(args))
        }
    }

    #[doc(hidden)]
    #[inline]
    #[cold]
    #[must_use]
    pub fn must_use(error: Error) -> Error {
        error
    }
}
