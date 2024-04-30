use std::fmt::Display;

mod backtrace;
mod context;

mod chain;
pub use chain::Chain as ErrorChain;

mod wrapper;
pub use wrapper::OpaqueError;

/// Extends the `Result` and `Option` types with methods for adding context to errors.
///
/// See the [module level documentation](crate::error) for more information.
///
/// # Examples
///
/// ```
/// use rama::error::ErrorContext;
///
/// let result = "hello".parse::<i32>().context("parse integer");
/// assert_eq!("parse integer: invalid digit found in string", result.unwrap_err().to_string());
/// ```
pub trait ErrorContext: private::SealedErrorContext {
    /// The resulting contexct type after adding context to the contained error.
    type Context;

    /// Add a static context to the contained error.
    fn context<M>(self, context: M) -> Self::Context
    where
        M: Display + Send + Sync + 'static;

    /// Lazily add a context to the contained error, if it exists.
    fn with_context<C, F>(self, context: F) -> Self::Context
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C;
}

impl<T, E> ErrorContext for Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    type Context = Result<T, OpaqueError>;

    fn context<M>(self, context: M) -> Self::Context
    where
        M: Display + Send + Sync + 'static,
    {
        self.map_err(|error| error.context(context))
    }

    fn with_context<C, F>(self, context: F) -> Self::Context
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.map_err(|error| error.context(context()))
    }
}

impl<T> ErrorContext for Option<T> {
    type Context = Result<T, OpaqueError>;

    fn context<M>(self, context: M) -> Self::Context
    where
        M: Display + Send + Sync + 'static,
    {
        match self {
            Some(value) => Ok(value),
            None => Err(wrapper::MessageError("Option is None").context(context)),
        }
    }

    fn with_context<C, F>(self, context: F) -> Self::Context
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        match self {
            Some(value) => Ok(value),
            None => Err(wrapper::MessageError("Option is None").with_context(context)),
        }
    }
}

/// Extends the `Error` type with methods for working with errorss.
///
/// See the [module level documentation](crate::error) for more information.
///
/// # Examples
///
/// ```
/// use rama::error::{BoxError, ErrorExt, ErrorContext};
///
/// #[derive(Debug)]
/// struct CustomError;
///
/// impl std::fmt::Display for CustomError {
///  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
///    write!(f, "Custom error")
///  }
/// }
///
/// impl std::error::Error for CustomError {}
///
/// let error = CustomError.context("whoops");
/// let root_cause = error.root_cause();
/// assert!(root_cause.downcast_ref::<CustomError>().is_some());
pub trait ErrorExt: private::SealedErrorExt {
    /// Wrap the error in a context.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama::error::ErrorExt;
    ///
    /// let error = std::io::Error::new(std::io::ErrorKind::Other, "oh no!").context("do I/O");
    /// assert_eq!(error.to_string(), "do I/O: oh no!");
    /// ```
    fn context<M>(self, context: M) -> OpaqueError
    where
        M: Display + Send + Sync + 'static;

    /// Lazily wrap the error with a context.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama::error::ErrorExt;
    ///
    /// let error = std::io::Error::new(std::io::ErrorKind::Other, "oh no!").with_context(|| format!(
    ///    "do I/O ({})", 42,
    /// ));
    /// assert_eq!(error.to_string(), "do I/O (42): oh no!");
    /// ```
    fn with_context<C, F>(self, context: F) -> OpaqueError
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C;

    /// Add a [`Backtrace`][std::backtrace::Backtrace] to the error.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama::error::ErrorExt;
    ///
    /// let error = std::io::Error::new(std::io::ErrorKind::Other, "oh no!").backtrace();
    /// println!("{}", error);
    /// ```
    fn backtrace(self) -> OpaqueError;

    /// Convert the error into an [`OpaqueError`].
    ///
    /// # Examples
    ///
    /// ```
    /// use rama::error::ErrorExt;
    ///
    /// let error = std::io::Error::new(std::io::ErrorKind::Other, "oh no!").into_opaque();
    /// assert_eq!(error.to_string(), "oh no!");
    /// ```
    fn into_opaque(self) -> OpaqueError;

    /// Iterate over the chain of errors.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama::error::ErrorExt;
    ///
    /// let error = std::io::Error::new(std::io::ErrorKind::Other, "oh no!").context("do I/O");
    ///
    /// for cause in error.chain() {
    ///    if cause.downcast_ref::<std::io::Error>().is_some() {
    ///       println!("I/O error: {}", cause);
    ///    }
    /// }
    /// ```
    ///
    /// # Remarks
    ///
    /// The error chain logic relies on the [`Error::source`](std::error::Error::source) method to
    /// traverse the chain of errors:
    ///
    /// - if the error does not implement the `source` method it will not work for _that_ error type;
    /// - the meaning of [`Error::source`](std::error::Error::source) is not well defined and
    ///   even within the standard library it is not uncommon for an error to call source on the inner error,
    ///   which can lead to some error types being skipped. This is [by design](https://github.com/rust-lang/rust/pull/124536#issuecomment-2084667289),
    ///   and behaviour that must be taken into account in case you rely on [`ErrorChain`] for some of your error handling.
    fn chain(&self) -> ErrorChain<'_>;

    /// Tries to get the most top level error cause of the given type.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama::error::{BoxError, ErrorExt};
    ///
    /// #[derive(Debug)]
    /// struct CustomError;
    ///
    /// impl std::fmt::Display for CustomError {
    ///    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    ///        write!(f, "Custom error")
    ///    }
    /// }
    ///
    /// impl std::error::Error for CustomError {}
    ///
    /// #[derive(Debug)]
    /// struct WrapperError(BoxError);
    ///
    /// impl std::fmt::Display for WrapperError {
    ///    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    ///        write!(f, "Wrapper error")
    ///    }
    /// }
    ///
    /// impl std::error::Error for WrapperError {
    ///    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    ///        Some(self.0.as_ref())
    ///    }
    /// }
    ///
    /// let error = CustomError.context("whoops");
    /// let opaque = WrapperError(Box::new(error)).into_opaque();
    ///
    /// assert!(opaque.has_error::<CustomError>().is_some());
    /// assert!(opaque.has_error::<WrapperError>().is_some());
    /// ```
    fn has_error<E>(&self) -> Option<&E>
    where
        E: std::error::Error + 'static,
    {
        self.chain()
            .rev()
            .find_map(|error| error.downcast_ref::<E>())
    }

    /// Get the root cause of the error.
    ///
    /// # Examples
    ///
    /// ```
    /// use rama::error::{BoxError, ErrorExt};
    ///
    /// #[derive(Debug)]
    /// struct CustomError;
    ///
    /// impl std::fmt::Display for CustomError {
    ///    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    ///        write!(f, "Custom error")
    ///    }
    /// }
    ///
    /// impl std::error::Error for CustomError {}
    ///
    /// #[derive(Debug)]
    /// struct WrapperError(BoxError);
    ///
    /// impl std::fmt::Display for WrapperError {
    ///    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    ///        write!(f, "Wrapper error")
    ///    }
    /// }
    ///
    /// impl std::error::Error for WrapperError {
    ///    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    ///        Some(self.0.as_ref())
    ///    }
    /// }
    ///
    /// let error = CustomError.context("whoops");
    /// let opaque = WrapperError(Box::new(error)).into_opaque();
    ///
    /// assert!(opaque.root_cause().downcast_ref::<CustomError>().is_some());
    /// ```
    fn root_cause(&self) -> &(dyn std::error::Error + 'static) {
        self.chain().last().unwrap()
    }
}

impl<Error: std::error::Error + Send + Sync + 'static> ErrorExt for Error {
    fn context<M>(self, context: M) -> OpaqueError
    where
        M: Display + Send + Sync + 'static,
    {
        OpaqueError::from_std(context::ContextError {
            context,
            error: self,
        })
    }

    fn with_context<C, F>(self, context: F) -> OpaqueError
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        OpaqueError::from_std(context::ContextError {
            context: context(),
            error: self,
        })
    }

    fn backtrace(self) -> OpaqueError {
        OpaqueError::from_std(backtrace::BacktraceError::new(self))
    }

    fn into_opaque(self) -> OpaqueError {
        OpaqueError::from_std(self)
    }

    fn chain(&self) -> ErrorChain<'_> {
        ErrorChain::new(self)
    }
}

mod private {
    pub trait SealedErrorContext {}

    impl<T, E> SealedErrorContext for Result<T, E> where E: std::error::Error + Send + Sync + 'static {}
    impl<T> SealedErrorContext for Option<T> {}

    pub trait SealedErrorExt {}

    impl<Error: std::error::Error + Send + Sync + 'static> SealedErrorExt for Error {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BoxError;

    #[test]
    fn message_error_context() {
        let error = wrapper::MessageError("foo").context("context");
        assert_eq!(error.to_string(), "context: foo");
    }

    #[test]
    fn box_error_context() {
        let error = Box::new(wrapper::MessageError("foo"));
        let error = error.context("context");
        assert_eq!(error.to_string(), "context: foo");
    }

    #[derive(Debug)]
    struct CustomError;

    impl std::fmt::Display for CustomError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "Custom error")
        }
    }

    impl std::error::Error for CustomError {}

    #[derive(Debug)]
    struct WrapperError(BoxError);

    impl std::fmt::Display for WrapperError {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "Wrapper error")
        }
    }

    impl std::error::Error for WrapperError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self.0.as_ref())
        }
    }

    #[test]
    fn context_opaque_custom_error_has() {
        let error = WrapperError(Box::new(CustomError.context("context"))).into_opaque();
        assert!(error.has_error::<CustomError>().is_some());
        assert!(error.has_error::<WrapperError>().is_some());
        assert!(error.has_error::<OpaqueError>().is_some());
        assert!(error.has_error::<std::io::Error>().is_none());
    }

    #[test]
    fn custom_error_root_cause() {
        let error = CustomError;
        let root_cause = error.root_cause();
        assert!(root_cause.is::<CustomError>());
    }

    #[test]
    fn custom_error_context_chain_len() {
        let error = CustomError.context("context");
        let n = error.chain().count();
        assert_eq!(3, n);
    }

    #[test]
    fn custom_error_context_context_context_chain_len() {
        //...........................1.......+.....2.......+.......2......+......2
        let error = CustomError.context("a").context("b").context("c");
        let n = error.chain().count();
        assert_eq!(7, n);
    }

    #[test]
    fn custom_error_context_root_cause_downcast() {
        let error = CustomError.context("context");
        let root_cause = error.root_cause();
        assert!(root_cause.downcast_ref::<CustomError>().is_some());
    }

    #[test]
    fn custom_error_context_context_context_root_cause_downcast() {
        let error = CustomError.context("a").context("b").context("c");
        let root_cause = error.root_cause();
        assert!(root_cause.downcast_ref::<CustomError>().is_some());
    }

    #[test]
    fn custom_error_into_opaque() {
        let error = CustomError;
        let opaque = error.into_opaque();
        assert_eq!(opaque.to_string(), "Custom error");

        let root_cause = opaque.root_cause();
        assert!(root_cause.downcast_ref::<CustomError>().is_some());
    }

    #[test]
    fn custom_error_backtrace() {
        let error = CustomError;
        let error = error.backtrace();

        assert!(error
            .to_string()
            .starts_with("Initial error: Custom error\nError context:\n"));
    }
}
