use std::fmt::Display;

mod backtrace;
mod context;

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
/// assert_eq!(error.to_string(), "whoops: Custom error");
/// ```
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
    fn test_wrapper_error_source() {
        let error = WrapperError(Box::new(CustomError))
            .context("foo")
            .backtrace();
        let source = std::error::Error::source(&error).unwrap();
        assert!(source.downcast_ref::<CustomError>().is_some());
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
