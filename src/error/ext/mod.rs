use std::fmt::Display;

mod chain;
mod context;

mod wrapper;
pub use wrapper::BoxedError;
pub(crate) use wrapper::MessageError;

/// Extends the `Result` and `Option` types with methods for adding context to errors.
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
    type Context = Result<T, BoxedError>;

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
    type Context = Result<T, BoxedError>;

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
    fn context<M>(self, context: M) -> BoxedError
    where
        M: Display + Send + Sync + 'static;

    /// Lazily wrap the error with a context.
    fn with_context<C, F>(self, context: F) -> BoxedError
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C;

    /// Iterate over the chain of errors.
    fn chain(&self) -> impl Iterator<Item = &(dyn std::error::Error + 'static)>;

    /// Get the root cause of the error.
    fn root_cause(&self) -> &(dyn std::error::Error + 'static) {
        self.chain().last().unwrap()
    }
}

impl<Error: std::error::Error + Send + Sync + 'static> ErrorExt for Error {
    fn context<M>(self, context: M) -> BoxedError
    where
        M: Display + Send + Sync + 'static,
    {
        BoxedError::from_std(context::ContextError {
            context,
            error: self,
        })
    }

    fn with_context<C, F>(self, context: F) -> BoxedError
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        BoxedError::from_std(context::ContextError {
            context: context(),
            error: self,
        })
    }

    fn chain(&self) -> impl Iterator<Item = &(dyn std::error::Error + 'static)> {
        chain::Chain::new(self)
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
        assert_eq!(2, n);
    }

    #[test]
    fn custom_error_context_context_context_chain_len() {
        let error = CustomError.context("a").context("b").context("c");
        let n = error.chain().count();
        assert_eq!(4, n);
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
}
