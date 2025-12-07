use std::fmt;

pub(super) trait ErrorIntoOutput<Error>: Send + Sync + 'static {
    type Output: Send + 'static;
    type Error: Send + 'static;

    fn error_into_output(&self, error: Error) -> Result<Self::Output, Self::Error>;
}

/// Wrapper around a user-specific transformer callback.
pub struct ErrorIntoOutputFn<F>(pub(super) F);

impl<F: fmt::Debug> fmt::Debug for ErrorIntoOutputFn<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ErrorIntoOutputFn").field(&self.0).finish()
    }
}

impl<F: Clone> Clone for ErrorIntoOutputFn<F> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<Output, ErrorIn, ErrorOut, F> ErrorIntoOutput<ErrorIn> for ErrorIntoOutputFn<F>
where
    F: Fn(ErrorIn) -> Result<Output, ErrorOut> + Send + Sync + 'static,
    Output: Send + 'static,
    ErrorOut: Send + Sync + 'static,
{
    type Output = Output;
    type Error = ErrorOut;

    fn error_into_output(&self, error: ErrorIn) -> Result<Self::Output, ErrorOut> {
        (self.0)(error)
    }
}
