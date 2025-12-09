pub(super) trait ErrorIntoOutput<Error>: Send + Sync + 'static {
    type Output: Send + 'static;
    type Error: Send + 'static;

    fn error_into_output(&self, error: Error) -> Result<Self::Output, Self::Error>;
}

/// Wrapper around a user-specific transformer callback.
#[derive(Debug, Clone)]
pub struct ErrorIntoOutputFn<F>(pub(super) F);

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
