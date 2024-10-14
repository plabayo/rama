use std::fmt;

pub(super) trait ErrorIntoResponse<Error>: Send + Sync + 'static {
    type Response: Send + 'static;
    type Error: Send + Sync + 'static;

    fn error_into_response(&self, error: Error) -> Result<Self::Response, Self::Error>;
}

/// Wrapper around a user-specific transformer callback.
pub struct ErrorIntoResponseFn<F>(pub(super) F);

impl<F: fmt::Debug> fmt::Debug for ErrorIntoResponseFn<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ErrorIntoResponseFn").field(&self.0).finish()
    }
}

impl<F: Clone> Clone for ErrorIntoResponseFn<F> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<Response, ErrorIn, ErrorOut, F> ErrorIntoResponse<ErrorIn> for ErrorIntoResponseFn<F>
where
    F: Fn(ErrorIn) -> Result<Response, ErrorOut> + Send + Sync + 'static,
    Response: Send + 'static,
    ErrorOut: Send + Sync + 'static,
{
    type Response = Response;
    type Error = ErrorOut;

    fn error_into_response(&self, error: ErrorIn) -> Result<Self::Response, ErrorOut> {
        (self.0)(error)
    }
}
