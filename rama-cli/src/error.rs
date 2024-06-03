//! Error utilities

use rama::error::BoxError;

#[derive(Debug)]
/// Error with an exit code
pub struct ErrorWithExitCode {
    code: i32,
    error: BoxError,
}

impl ErrorWithExitCode {
    /// Create a new error with an exit code
    pub fn new(code: i32, error: impl Into<BoxError>) -> Self {
        Self {
            code,
            error: error.into(),
        }
    }

    /// Get the exit error code
    pub fn exit_code(&self) -> i32 {
        self.code
    }
}

impl From<BoxError> for ErrorWithExitCode {
    fn from(error: BoxError) -> Self {
        Self { code: 1, error }
    }
}

impl std::fmt::Display for ErrorWithExitCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.error)
    }
}

impl std::error::Error for ErrorWithExitCode {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}
