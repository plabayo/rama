use rama::error::BoxError;
use std::fmt;

#[derive(Debug)]
pub struct ErrorWithExitCode {
    pub error: BoxError,
    pub code: i32,
}

impl fmt::Display for ErrorWithExitCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error {} with OS exit code {}", self.error, self.code)
    }
}

impl std::error::Error for ErrorWithExitCode {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}
