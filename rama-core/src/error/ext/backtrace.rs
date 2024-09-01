use std::{
    backtrace::Backtrace,
    error::Error,
    fmt::{Debug, Display},
};

/// An error type that contains a backtrace.
pub(crate) struct BacktraceError<E> {
    inner: E,
    backtrace: Backtrace,
}

impl<E> BacktraceError<E> {
    /// Create a new backtrace error.
    pub(crate) fn new(inner: E) -> Self {
        Self {
            inner,
            backtrace: Backtrace::capture(),
        }
    }
}

impl<E: Error> Display for BacktraceError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Initial error\r\n ↪ {:}\r\n============================\r\n",
            self.inner
        )?;
        write!(
            f,
            " ⇒ backtrace: {:}\r\n============================\r\n",
            self.backtrace
        )
    }
}

impl<E: Error> Debug for BacktraceError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <Self as Display>::fmt(self, f)
    }
}

impl<E: Error + 'static> Error for BacktraceError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.inner.source()
    }
}
