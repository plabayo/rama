/// A macro to create a new error from a string literal,
/// formatted string, or an existing error.
#[macro_export]
#[doc(hidden)]
macro_rules! __error {
    ($msg:literal $(,)?) => ({
        $crate::error::OpaqueError::from_display($msg)
    });
    ($fmt:literal, $($arg:tt),+ $(,)?) => ({
        $crate::error::OpaqueError::from_display(format!($fmt, $($arg)*))
    });
    ($err:expr $(,)?) => ({
        $crate::error::OpaqueError::from_std($err)
    });
}
