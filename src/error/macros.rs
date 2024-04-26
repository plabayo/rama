/// A macro to create a new error from a string literal,
/// formatted string, or an existing error.
#[macro_export]
#[doc(hidden)]
macro_rules! __error {
    ($msg:literal $(,)?) => ({
        $crate::error::__private::str_error($msg)
    });
    ($fmt:literal, $($arg:tt),+ $(,)?) => ({
        $crate::error::__private::str_error(format!($fmt, $($arg)*))
    });
    ($err:expr $(,)?) => ({
        $crate::error::__private::error($err)
    });
}
