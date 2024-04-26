/// Construct an ad-hoc error from a string or existing error value.
///
/// This evaluates to an [`Error`][crate::error::Error]. It can take either just a
/// string, or a format string with arguments. It also can take any custom type
/// which implements `Debug` and `Display`.
///
/// If called with a single argument whose type implements `std::error::Error`
/// (in addition to `Debug` and `Display`, which are always required), then that
/// Error impl's `source` is preserved as the `source` of the resulting
/// [`crate::error::Error`].
///
/// # Example
///
/// ```
/// # type V = ();
/// #
/// use crate::error::{error, Result};
///
/// fn lookup(key: &str) -> Result<V> {
///     if key.len() != 16 {
///         return Err(error!("key length must be 16 characters, got {:?}", key));
///     }
///
///     // ...
///     # Ok(())
/// }
/// ```
#[macro_export]
#[doc(hidden)]
macro_rules! __error {
    ($msg:literal $(,)?) => {
        $crate::error::__private::must_use({
            let error = $crate::error::__private::format_err(std::format_args!($msg));
            error
        })
    };
    ($err:expr $(,)?) => {
        $crate::error::__private::must_use({
            use $crate::error::__private::kind::*;
            let error = match $err {
                error => (&error).anyhow_kind().new(error),
            };
            error
        })
    };
    ($fmt:expr, $($arg:tt)*) => {
        $crate::error::Error::msg(std::format!($fmt, $($arg)*))
    };
}
