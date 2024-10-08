/// A macro to create a new error from a string literal,
/// formatted string, or an existing error.
///
/// See the [module level documentation](crate::error) for more information.
///
/// ## Examples
///
/// ```
/// use rama_error::error;
///
/// let err = error!("An error occurred");
/// let err = error!("An error occurred: {}", 42);
/// let err = error!(std::io::Error::new(std::io::ErrorKind::Other, "oh no!"));
/// ```
#[doc(hidden)]
#[macro_export]
macro_rules! __error {
    ($msg:literal $(,)?) => ({
        $crate::OpaqueError::from_display($msg)
    });
    ($fmt:literal, $($arg:tt),+ $(,)?) => ({
        $crate::OpaqueError::from_display(format!($fmt, $($arg)*))
    });
    ($err:expr $(,)?) => ({
        $crate::OpaqueError::from_std($err)
    });
}
pub use crate::__error as error;
