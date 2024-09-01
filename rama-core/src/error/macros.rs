/// A macro to create a new error from a string literal,
/// formatted string, or an existing error.
///
/// See the [module level documentation](crate::error) for more information.
///
/// ## Examples
///
/// ```
/// use rama::error::error;
///
/// let err = error!("An error occurred");
/// let err = error!("An error occurred: {}", 42);
/// let err = error!(std::io::Error::new(std::io::ErrorKind::Other, "oh no!"));
/// ```
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
