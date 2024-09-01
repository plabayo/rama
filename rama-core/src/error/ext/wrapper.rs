use crate::error::BoxError;
use std::fmt::{self, Debug, Display};

#[repr(transparent)]
/// A type-erased error type that can be used as a trait object.
///
/// Note this type is not intended to be used directly,
/// it is used by `rama` to hide the concrete error type.
///
/// See the [module level documentation](crate::error) for more information.
pub struct OpaqueError(BoxError);

impl OpaqueError {
    /// create an [`OpaqueError`] from an std error
    pub fn from_std(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(Box::new(error))
    }

    /// create an [`OpaqueError`] from a display object
    pub fn from_display(msg: impl Display + Debug + Send + Sync + 'static) -> Self {
        Self::from_std(MessageError(msg))
    }

    /// create an [`OpaqueError`] from a boxed error
    pub fn from_boxed(inner: BoxError) -> Self {
        Self(inner)
    }

    /// Returns true if the underlying error is of type `T`.
    pub fn is<T>(&self) -> bool
    where
        T: std::error::Error + 'static,
    {
        self.0.is::<T>()
    }

    /// Consumes the [`OpaqueError`] and returns it as a [`BoxError`].
    pub fn into_boxed(self) -> BoxError {
        self.0
    }

    /// Attempts to downcast the error to the concrete type `T`.
    pub fn downcast<T>(self) -> Result<T, Self>
    where
        T: std::error::Error + 'static,
    {
        match self.0.downcast::<T>() {
            Ok(error) => Ok(*error),
            Err(inner) => Err(Self(inner)),
        }
    }

    /// Attempts to downcast the error to a shared reference
    /// of the concrete type `T`.
    pub fn downcast_ref<T>(&self) -> Option<&T>
    where
        T: std::error::Error + 'static,
    {
        self.0.downcast_ref()
    }

    /// Attempts to downcast the error to the exclusive reference
    /// of the concrete type `T`.
    pub fn downcast_mut<T>(&mut self) -> Option<&mut T>
    where
        T: std::error::Error + 'static,
    {
        self.0.downcast_mut()
    }
}

impl Debug for OpaqueError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl Display for OpaqueError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl std::error::Error for OpaqueError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl From<BoxError> for OpaqueError {
    fn from(error: BoxError) -> Self {
        Self(error)
    }
}

#[repr(transparent)]
/// An error type that wraps a message.
pub(crate) struct MessageError<M>(pub(crate) M);

impl<M> Debug for MessageError<M>
where
    M: Display + Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl<M> Display for MessageError<M>
where
    M: Display + Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<M> std::error::Error for MessageError<M> where M: Display + Debug + 'static {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct CustomError(usize);

    impl Display for CustomError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Custom error ({})", self.0)
        }
    }

    impl std::error::Error for CustomError {}

    #[test]
    fn opaque_error_is() {
        let error = OpaqueError::from_std(CustomError(1));
        assert!(error.is::<CustomError>());
    }

    #[test]
    fn opaque_error_is_not() {
        let error = OpaqueError::from_display("hello");
        assert!(!error.is::<CustomError>());
    }

    #[test]
    fn opaque_error_downcast() {
        let error = OpaqueError::from_std(CustomError(2));
        let custom_error = error.downcast::<CustomError>().unwrap();
        assert_eq!(custom_error.0, 2);
    }

    #[test]
    fn opaque_error_downcast_fail() {
        let error = OpaqueError::from_display("hello");
        assert!(error.downcast::<CustomError>().is_err());
    }

    #[test]
    fn opaque_error_downcast_ref() {
        let error = OpaqueError::from_std(CustomError(3));
        let custom_error = error.downcast_ref::<CustomError>().unwrap();
        assert_eq!(custom_error.0, 3);
    }

    #[test]
    fn opaque_error_downcast_ref_fail() {
        let error = OpaqueError::from_display("hello");
        assert!(error.downcast_ref::<CustomError>().is_none());
    }

    #[test]
    fn opaque_error_downcast_mut() {
        let error = {
            let mut error = OpaqueError::from_std(CustomError(4));
            error.downcast_mut::<CustomError>().unwrap().0 = 42;
            error
        };

        let custom_error = error.downcast_ref::<CustomError>().unwrap();
        assert_eq!(custom_error.0, 42);
    }

    #[test]
    fn opaque_error_downcast_mut_fail() {
        let mut error = OpaqueError::from_display("hello");
        assert!(error.downcast_mut::<CustomError>().is_none());
    }
}
