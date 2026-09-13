#[doc(hidden)]
#[macro_export]
macro_rules! __static_str_error {
    (
        #[doc = $desc:literal]
        $(#[$m:meta])*
        $vis:vis struct $name:ident;
    ) => {
        $(#[$m])*
        #[derive(Debug, Default, Clone, PartialEq, Eq)]
        #[non_exhaustive]
        #[doc = $desc]
        $vis struct $name;

        impl $name {
            #[doc = concat!("Create a new ", stringify!($name), ".")]
            #[inline(always)]
            #[must_use] $vis const fn new() -> Self {
                Self
            }
        }

        impl core::fmt::Display for $name {
            #[inline(always)]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, $desc)
            }
        }

        impl core::error::Error for $name {}
    }
}
#[doc(inline)]
pub use crate::__static_str_error as static_str_error;

#[cfg(test)]
mod tests {
    mod scoped {
        crate::macros::error::static_str_error! {
            #[doc = "restricted error"]
            #[derive(Copy)]
            pub(super) struct RestrictedError;
        }

        crate::macros::error::static_str_error! {
            #[doc = "crate error"]
            #[derive(Copy)]
            pub(crate) struct CrateError;
        }
    }

    #[test]
    fn static_errors_support_private_and_restricted_visibility() {
        crate::macros::error::static_str_error! {
            #[doc = "private error"]
            #[derive(Copy)]
            struct PrivateError;
        }

        fn check<T: core::error::Error + Default + Copy + Eq>(error: T, message: &str) {
            assert_eq!(error, T::default());
            assert_eq!(error.to_string(), message);
            assert!(error.source().is_none());
        }

        const PRIVATE: PrivateError = PrivateError::new();
        check(PRIVATE, "private error");
        check(scoped::RestrictedError::new(), "restricted error");
        check(scoped::CrateError::new(), "crate error");
    }
}
