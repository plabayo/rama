#[doc(hidden)]
#[macro_export]
macro_rules! __static_str_error {
    (
        #[doc = $desc:literal]
        $(#[$m:meta])*
        pub struct $name:ident;
    ) => {
        $(#[$m])*
        #[derive(Debug, Default, Clone, PartialEq, Eq)]
        #[non_exhaustive]
        #[doc = $desc]
        pub struct $name;

        impl $name {
            #[doc = concat!("Create a new ", stringify!($name), ".")]
            #[inline(always)]
            #[must_use] pub const fn new() -> Self {
                Self
            }
        }

        impl std::fmt::Display for $name {
            #[inline(always)]
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, $desc)
            }
        }

        impl std::error::Error for $name {}
    }
}
#[doc(inline)]
pub use crate::__static_str_error as static_str_error;
