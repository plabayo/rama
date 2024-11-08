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
            pub fn new() -> Self {
                Self::default()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, $desc)
            }
        }

        impl std::error::Error for $name {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(self)
            }
        }
    }
}
#[doc(inline)]
pub use crate::__static_str_error as static_str_error;
