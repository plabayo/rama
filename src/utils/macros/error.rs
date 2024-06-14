/// Private API.
#[doc(hidden)]
#[macro_export]
macro_rules! __static_str_error {
    (
        $(#[$m:meta])*
        pub struct $name:ident = $desc:literal;
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

        impl std::error::Error for $name {}
    }
}
