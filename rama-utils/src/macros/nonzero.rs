/// Construct a nonzero integer from a constant expression, checked at compile time.
///
/// The integer type can be inferred from context or specified with a suffix. A zero value
/// or a runtime expression is a compile error; use `NonZero::new` for runtime input.
#[macro_export]
#[doc(hidden)]
macro_rules! __nonzero {
    ($value:expr $(,)?) => {
        const {
            match ::core::num::NonZero::new($value) {
                ::core::option::Option::Some(value) => value,
                ::core::option::Option::None => {
                    ::core::panic!("nonzero! requires a nonzero constant")
                }
            }
        }
    };
}

#[doc(inline)]
pub use crate::__nonzero as nonzero;
