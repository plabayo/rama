//! Collections such as [`NonEmptyVec`] provided by rama,
//! mostly for internal usage, but available for others to use as well.

mod non_empty_vec;
#[doc(inline)]
pub use non_empty_vec::{NonEmptyVec, NonEmptyVecEmptyError, NonEmptyVecIter};

#[doc(inline)]
pub use crate::__non_empty_vec as non_empty_vec;

#[doc(hidden)]
pub mod __macro_support {
    pub use std::vec;
}
