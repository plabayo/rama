//! Collections such as [`NonEmptyVec`] and [`NonEmptySmallVec`] provided by rama,
//! mostly for internal usage, but available for others to use as well.

pub mod append_only_vec;
#[doc(inline)]
pub use append_only_vec::AppendOnlyVec;

mod non_empty_vec;
#[doc(inline)]
pub use non_empty_vec::{NonEmptyVec, NonEmptyVecEmptyError, NonEmptyVecIter};

mod non_empty_small_vec;
#[doc(inline)]
pub use non_empty_small_vec::{NonEmptySmallVec, NonEmptySmallVecEmptyError, NonEmptySmallVecIter};

#[doc(inline)]
pub use crate::__non_empty_vec as non_empty_vec;

#[doc(inline)]
pub use crate::__non_empty_smallvec as non_empty_smallvec;

#[doc(hidden)]
pub mod __macro_support {
    pub use std::vec;
}

pub use smallvec;
