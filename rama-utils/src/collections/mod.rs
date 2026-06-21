//! Collections such as [`NonEmptyVec`] and [`NonEmptySmallVec`] provided by rama,
//! mostly for internal usage, but available for others to use as well.

pub mod append_only_vec;
#[doc(inline)]
pub use append_only_vec::AppendOnlyVec;

/// Re-inserts the head of a non-empty collection into its already-sorted tail at
/// `index`, keeping the whole list sorted. Shared by the `sort*` methods of
/// [`NonEmptyVec`] and [`NonEmptySmallVec`], which compute `index` differently
/// but rotate the head into place identically.
macro_rules! place_sorted_head {
    ($self:ident, $index:expr) => {{
        let index = $index;
        if index != 0 {
            let new_head = $self.tail.remove(0);
            let head = ::core::mem::replace(&mut $self.head, new_head);
            $self.tail.insert(index - 1, head);
        }
    }};
}

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
    pub use crate::std::vec;
}

pub use smallvec;
