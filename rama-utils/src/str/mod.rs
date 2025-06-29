//! string utilities

mod non_empty;
#[doc(inline)]
pub use non_empty::{EmptyStringErr, NonEmptyString};

mod search;
#[doc(inline)]
pub use search::{
    contains_any_ignore_ascii_case, contains_ignore_ascii_case, starts_with_ignore_ascii_case,
    submatch_any_ignore_ascii_case, submatch_ignore_ascii_case,
};

pub mod utf8;
