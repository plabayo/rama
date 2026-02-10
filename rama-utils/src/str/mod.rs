//! string utilities

mod non_empty;
#[doc(inline)]
pub use non_empty::{EmptyStrErr, NonEmptyStr};

#[doc(inline)]
pub use crate::__non_empty_str as non_empty_str;

pub use ::smol_str;

mod search;
#[doc(inline)]
pub use search::{
    any_contains_ignore_ascii_case, any_ends_with_ignore_ascii_case,
    any_starts_with_ignore_ascii_case, any_submatch_ignore_ascii_case, contains_ignore_ascii_case,
    ends_with_ignore_ascii_case, starts_with_ignore_ascii_case, submatch_ignore_ascii_case,
};

pub mod arcstr;
pub mod utf8;

#[cfg(not(target_os = "windows"))]
pub const NATIVE_NEWLINE: &str = "\n";

#[cfg(target_os = "windows")]
pub const NATIVE_NEWLINE: &str = "\r\n";
