//! string utilities

mod non_empty;
#[doc(inline)]
pub use non_empty::{EmptyStrErr, NonEmptyStr};

mod encoding;
#[doc(inline)]
pub use encoding::{decode_utf8_or_latin1, decode_utf8_or_latin1_owned};

#[doc(inline)]
pub use crate::__non_empty_str as non_empty_str;

pub use ::smol_str;

mod search;
#[doc(inline)]
pub use search::{
    any_contains_ignore_ascii_case, any_ends_with_ignore_ascii_case,
    any_starts_with_ignore_ascii_case, any_submatch_ignore_ascii_case, cmp_ignore_ascii_case,
    contains_ignore_ascii_case, ends_with_ignore_ascii_case, eq_ignore_ascii_case,
    eq_ignore_ascii_kebab_case, starts_with_ignore_ascii_case, submatch_ignore_ascii_case,
};

mod trim;
#[doc(inline)]
pub use trim::{trim_ascii_quotes_non_empty, trim_non_empty};

pub mod arcstr;
pub mod utf8;

#[cfg(not(target_os = "windows"))]
#[cfg_attr(docsrs, doc(cfg(not(target_os = "windows"))))]
pub const NATIVE_NEWLINE: &str = "\n";

#[cfg(target_os = "windows")]
#[cfg_attr(docsrs, doc(cfg(target_os = "windows")))]
pub const NATIVE_NEWLINE: &str = "\r\n";
