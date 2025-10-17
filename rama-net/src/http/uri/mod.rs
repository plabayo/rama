//! Request Uri utilities
//!
//! NOTE: in future this needs to move in its own crate
//! or some core module below rama-http-types
//! as the Uri goes beyond http...

pub mod match_replace;
#[doc(inline)]
pub use match_replace::{UriMatchReplace, UriMatchReplaceRule};
