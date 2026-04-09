use rama_core::extensions::Extension;
use rama_utils::str::arcstr::ArcStr;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Extension)]
pub struct RequestComment(pub ArcStr);
