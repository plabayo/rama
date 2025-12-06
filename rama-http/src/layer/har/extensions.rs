use rama_utils::str::arcstr::ArcStr;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestComment(pub ArcStr);
