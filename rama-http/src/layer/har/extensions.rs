use std::borrow::Cow;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestComment(pub(super) Cow<'static, str>);

impl RequestComment {
    pub fn new(comment: impl Into<Cow<'static, str>>) -> Self {
        Self(comment.into())
    }

    pub const fn from_static(comment: &'static str) -> Self {
        Self(Cow::Borrowed(comment))
    }
}

impl AsRef<str> for RequestComment {
    #[inline]
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}
