use super::Matcher;
use crate::extensions::Extensions;

/// A matcher that matches if the inner matcher does not match.
#[derive(Debug, Clone)]
pub struct Not<T>(T);

impl<T> Not<T> {
    /// Create a new `Not` matcher.
    pub const fn new(inner: T) -> Self {
        Self(inner)
    }
}

impl<Request, T> Matcher<Request> for Not<T>
where
    T: Matcher<Request>,
{
    fn matches(&self, ext: Option<&mut Extensions>, req: &Request) -> bool {
        !self.0.matches(ext, req)
    }
}
