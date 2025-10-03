use super::Matcher;
use crate::extensions::Extensions;

/// A matcher that matches if the inner matcher does not match.
pub struct Not<T>(T);

impl<T: std::fmt::Debug> std::fmt::Debug for Not<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Not").field(&self.0).finish()
    }
}

impl<T: Clone> Clone for Not<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

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
