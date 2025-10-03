use crate::extensions::Extensions;

use super::Matcher;

/// Extension to apply matcher operations to an [`Iterator`] of [`Matcher`]s.
pub trait IteratorMatcherExt<'a, M, Request>: Iterator<Item = &'a M> + 'a
where
    M: Matcher<Request>,
{
    /// Matches in case all [`Matcher`] elements match for the given `Request`
    /// within the specified [`crate::Context`].
    fn matches_and(self, ext: Option<&mut Extensions>, request: &Request) -> bool;

    /// Matches in case any of the [`Matcher`] elements match for the given `Request`
    /// within the specified [`crate::Context`].
    fn matches_or(self, ext: Option<&mut Extensions>, request: &Request) -> bool;
}

impl<'a, I, M, Request> IteratorMatcherExt<'a, M, Request> for I
where
    I: Iterator<Item = &'a M> + 'a,
    M: Matcher<Request>,
{
    fn matches_and(self, ext: Option<&mut Extensions>, request: &Request) -> bool {
        match ext {
            None => {
                for matcher in self {
                    if !matcher.matches(None, request) {
                        return false;
                    }
                }
                true
            }
            Some(ext) => {
                let mut inner_ext = Extensions::new();
                for matcher in self {
                    if !matcher.matches(Some(&mut inner_ext), request) {
                        return false;
                    }
                }
                ext.extend(inner_ext);
                true
            }
        }
    }

    fn matches_or(self, ext: Option<&mut Extensions>, request: &Request) -> bool {
        let mut it = self.peekable();
        if it.peek().is_none() {
            return true;
        }

        match ext {
            None => {
                for matcher in it {
                    if matcher.matches(None, request) {
                        return true;
                    }
                }
                false
            }
            Some(ext) => {
                let mut inner_ext = Extensions::new();
                for matcher in it {
                    if matcher.matches(Some(&mut inner_ext), request) {
                        ext.extend(inner_ext);
                        return true;
                    }
                    inner_ext.clear();
                }
                false
            }
        }
    }
}
