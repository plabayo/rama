use crate::extensions::Extensions;

use super::Matcher;

/// Extension to apply matcher operations to an [`Iterator`] of [`Matcher`]s.
pub trait IteratorMatcherExt<'a, M, Input>: Iterator<Item = &'a M> + 'a
where
    M: Matcher<Input>,
{
    /// Matches in case all [`Matcher`] elements match for the given `Input`
    /// within the specified [`Extensions`].
    fn matches_and(self, ext: Option<&mut Extensions>, input: &Input) -> bool;

    /// Matches in case any of the [`Matcher`] elements match for the given `Input`
    /// within the specified [`Extensions`].
    fn matches_or(self, ext: Option<&mut Extensions>, input: &Input) -> bool;
}

impl<'a, I, M, Input> IteratorMatcherExt<'a, M, Input> for I
where
    I: Iterator<Item = &'a M> + 'a,
    M: Matcher<Input>,
{
    fn matches_and(self, ext: Option<&mut Extensions>, input: &Input) -> bool {
        match ext {
            None => {
                for matcher in self {
                    if !matcher.matches(None, input) {
                        return false;
                    }
                }
                true
            }
            Some(ext) => {
                let mut inner_ext = Extensions::new();
                for matcher in self {
                    if !matcher.matches(Some(&mut inner_ext), input) {
                        return false;
                    }
                }
                ext.extend(inner_ext);
                true
            }
        }
    }

    fn matches_or(self, ext: Option<&mut Extensions>, input: &Input) -> bool {
        let mut it = self.peekable();
        if it.peek().is_none() {
            return true;
        }

        match ext {
            None => {
                for matcher in it {
                    if matcher.matches(None, input) {
                        return true;
                    }
                }
                false
            }
            Some(ext) => {
                for matcher in it {
                    let mut inner_ext = Extensions::new();
                    if matcher.matches(Some(&mut inner_ext), input) {
                        ext.extend(inner_ext);
                        return true;
                    }
                }
                false
            }
        }
    }
}
