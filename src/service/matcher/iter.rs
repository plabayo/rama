use crate::service::{context::Extensions, Context};

use super::Matcher;

/// Extension to apply matcher operations to an [`Iterator`] of [`Matcher`]s.
pub trait IteratorMatcherExt<'a, M, State, Request>: Iterator<Item = &'a M> + 'a
where
    M: Matcher<State, Request>,
{
    /// Matches in case all [`Matcher`] elements match for the given `Request`
    /// within the specified [`crate::service::Context`].
    fn match_and(
        self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        request: &Request,
    ) -> bool;

    /// Matches in case any of the [`Matcher`] elements match for the given `Request`
    /// within the specified [`crate::service::Context`].
    fn match_or(
        self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        request: &Request,
    ) -> bool;
}

impl<'a, I, M, State, Request> IteratorMatcherExt<'a, M, State, Request> for I
where
    I: Iterator<Item = &'a M> + 'a,
    M: Matcher<State, Request>,
{
    fn match_and(
        self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        request: &Request,
    ) -> bool {
        match ext {
            None => {
                for matcher in self {
                    if !matcher.matches(None, ctx, request) {
                        return false;
                    }
                }
                true
            }
            Some(ext) => {
                let mut inner_ext = Extensions::new();
                for matcher in self {
                    if !matcher.matches(Some(&mut inner_ext), ctx, request) {
                        return false;
                    }
                }
                ext.extend(inner_ext);
                true
            }
        }
    }

    fn match_or(
        self,
        ext: Option<&mut Extensions>,
        ctx: &Context<State>,
        request: &Request,
    ) -> bool {
        match ext {
            None => {
                for matcher in self {
                    if matcher.matches(None, ctx, request) {
                        return true;
                    }
                }
                false
            }
            Some(ext) => {
                let mut inner_ext = Extensions::new();
                for matcher in self {
                    if matcher.matches(Some(&mut inner_ext), ctx, request) {
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
