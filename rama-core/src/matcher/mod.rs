//! Matcher utilities for any middleware where need to match
//! on incoming inputs.
//!
//! This module provides the [`Matcher`] trait and convenience utilities around it.
//!
//! - Examples of this are iterator "reducers" as made available via [`IteratorMatcherExt`],
//!   as well as optional [`Matcher::or`] and [`Matcher::and`] trait methods.
//! - These all serve as building blocks together with [`And`], [`Or`], [`Not`] and a bool
//!   to combine and transform any kind of [`Matcher`].
//! - And finally there is [`MatchFn`], easily created using [`match_fn`] to create a [`Matcher`]
//!   from any compatible [`Fn`].

use std::sync::Arc;

use super::extensions::Extensions;
use crate::Service;
use crate::extensions::ExtensionsMut;
use rama_macros::paste;
use rama_utils::macros::all_the_tuples_no_last_special_case;

mod op_or;
#[doc(inline)]
pub use op_or::Or;

mod op_and;
#[doc(inline)]
pub use op_and::And;

mod op_not;
#[doc(inline)]
pub use op_not::Not;

mod mfn;
#[doc(inline)]
pub use mfn::{MatchFn, match_fn};

mod iter;
#[doc(inline)]
pub use iter::IteratorMatcherExt;

mod ext;
#[doc(inline)]
pub use ext::ExtensionMatcher;

/// A condition to decide whether `Input` matches for
/// router or other middleware purposes.
pub trait Matcher<Input>: Send + Sync + 'static {
    /// returns true on a match, false otherwise
    ///
    /// `ext` is None in case the callee is not interested in collecting potential
    /// match metadata gathered during the matching process. An example of this
    /// path parameters for an http Uri matcher.
    fn matches(&self, ext: Option<&mut Extensions>, input: &Input) -> bool;

    /// Provide an alternative matcher to match if the current one does not match.
    fn or<M>(self, other: M) -> impl Matcher<Input>
    where
        Self: Sized,
        M: Matcher<Input>,
    {
        Or::new((self, other))
    }

    /// Add another condition to match on top of the current one.
    fn and<M>(self, other: M) -> impl Matcher<Input>
    where
        Self: Sized,
        M: Matcher<Input>,
    {
        And::new((self, other))
    }

    /// Negate the current condition.
    fn not(self) -> impl Matcher<Input>
    where
        Self: Sized,
    {
        Not::new(self)
    }
}

impl<Input, T> Matcher<Input> for Arc<T>
where
    T: Matcher<Input>,
{
    fn matches(&self, ext: Option<&mut Extensions>, input: &Input) -> bool {
        (**self).matches(ext, input)
    }
}

impl<Input, T> Matcher<Input> for &'static T
where
    T: Matcher<Input>,
{
    #[inline(always)]
    fn matches(&self, ext: Option<&mut Extensions>, input: &Input) -> bool {
        (**self).matches(ext, input)
    }
}

impl<Input, T> Matcher<Input> for Option<T>
where
    T: Matcher<Input>,
{
    fn matches(&self, ext: Option<&mut Extensions>, input: &Input) -> bool {
        match self {
            Some(inner) => inner.matches(ext, input),
            None => false,
        }
    }
}

impl<Input, T> Matcher<Input> for Box<T>
where
    T: Matcher<Input>,
{
    fn matches(&self, ext: Option<&mut Extensions>, input: &Input) -> bool {
        (**self).matches(ext, input)
    }
}

impl<Input> Matcher<Input> for Box<dyn Matcher<Input> + 'static>
where
    Input: Send + 'static,
{
    fn matches(&self, ext: Option<&mut Extensions>, input: &Input) -> bool {
        (**self).matches(ext, input)
    }
}

impl<Input> Matcher<Input> for bool {
    fn matches(&self, _: Option<&mut Extensions>, _: &Input) -> bool {
        *self
    }
}

macro_rules! impl_matcher_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+, Input> Matcher<Input> for crate::combinators::$id<$($param),+>
        where
            $($param: Matcher<Input>),+,
            Input: Send + 'static,

        {
            fn matches(
                &self,
                ext: Option<&mut Extensions>,
                input: &Input
            ) -> bool{
                match self {
                    $(
                        crate::combinators::$id::$param(layer) => layer.matches(ext, input),
                    )+
                }
            }
        }
    };
}

crate::combinators::impl_either!(impl_matcher_either);

/// Wrapper type that can be used to turn a tuple of ([`Matcher`], [`Service`]) tuples
/// into a single [`Service`].
#[derive(Debug, Clone)]
pub struct MatcherRouter<N>(pub N);

macro_rules! impl_matcher_service_tuple {
    ($($T:ident),+ $(,)?) => {
        paste!{
            #[allow(non_camel_case_types)]
            #[allow(non_snake_case)]
            impl<$([<M_ $T>], $T),+, S, Input, Output, Error> Service<Input> for MatcherRouter<($(([<M_ $T>], $T)),+, S)>
            where
                Input: Send + ExtensionsMut + 'static,
                Output: Send + 'static,
                $(
                    [<M_ $T>]: Matcher<Input>,
                    $T: Service<Input, Output = Output, Error = Error>,
                )+
                S: Service<Input, Output = Output, Error = Error>,
                Error: Send + 'static,
            {
                type Output = Output;
                type Error = Error;

                async fn serve(
                    &self,
                    mut input: Input,
                ) -> Result<Self::Output, Self::Error> {
                    let ($(([<M_ $T>], $T)),+, S) = &self.0;
                    $(
                        let mut ext = Extensions::new();
                        if [<M_ $T>].matches(Some(&mut ext), &input) {
                            input.extensions_mut().extend(ext);
                            return $T.serve(input).await;
                        }
                    )+
                    S.serve(input).await
                }
            }
        }
    };
}

all_the_tuples_no_last_special_case!(impl_matcher_service_tuple);

#[cfg(test)]
mod test;
