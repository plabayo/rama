//! `IntoHtml` for the rama-utils collection types — each element is
//! rendered in turn and concatenated.

use rama_utils::collections::{
    NonEmptySmallVec,
    smallvec::{Array, SmallVec},
};

use crate::html::core::IntoHtml;

impl<A> IntoHtml for SmallVec<A>
where
    A: Array,
    A::Item: IntoHtml,
{
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        for x in self {
            x.escape_and_write(buf);
        }
    }
    #[inline]
    fn size_hint(&self) -> usize {
        self.iter().map(IntoHtml::size_hint).sum()
    }
}

impl<const N: usize, T> IntoHtml for NonEmptySmallVec<N, T>
where
    T: IntoHtml,
    [T; N]: Array<Item = T>,
{
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        for x in self {
            x.escape_and_write(buf);
        }
    }
    #[inline]
    fn size_hint(&self) -> usize {
        let mut n = 0;
        for x in self {
            n += x.size_hint();
        }
        n
    }
}
