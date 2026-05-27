//! `IntoHtml` for the rama-utils string-like types.
//!
//! Each type gets two impls: one consuming the value (escapes on render)
//! and one for `&T`. `PreEscaped<T>` versions write the inner string
//! verbatim instead of escaping.

use rama_utils::str::{
    NonEmptyStr,
    arcstr::{ArcStr, Substr},
    smol_str::SmolStr,
};

use crate::html::core::{IntoHtml, PreEscaped, escape_into};

macro_rules! impl_str_like {
    ($ty:ty) => {
        impl IntoHtml for $ty {
            #[inline]
            fn into_html(self) -> impl IntoHtml {
                self
            }
            #[inline]
            fn escape_and_write(self, buf: &mut String) {
                escape_into(buf, self.as_str())
            }
            #[inline]
            fn size_hint(&self) -> usize {
                self.len()
            }
        }

        impl IntoHtml for &$ty {
            #[inline]
            fn into_html(self) -> impl IntoHtml {
                self
            }
            #[inline]
            fn escape_and_write(self, buf: &mut String) {
                escape_into(buf, self.as_str())
            }
            #[inline]
            fn size_hint(&self) -> usize {
                self.len()
            }
        }

        impl IntoHtml for PreEscaped<$ty> {
            #[inline]
            fn into_html(self) -> impl IntoHtml {
                self
            }
            #[inline]
            fn escape_and_write(self, buf: &mut String) {
                buf.push_str(self.0.as_str());
            }
            #[inline]
            fn size_hint(&self) -> usize {
                self.0.len()
            }
        }
    };
}

impl_str_like!(ArcStr);
impl_str_like!(Substr);
impl_str_like!(SmolStr);

// `NonEmptyStr` exposes the inner string via `Deref`/`AsRef<str>` rather
// than `as_str`, so it does not fit the macro above.
impl IntoHtml for NonEmptyStr {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        escape_into(buf, &self)
    }
    #[inline]
    fn size_hint(&self) -> usize {
        self.len()
    }
}

impl IntoHtml for &NonEmptyStr {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        escape_into(buf, self)
    }
    #[inline]
    fn size_hint(&self) -> usize {
        self.len()
    }
}

impl IntoHtml for PreEscaped<NonEmptyStr> {
    #[inline]
    fn into_html(self) -> impl IntoHtml {
        self
    }
    #[inline]
    fn escape_and_write(self, buf: &mut String) {
        buf.push_str(&self.0);
    }
    #[inline]
    fn size_hint(&self) -> usize {
        self.0.len()
    }
}
