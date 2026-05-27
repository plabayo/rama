//! [`IntoHtml`] impls for [`rama_core::combinators::Either`] and friends,
//! so that `if`/`if let`/`match` branches with differing concrete types
//! can still be returned from a template. The macros in
//! `rama-http-macros` desugar `if`/`else if`/`else` chains into nested
//! `Either*` values.

use super::core::IntoHtml;

macro_rules! impl_into_html_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param,)+> IntoHtml for ::rama_core::combinators::$id<$($param,)+>
        where
            $($param: IntoHtml,)+
        {
            #[inline]
            fn into_html(self) -> impl IntoHtml {
                match self {
                    $(
                        Self::$param(value) => ::rama_core::combinators::$id::$param(value.into_html()),
                    )+
                }
            }

            #[inline]
            fn escape_and_write(self, buf: &mut String) {
                match self {
                    $( Self::$param(value) => value.escape_and_write(buf), )+
                }
            }

            #[inline]
            fn size_hint(&self) -> usize {
                match self {
                    $( Self::$param(value) => value.size_hint(), )+
                }
            }
        }
    };
}

::rama_core::combinators::impl_either!(impl_into_html_either);
