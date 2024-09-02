//! macros crate for rama
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![warn(
    clippy::all,
    clippy::todo,
    clippy::empty_enum,
    clippy::enum_glob_use,
    clippy::mem_forget,
    clippy::unused_self,
    clippy::filter_map_next,
    clippy::needless_continue,
    clippy::needless_borrow,
    clippy::match_wildcard_for_single_variants,
    clippy::if_let_mutex,
    clippy::mismatched_target_os,
    clippy::await_holding_lock,
    clippy::match_on_vec_items,
    clippy::imprecise_flops,
    clippy::suboptimal_flops,
    clippy::lossy_float_literal,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::fn_params_excessive_bools,
    clippy::exit,
    clippy::inefficient_to_string,
    clippy::linkedlist,
    clippy::macro_use_imports,
    clippy::option_option,
    clippy::verbose_file_reads,
    clippy::unnested_or_patterns,
    clippy::str_to_string,
    rust_2018_idioms,
    future_incompatible,
    nonstandard_style,
    missing_debug_implementations,
    missing_docs
)]
#![deny(unreachable_pub)]
#![allow(elided_lifetimes_in_paths, clippy::type_complexity)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(not(test), warn(clippy::print_stdout, clippy::dbg_macro))]

pub use ::rama_macros_proc::AsRef;

#[doc(hidden)]
#[macro_use]
pub mod error;

#[doc(hidden)]
#[macro_use]
pub mod str;

#[doc(hidden)]
#[macro_export]
macro_rules! opaque_body {
    ($(#[$m:meta])* pub type $name:ident = $actual:ty;) => {
        $crate::__opaque_body! {
            $(#[$m])* pub type $name<> = $actual;
        }
    };

    ($(#[$m:meta])* pub type $name:ident<$($param:ident),*> = $actual:ty;) => {
        pin_project_lite::pin_project! {
            $(#[$m])*
            pub struct $name<$($param),*> {
                #[pin]
                pub(crate) inner: $actual
            }
        }

        impl<$($param),*> $name<$($param),*> {
            pub(crate) fn new(inner: $actual) -> Self {
                Self { inner }
            }
        }

        impl<$($param),*> http_body::Body for $name<$($param),*> {
            type Data = <$actual as http_body::Body>::Data;
            type Error = <$actual as http_body::Body>::Error;

            #[inline]
            fn poll_frame(
                self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                self.project().inner.poll_frame(cx)
            }

            #[inline]
            fn is_end_stream(&self) -> bool {
                http_body::Body::is_end_stream(&self.inner)
            }

            #[inline]
            fn size_hint(&self) -> http_body::SizeHint {
                http_body::Body::size_hint(&self.inner)
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! all_the_tuples_minus_one_no_last_special_case {
    ($name:ident) => {
        $name!(T1);
        $name!(T1, T2);
        $name!(T1, T2, T3);
        $name!(T1, T2, T3, T4);
        $name!(T1, T2, T3, T4, T5);
        $name!(T1, T2, T3, T4, T5, T6);
        $name!(T1, T2, T3, T4, T5, T6, T7);
        $name!(T1, T2, T3, T4, T5, T6, T7, T8);
        $name!(T1, T2, T3, T4, T5, T6, T7, T8, T9);
        $name!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10);
        $name!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! all_the_tuples_no_last_special_case {
    ($name:ident) => {
        $crate::all_the_tuples_minus_one_no_last_special_case!($name);
        $name!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! match_ignore_ascii_case_str {
    (match ($s:expr) { $caseA:literal $(| $caseAVar:literal)* $(if $condA:expr)? => $retA:expr $(, $caseB:literal $(| $caseBVar:literal)* $(if $condB:expr)? => $retB:expr)* $(,)?}) => {
        $crate::match_ignore_ascii_case_str!(match ($s) {
            $caseA $(| $caseAVar)* $(if $condA)? => $retA,
            $($caseB $(| $caseBVar)* $(if $condB)? => $retB,)*
            _ => panic!("{}", format!("failed to match {}", $s)),
        })
    };
    (match ($s:expr) { $caseA:literal $(| $caseAVar:literal)* $(if $condA:expr)? => $retA:expr $(, $caseB:literal $(| $caseBVar:literal)* $(if $condB:expr)? => $retB:expr)*, _ => $fallback:expr $(,)? }) => {
        {
            let s = ($s).trim();
            if $($condA &&)? (s.eq_ignore_ascii_case($caseA) $(|| s.eq_ignore_ascii_case($caseAVar))*) {
                $retA
            }
            $(
                else if $($condB &&)? (s.eq_ignore_ascii_case($caseB) $(|| s.eq_ignore_ascii_case($caseBVar))*) {
                    $retB
                }
            )*
            else {
                $fallback
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! define_inner_service_accessors {
    () => {
        /// Gets a reference to the underlying service.
        pub fn get_ref(&self) -> &S {
            &self.inner
        }

        /// Consumes `self`, returning the underlying service.
        pub fn into_inner(self) -> S {
            self.inner
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_deref {
    ($ident:ident) => {
        impl<T> std::ops::Deref for $ident<T> {
            type Target = T;

            #[inline]
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<T> std::ops::DerefMut for $ident<T> {
            #[inline]
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };

    ($ident:ident: $ty:ty) => {
        impl std::ops::Deref for $ident {
            type Target = $ty;

            #[inline]
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::ops::DerefMut for $ident {
            #[inline]
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn match_ignore_ascii_case_str_happy_simple() {
        let s = "hello";
        let result = match_ignore_ascii_case_str!(match (s) {
            "hello" => true,
            _ => false,
        });
        assert!(result);
    }

    #[test]
    fn match_ignore_ascii_case_str_happy_mixed_case() {
        let s = "HeLLo";
        let result = match_ignore_ascii_case_str!(match (s) {
            "hello" => true,
            _ => false,
        });
        assert!(result);
    }

    #[test]
    fn match_ignore_ascii_case_str_happy_multiple_cases() {
        let s = "HeLLo";
        let result = match_ignore_ascii_case_str!(match (s) {
            "world" => 1,
            "hello" => 2,
            "!" => 3,
            _ => 4,
        });
        assert_eq!(result, 2);
    }

    #[test]
    fn match_ignore_ascii_case_str_happy_variants() {
        let result = match_ignore_ascii_case_str!(match ("world") {
            "?" => 1,
            "you" | "world" | "there" => 2,
            "!" => 3,
            _ => 4,
        });
        assert_eq!(result, 2);
    }

    #[test]
    fn match_ignore_ascii_case_str_happy_fallback() {
        let s = "HeLLo";
        let result = match_ignore_ascii_case_str!(match (s) {
            "world" => 1,
            "!" => 2,
            _ => 3,
        });
        assert_eq!(result, 3);
    }

    #[test]
    fn match_ignore_ascii_case_str_condition() {
        let s = "HeLLo";
        let result = match_ignore_ascii_case_str!(match (s) {
            "world" => 1,
            "hello" if s.len() == 4 => 2,
            "hello" => 3,
            "!" => 4,
            _ => 5,
        });
        assert_eq!(result, 3);
    }

    #[test]
    fn match_ignore_ascii_case_str_happy_variants_condition() {
        let result = match_ignore_ascii_case_str!(match ("world") {
            "?" => 1,
            "you" | "world" | "there" if false => 2,
            "you" | "world" | "there" if "world".len() == 5 => 3,
            "!" => 4,
            _ => 5,
        });

        assert_eq!(result, 3);
    }

    #[test]
    #[should_panic]
    fn match_ignore_ascii_case_str_panic() {
        match_ignore_ascii_case_str!(match ("hello") {
            "world" => (),
        })
    }
}
