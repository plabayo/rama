//! hidden rama macros 🤫

#[doc(hidden)]
#[macro_use]
pub mod enums;

#[doc(hidden)]
#[macro_use]
pub mod error;

#[doc(hidden)]
#[macro_use]
pub mod str;

#[doc(hidden)]
#[macro_export]
macro_rules! __opaque_body {
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
#[doc(inline)]
pub use crate::__opaque_body as opaque_body;

#[doc(hidden)]
#[macro_export]
macro_rules! __count {
    () => (0usize);
    ( $x:tt $($xs:tt)* ) => (1usize + $crate::macros::count!($($xs)*));
}
#[doc(inline)]
pub use crate::__count as count;

#[doc(hidden)]
#[macro_export]
macro_rules! __all_the_tuples_minus_one_no_last_special_case {
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
#[doc(inline)]
pub use crate::__all_the_tuples_minus_one_no_last_special_case as all_the_tuples_minus_one_no_last_special_case;

#[doc(hidden)]
#[macro_export]
macro_rules! __all_the_tuples_no_last_special_case {
    ($name:ident) => {
        $crate::macros::all_the_tuples_minus_one_no_last_special_case!($name);
        $name!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12);
    };
}
#[doc(inline)]
pub use crate::__all_the_tuples_no_last_special_case as all_the_tuples_no_last_special_case;

#[doc(hidden)]
#[macro_export]
macro_rules! __match_ignore_ascii_case_str {
    (match ($s:expr) { $caseA:literal $(| $caseAVar:literal)* $(if $condA:expr)? => $retA:expr $(, $caseB:literal $(| $caseBVar:literal)* $(if $condB:expr)? => $retB:expr)* $(,)?}) => {
        $crate::macros::match_ignore_ascii_case_str!(match ($s) {
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
#[doc(inline)]
pub use crate::__match_ignore_ascii_case_str as match_ignore_ascii_case_str;

#[doc(hidden)]
#[macro_export]
macro_rules! __define_inner_service_accessors {
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
#[doc(inline)]
pub use crate::__define_inner_service_accessors as define_inner_service_accessors;

#[doc(hidden)]
#[macro_export]
macro_rules! __impl_deref {
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

    ($ident:ident< $($gen:ident),* >: $ty:ty) => {
        impl<$($gen),*> std::ops::Deref for $ident<$($gen),*> {
            type Target = $ty;

            #[inline]
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<$($gen),*> std::ops::DerefMut for $ident<$($gen),*> {
            #[inline]
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };
}
#[doc(inline)]
pub use crate::__impl_deref as impl_deref;

#[doc(inline)]
pub use rama_macros::paste;

#[doc(hidden)]
#[macro_export]
macro_rules! __generate_set_and_with {
    (
        $(#[$outer_doc:meta])*
        $vis:vis fn $fn_name:ident(mut $self_token:ident) -> Self {
            $($body:tt)*
        }
    ) => {
        $crate::macros::paste! {
            $(#[$outer_doc])*
            #[must_use]
            $vis fn [<with_ $fn_name>](mut $self_token) -> Self {
                $($body)*
            }

            $(#[$outer_doc])*
            $vis fn [<set_ $fn_name>](&mut $self_token) -> &mut Self {
                $($body)*
            }
        }
    };
    (
        $(#[$outer_doc:meta])*
        $vis:vis fn $fn_name:ident(mut $self_token:ident, $param_name:ident: Option<$param_ty:ty> $(,)?) -> Self {
            $($body:tt)*
        }
    ) => {
        $crate::macros::paste! {

            $(#[$outer_doc])*
            #[must_use]
            $vis fn [<maybe_with_ $fn_name>](mut $self_token, $param_name: Option<$param_ty>) -> Self {
                $($body)*
            }

            $(#[$outer_doc])*
            $vis fn [<maybe_set_ $fn_name>](&mut $self_token, $param_name: Option<$param_ty>) -> &mut Self {
                $($body)*
            }

            $(#[$outer_doc])*
            #[must_use]
            $vis fn [<with_ $fn_name>](mut $self_token, $param_name: $param_ty) -> Self {
                let $param_name: Option<$param_ty> = Some($param_name);
                $($body)*
            }

            $(#[$outer_doc])*
            $vis fn [<set_ $fn_name>](&mut $self_token, $param_name: $param_ty) -> &mut Self {
                let $param_name: Option<$param_ty> = Some($param_name);
                $($body)*
            }

            $(#[$outer_doc])*
            #[must_use]
            $vis fn [<without_ $fn_name>](mut $self_token) -> Self {
                let $param_name: Option<$param_ty> = None;
                $($body)*
            }

            $(#[$outer_doc])*
            $vis fn [<unset_ $fn_name>](&mut $self_token) -> &mut Self {
                let $param_name: Option<$param_ty> = None;
                $($body)*
            }

        }
    };
    (
        $(#[$outer_doc:meta])*
        $vis:vis fn $fn_name:ident(mut $self_token:ident, $param_name:ident: Option<$param_ty:ty> $(,)?) -> Result<Self, $error:ty> {
            $($body:tt)*
        }
    ) => {
        $crate::macros::paste! {
            $(#[$outer_doc])*
            #[must_use]
            $vis fn [<try_maybe_with_ $fn_name>](mut $self_token, $param_name: Option<$param_ty>) -> Result<Self, $error> {
                $($body)*
            }

            $(#[$outer_doc])*
            $vis fn [<try_maybe_set_ $fn_name>](&mut $self_token, $param_name: Option<$param_ty>) -> Result<&mut Self, $error> {
                $($body)*
            }

            $(#[$outer_doc])*
            #[must_use]
            $vis fn [<try_with_ $fn_name>](mut $self_token, $param_name: $param_ty) -> Result<Self, $error> {
                let $param_name: Option<$param_ty> = Some($param_name);
                $($body)*
            }

            $(#[$outer_doc])*
            $vis fn [<try_set_ $fn_name>](&mut $self_token, $param_name: $param_ty) -> Result<&mut Self, $error> {
                let $param_name: Option<$param_ty> = Some($param_name);
                $($body)*
            }

            $(#[$outer_doc])*
            #[must_use]
            $vis fn [<try_without_ $fn_name>](mut $self_token) -> Result<Self, $error> {
                let $param_name: Option<$param_ty> = None;
                $($body)*
            }

            $(#[$outer_doc])*
            $vis fn [<try_unset_ $fn_name>](&mut $self_token) -> Result<&mut Self, $error> {
                let $param_name: Option<$param_ty> = None;
                $($body)*
            }

        }
    };
    (
        $(#[$outer_doc:meta])*
        $vis:vis const fn $fn_name:ident(mut $self_token:ident, $($param_name:ident: $param_ty:ty),+ $(,)?) -> Self {
            $($body:tt)*
        }
    ) => {
        $crate::macros::paste! {
            $(#[$outer_doc])*
            #[must_use]
            $vis const fn [<with_ $fn_name>](mut $self_token, $($param_name: $param_ty),+) -> Self {
                $($body)*
            }
        }
    };
    (
        $(#[$outer_doc:meta])*
        $vis:vis fn $fn_name:ident(mut $self_token:ident, $($param_name:ident: $param_ty:ty),+ $(,)?) -> Self {
            $($body:tt)*
        }
    ) => {
        $crate::macros::paste! {
            $(#[$outer_doc])*
            #[must_use]
            $vis fn [<with_ $fn_name>](mut $self_token, $($param_name: $param_ty),+) -> Self {
                $($body)*
            }

            $(#[$outer_doc])*
            $vis fn [<set_ $fn_name>](&mut $self_token, $($param_name: $param_ty),+) -> &mut Self {
                $($body)*
            }
        }
    };
    (
        $(#[$outer_doc:meta])*
        $vis:vis fn $fn_name:ident(mut $self_token:ident, $($param_name:ident: $param_ty:ty),+ $(,)?) -> Result<Self, $error:ty> {
            $($body:tt)*
        }
    ) => {
        $crate::macros::paste! {
            $(#[$outer_doc])*
            #[must_use]
            $vis fn [<try_with_ $fn_name>](mut $self_token, $($param_name: $param_ty),+) -> Result<Self, $error> {
                $($body)*
            }

            $(#[$outer_doc])*
            $vis fn [<try_set_ $fn_name>](&mut $self_token, $($param_name: $param_ty),+) -> Result<&mut Self, $error> {
                $($body)*
            }
        }
    };
    (
        $(#[$outer_doc:meta])*
        $vis:vis fn $fn_name:ident(mut $self_token:ident) -> Result<Self, $error:ty> {
            $($body:tt)*
        }
    ) => {
        $crate::macros::paste! {
            $(#[$outer_doc])*
            #[must_use]
            $vis fn [<try_with_ $fn_name>](mut $self_token) -> Result<Self, $error> {
                $($body)*
            }

            $(#[$outer_doc])*
            $vis fn [<try_set_ $fn_name>](&mut $self_token) -> Result<&mut Self, $error> {
                $($body)*
            }
        }
    };
}

pub use crate::__generate_set_and_with as generate_set_and_with;

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

    #[test]
    fn test_generate_set_and_with() {
        #[derive(Default)]
        struct Builder {
            something: Option<String>,
            should_execute: bool,
        }

        struct AlsoABool(bool);

        impl From<AlsoABool> for bool {
            fn from(value: AlsoABool) -> Self {
                value.0
            }
        }

        impl Builder {
            generate_set_and_with!(
                /// Configure maybe something
                fn something(mut self, value: Option<String>) -> Self {
                    self.something = value;
                    self
                }
            );
            generate_set_and_with!(
                /// Should this execute something
                ///
                /// We can use Into if we want to
                fn should_execute(mut self, value: impl Into<bool>) -> Self {
                    self.should_execute = value.into();
                    self
                }
            );
        }

        let test_string = "test".to_owned();

        let builder = Builder::default();
        assert_eq!(builder.something, None);
        let builder = builder.with_something(test_string.clone());
        assert_eq!(builder.something, Some(test_string.clone()));
        let builder = builder.without_something();
        assert_eq!(builder.something, None);
        let builder = builder.maybe_with_something(Some(test_string.clone()));
        assert_eq!(builder.something, Some(test_string.clone()));

        let mut builder = Builder::default();
        assert_eq!(builder.something, None);
        builder.set_something(test_string.clone());
        assert_eq!(builder.something, Some(test_string.clone()));
        builder.unset_something();
        assert_eq!(builder.something, None);
        builder.maybe_set_something(Some(test_string.clone()));
        assert_eq!(builder.something, Some(test_string));

        let builder = Builder::default();
        assert!(!builder.should_execute);
        let builder = builder.with_should_execute(true);
        assert!(builder.should_execute);

        let mut builder = Builder::default();
        assert!(!builder.should_execute);
        builder.set_should_execute(true);
        assert!(builder.should_execute);

        let builder = Builder::default().with_should_execute(AlsoABool(true));
        assert!(builder.should_execute)
    }
}
