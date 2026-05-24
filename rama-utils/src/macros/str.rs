use crate::str::eq_ignore_ascii_case;

/// Const-eval dispatch helper for the [`eq_ignore_ascii_case!`] macro.
/// Implementation detail; call sites should use the macro.
#[doc(hidden)]
#[derive(Debug)]
pub struct EqIgnoreAsciiCase<T1, T2>(pub T1, pub T2);

impl EqIgnoreAsciiCase<&[u8], &[u8]> {
    #[must_use]
    pub const fn const_eval(&self) -> bool {
        eq_ignore_ascii_case(self.0, self.1)
    }
}

impl EqIgnoreAsciiCase<&str, &str> {
    #[must_use]
    pub const fn const_eval(&self) -> bool {
        eq_ignore_ascii_case(self.0.as_bytes(), self.1.as_bytes())
    }
}

impl<const N1: usize, const N2: usize> EqIgnoreAsciiCase<&[u8; N1], &[u8; N2]> {
    #[must_use]
    pub const fn const_eval(&self) -> bool {
        eq_ignore_ascii_case(self.0.as_slice(), self.1.as_slice())
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __eq_ignore_ascii_case {
    ($lhs:expr, $rhs:expr) => {
        $crate::macros::str::EqIgnoreAsciiCase($lhs, $rhs).const_eval()
    };
}
#[doc(inline)]
pub use crate::__eq_ignore_ascii_case as eq_ignore_ascii_case;
