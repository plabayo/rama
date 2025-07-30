#[derive(Debug)]
pub struct EqIgnoreAsciiCase<T1, T2>(pub T1, pub T2);

#[must_use]
pub const fn eq_ignore_ascii_case(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    let mut i = 0;
    while i < lhs.len() {
        let l = lhs[i].to_ascii_lowercase();
        let r = rhs[i].to_ascii_lowercase();
        if l != r {
            return false;
        }
        i += 1;
    }
    true
}

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
