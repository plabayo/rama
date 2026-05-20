//! Sealed `IntoUriInput` trait — the set of types that can be passed to
//! [`Uri::parse`] / [`Uri::parse_strict`].
//!
//! The conversion method itself lives on the private supertrait
//! `sealed::Sealed`, so the public surface is just the marker
//! `IntoUriInput`. Downstream crates cannot add implementations.

use rama_core::bytes::{Bytes, BytesMut};

mod sealed {
    use super::Bytes;

    pub trait Sealed {
        fn into_uri_input(self) -> Bytes;
    }
}

/// Marker trait for inputs accepted by [`Uri::parse`] and
/// [`Uri::parse_strict`].
///
/// Sealed — implementations are exhaustive and live in this crate. The
/// conversion logic is on the private supertrait so the public API is
/// just the bound.
///
/// [`Uri::parse`]: crate::uri::Uri::parse
/// [`Uri::parse_strict`]: crate::uri::Uri::parse_strict
pub trait IntoUriInput: sealed::Sealed {}

impl sealed::Sealed for Bytes {
    #[inline(always)]
    fn into_uri_input(self) -> Bytes {
        self
    }
}
impl IntoUriInput for Bytes {}

impl sealed::Sealed for BytesMut {
    #[inline(always)]
    fn into_uri_input(self) -> Bytes {
        self.freeze()
    }
}
impl IntoUriInput for BytesMut {}

impl sealed::Sealed for String {
    #[inline(always)]
    fn into_uri_input(self) -> Bytes {
        Bytes::from(self)
    }
}
impl IntoUriInput for String {}

impl sealed::Sealed for Vec<u8> {
    #[inline(always)]
    fn into_uri_input(self) -> Bytes {
        Bytes::from(self)
    }
}
impl IntoUriInput for Vec<u8> {}

impl sealed::Sealed for &str {
    #[inline(always)]
    fn into_uri_input(self) -> Bytes {
        Bytes::copy_from_slice(self.as_bytes())
    }
}
impl IntoUriInput for &str {}

impl sealed::Sealed for &[u8] {
    #[inline(always)]
    fn into_uri_input(self) -> Bytes {
        Bytes::copy_from_slice(self)
    }
}
impl IntoUriInput for &[u8] {}

/// `pub(crate)` accessor that routes through the private supertrait.
/// `Uri::parse` calls this — it's the bridge between the public trait
/// (which is just a marker) and the conversion method.
#[inline(always)]
pub(crate) fn into_uri_input<T: IntoUriInput>(input: T) -> Bytes {
    <T as sealed::Sealed>::into_uri_input(input)
}
