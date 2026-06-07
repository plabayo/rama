//! Input trait for URI component setters.
//!
//! `IntoUriComponent` accepts borrowed (`&str`, `&[u8]`) and owned
//! (`String`, `Vec<u8>`, `Bytes`, `BytesMut`) byte sources, and lets
//! owned inputs move into the URI without an extra copy. Integer and
//! boolean scalars are also accepted — they format to their decimal /
//! `true`/`false` rendering, so e.g. a numeric id can be pushed as a
//! path segment without a manual `.to_string()`.

use std::borrow::Cow;

use rama_core::bytes::{Bytes, BytesMut};

mod sealed {
    use std::borrow::Cow;

    use rama_core::bytes::BytesMut;
    pub trait Sealed {
        /// The component bytes to read for encoding. Backed by the value
        /// itself for byte-source types (`Cow::Borrowed`); scalar types
        /// format on demand and return `Cow::Owned`.
        fn as_uri_component_bytes(&self) -> Cow<'_, [u8]>;
        fn into_uri_component_bytes_mut(self) -> BytesMut;
    }
}

/// Sealed marker — types accepted by URI component setters.
pub trait IntoUriComponent: sealed::Sealed {}

impl sealed::Sealed for BytesMut {
    fn as_uri_component_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self)
    }
    fn into_uri_component_bytes_mut(self) -> BytesMut {
        self
    }
}
impl IntoUriComponent for BytesMut {}

impl sealed::Sealed for Bytes {
    fn as_uri_component_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self)
    }
    fn into_uri_component_bytes_mut(self) -> BytesMut {
        // `BytesMut::from(Bytes)` is zero-copy when the Bytes is the
        // unique owner of its underlying buffer; otherwise it copies.
        BytesMut::from(self)
    }
}
impl IntoUriComponent for Bytes {}

impl sealed::Sealed for String {
    fn as_uri_component_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_bytes())
    }
    fn into_uri_component_bytes_mut(self) -> BytesMut {
        // String → Vec<u8> → Bytes → BytesMut is a zero-copy chain.
        BytesMut::from(Bytes::from(self.into_bytes()))
    }
}
impl IntoUriComponent for String {}

impl sealed::Sealed for Vec<u8> {
    fn as_uri_component_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self)
    }
    fn into_uri_component_bytes_mut(self) -> BytesMut {
        BytesMut::from(Bytes::from(self))
    }
}
impl IntoUriComponent for Vec<u8> {}

impl sealed::Sealed for &str {
    fn as_uri_component_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self.as_bytes())
    }
    fn into_uri_component_bytes_mut(self) -> BytesMut {
        BytesMut::from(self.as_bytes())
    }
}
impl IntoUriComponent for &str {}

impl sealed::Sealed for &[u8] {
    fn as_uri_component_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(self)
    }
    fn into_uri_component_bytes_mut(self) -> BytesMut {
        BytesMut::from(self)
    }
}
impl IntoUriComponent for &[u8] {}

// Integer scalars format to their ASCII decimal rendering via `itoa`
// (no allocation for the format itself; the `Cow::Owned` / `BytesMut`
// copy is the only allocation). Decimal digits and a leading `-` are all
// legal in every URI component, so the encoder always takes its
// pass-through path for these.
macro_rules! impl_integer {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl sealed::Sealed for $ty {
                fn as_uri_component_bytes(&self) -> Cow<'_, [u8]> {
                    let mut buf = itoa::Buffer::new();
                    Cow::Owned(buf.format(*self).as_bytes().to_vec())
                }
                fn into_uri_component_bytes_mut(self) -> BytesMut {
                    let mut buf = itoa::Buffer::new();
                    BytesMut::from(buf.format(self).as_bytes())
                }
            }
            impl IntoUriComponent for $ty {}
        )+
    };
}

impl_integer!(
    i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize
);

impl sealed::Sealed for bool {
    fn as_uri_component_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(if *self { b"true" } else { b"false" })
    }
    fn into_uri_component_bytes_mut(self) -> BytesMut {
        BytesMut::from(if self { &b"true"[..] } else { &b"false"[..] })
    }
}
impl IntoUriComponent for bool {}
