//! Input trait for URI component setters.
//!
//! `IntoUriComponent` accepts borrowed (`&str`, `&[u8]`) and owned
//! (`String`, `Vec<u8>`, `Bytes`, `BytesMut`) byte sources, and lets
//! owned inputs move into the URI without an extra copy.

use rama_core::bytes::{Bytes, BytesMut};

mod sealed {
    use rama_core::bytes::BytesMut;
    pub trait Sealed {
        fn as_uri_component_bytes(&self) -> &[u8];
        fn into_uri_component_bytes_mut(self) -> BytesMut;
    }
}

/// Sealed marker — types accepted by URI component setters.
pub trait IntoUriComponent: sealed::Sealed {}

impl sealed::Sealed for BytesMut {
    fn as_uri_component_bytes(&self) -> &[u8] {
        self
    }
    fn into_uri_component_bytes_mut(self) -> BytesMut {
        self
    }
}
impl IntoUriComponent for BytesMut {}

impl sealed::Sealed for Bytes {
    fn as_uri_component_bytes(&self) -> &[u8] {
        self
    }
    fn into_uri_component_bytes_mut(self) -> BytesMut {
        // `BytesMut::from(Bytes)` is zero-copy when the Bytes is the
        // unique owner of its underlying buffer; otherwise it copies.
        BytesMut::from(self)
    }
}
impl IntoUriComponent for Bytes {}

impl sealed::Sealed for String {
    fn as_uri_component_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
    fn into_uri_component_bytes_mut(self) -> BytesMut {
        // String → Vec<u8> → Bytes → BytesMut is a zero-copy chain.
        BytesMut::from(Bytes::from(self.into_bytes()))
    }
}
impl IntoUriComponent for String {}

impl sealed::Sealed for Vec<u8> {
    fn as_uri_component_bytes(&self) -> &[u8] {
        self
    }
    fn into_uri_component_bytes_mut(self) -> BytesMut {
        BytesMut::from(Bytes::from(self))
    }
}
impl IntoUriComponent for Vec<u8> {}

impl sealed::Sealed for &str {
    fn as_uri_component_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
    fn into_uri_component_bytes_mut(self) -> BytesMut {
        BytesMut::from(self.as_bytes())
    }
}
impl IntoUriComponent for &str {}

impl sealed::Sealed for &[u8] {
    fn as_uri_component_bytes(&self) -> &[u8] {
        self
    }
    fn into_uri_component_bytes_mut(self) -> BytesMut {
        BytesMut::from(self)
    }
}
impl IntoUriComponent for &[u8] {}
