use rama_http_types::dep::http::request;

use super::Header;

/// An extension trait adding "typed" methods to `http::request::Builder`.
pub trait HttpRequestBuilderExt: self::sealed::Sealed {
    /// Inserts the typed [`Header`] into this `http::request::Builder`.
    #[must_use]
    fn typed_header<H>(self, header: H) -> Self
    where
        H: Header;
}

impl HttpRequestBuilderExt for request::Builder {
    fn typed_header<H>(self, header: H) -> Self
    where
        H: Header,
    {
        self.header(H::name(), header.encode_to_value())
    }
}

mod sealed {
    use super::*;

    pub trait Sealed: Sized {}
    impl Sealed for request::Builder {}
}
