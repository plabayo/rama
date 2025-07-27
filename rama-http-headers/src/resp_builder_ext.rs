use rama_http_types::dep::http::response;

use super::Header;

/// An extension trait adding "typed" methods to `http::response::Builder`.
pub trait HttpResponseBuilderExt: self::sealed::Sealed {
    /// Inserts the typed [`Header`] into this `http::response::Builder`.
    #[must_use]
    fn typed_header<H>(self, header: H) -> Self
    where
        H: Header;
}

impl HttpResponseBuilderExt for response::Builder {
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
    impl Sealed for response::Builder {}
}
