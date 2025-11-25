use rama_http_types::response;

use crate::HeaderEncode;

/// An extension trait adding "typed" methods to `http::response::Builder`.
pub trait HttpResponseBuilderExt: self::sealed::Sealed {
    /// Inserts the typed header into this `http::response::Builder`.
    #[must_use]
    fn typed_header<H>(self, header: H) -> Self
    where
        H: HeaderEncode;
}

impl HttpResponseBuilderExt for response::Builder {
    fn typed_header<H>(self, header: H) -> Self
    where
        H: HeaderEncode,
    {
        if let Some(value) = header.encode_to_value() {
            self.header(H::name(), value)
        } else {
            self
        }
    }
}

mod sealed {
    use super::*;

    pub trait Sealed: Sized {}
    impl Sealed for response::Builder {}
}
