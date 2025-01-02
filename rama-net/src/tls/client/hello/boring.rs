use crate::tls::client::parser::parse_client_hello;
use rama_core::error::{ErrorContext, OpaqueError};

impl<'ssl> TryFrom<boring::ssl::ClientHello<'ssl>> for super::ClientHello {
    type Error = OpaqueError;

    fn try_from(value: boring::ssl::ClientHello<'ssl>) -> Result<Self, Self::Error> {
        parse_client_hello(value.as_bytes()).context("parse boring ssl ClientHello")
    }
}

impl<'ssl> TryFrom<&boring::ssl::ClientHello<'ssl>> for super::ClientHello {
    type Error = OpaqueError;

    fn try_from(value: &boring::ssl::ClientHello<'ssl>) -> Result<Self, Self::Error> {
        parse_client_hello(value.as_bytes()).context("parse boring ssl ClientHello")
    }
}
