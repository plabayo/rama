//! http I/O utilities, e.g. writing http requests/responses in std http format.

mod request;
#[doc(inline)]
pub use request::write_http_request;

mod response;
#[doc(inline)]
pub use response::write_http_response;
