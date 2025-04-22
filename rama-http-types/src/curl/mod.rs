//! curl related utilities i.e transform HTTP request headers/body to curl command

mod traits;
pub use traits::{IntoCurlHeadersCommand, IntoCurlCommand};

mod headers;
#[doc(inline)]
pub use headers::request_headers_to_curl_command;

mod body;
#[doc(inline)]
pub use body::request_to_curl_command;