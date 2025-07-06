//! Pieces pertaining to the HTTP message protocol.

use rama_http::io::upgrade;
use rama_http_types::HeaderMap;
use rama_http_types::Version;
use rama_http_types::dep::http;

pub(crate) mod h1;

pub(crate) use self::h1::Conn;
pub(crate) use self::h1::ServerTransaction;
pub(crate) use self::h1::dispatch;

pub(crate) mod h2;

/// An Incoming Message head. Includes request/status line, and headers.
#[derive(Debug, Default)]
pub(crate) struct MessageHead<S> {
    /// HTTP version of the message.
    pub(crate) version: Version,
    /// Subject (request line or status line) of Incoming message.
    pub(crate) subject: S,
    /// Headers of the Incoming message.
    pub(crate) headers: HeaderMap,
    /// Extensions.
    extensions: http::Extensions,
}

/// An incoming request message.
pub(crate) type RequestHead = MessageHead<RequestLine>;

#[derive(Debug, Default, PartialEq)]
pub(crate) struct RequestLine(pub(crate) http::Method, pub(crate) http::Uri);

/// An incoming response message.
pub(crate) type ResponseHead = MessageHead<http::StatusCode>;

#[derive(Debug)]
pub(crate) enum BodyLength {
    /// Content-Length
    Known(u64),
    /// Transfer-Encoding: chunked (if h1)
    Unknown,
}

/// Status of when a Dispatcher future completes.
pub(crate) enum Dispatched {
    /// Dispatcher completely shutdown connection.
    Shutdown,
    /// Dispatcher has pending upgrade, and so did not shutdown.
    Upgrade(upgrade::Pending),
}

impl MessageHead<http::StatusCode> {
    fn into_response<B>(self, body: B) -> http::Response<B> {
        let mut res = http::Response::new(body);
        *res.status_mut() = self.subject;
        *res.headers_mut() = self.headers;
        *res.version_mut() = self.version;
        *res.extensions_mut() = self.extensions;
        res
    }
}
