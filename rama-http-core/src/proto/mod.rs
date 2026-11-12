//! Pieces pertaining to the HTTP message protocol.

use rama_core::extensions::Extensions;
use rama_http::io::upgrade;
use rama_http_types::{HeaderMap, Method, Response, StatusCode, Version};
use rama_net::uri::Uri;

use self::rate_budget::RateBudget;

pub(crate) mod h1;

pub(crate) use self::h1::Conn;
pub(crate) use self::h1::ServerTransaction;
pub(crate) use self::h1::dispatch;

pub(crate) mod h2;

pub(crate) mod rate_budget;

pub(crate) mod target;

/// Interim (1xx) responses a client accepts for one request by default: far above what
/// origins send, yet finite so a peer cannot hold a request open with them forever.
pub(crate) const DEFAULT_MAX_INFORMATIONAL_RESPONSES: usize = 1024;

/// Streams a connection refuses or resets for what its peer sent before it is closed, on
/// HTTP/2 and HTTP/3: the numbers established stacks use to rate limit stream resets. A
/// peer has to cause more than 33 a second, sustained after a burst of 1000.
pub(crate) const DEFAULT_REFUSED_STREAM_BUDGET: RateBudget = RateBudget::new(1000, 33);

/// What a connection closed for an exhausted refused stream budget tells its peer.
pub(crate) const TOO_MANY_REFUSED_STREAMS: &str = "too_many_refused_streams";

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
    extensions: Extensions,
}

/// An incoming request message.
pub(crate) type RequestHead = MessageHead<RequestLine>;

#[derive(Debug, Default, PartialEq)]
pub(crate) struct RequestLine(pub(crate) Method, pub(crate) Uri);

/// An incoming response message.
pub(crate) type ResponseHead = MessageHead<StatusCode>;

#[derive(Debug)]
pub(crate) enum BodyLength {
    /// `Content-Length`.
    Known(u64),
    /// `Transfer-Encoding: chunked` (if h1).
    Unknown,
}

/// Status of when a Dispatcher future completes.
pub(crate) enum Dispatched {
    /// Dispatcher completely shutdown connection.
    Shutdown,
    /// Dispatcher has pending upgrade, and so did not shutdown.
    Upgrade(upgrade::Pending),
}

impl MessageHead<StatusCode> {
    fn into_response<B>(self, body: B) -> Response<B> {
        let mut res = Response::new(body);
        *res.status_mut() = self.subject;
        *res.headers_mut() = self.headers;
        *res.version_mut() = self.version;
        res.set_extensions(self.extensions);
        res
    }
}
