//! Streaming bodies for Requests and Responses
//!
//! For both [Clients](crate::client) and [Servers](crate::server), requests and
//! responses use streaming bodies, instead of complete buffering. This
//! allows applications to not use memory they don't need, and allows exerting
//! back-pressure on connections by only reading when asked.
//!
//! There are two pieces to this in rama_http_core:
//!
//! - **The [`StreamingBody`] trait** describes all possible bodies.
//!   rama_http_core allows any body type that implements `StreamingBody`, allowing
//!   applications to have fine-grained control over their streaming.
//! - **The [`Incoming`] concrete type**, which is an implementation
//!   of `StreamingBody`, and returned by rama_http_core as a "receive stream" (so, for server
//!   requests and client responses).
//!
//! There are additional implementations available in [`rama_http_types::body::util`],
//! such as a `Full` or `Empty` body
//!
//! [`StreamingBody`]: rama_http_types::body::StreamingBody

pub use rama_core::bytes::{Buf, Bytes};
pub use rama_http_types::body::{Body, Frame, SizeHint};

pub use self::incoming::Incoming;

pub(crate) use self::incoming::Sender;
pub(crate) use self::length::DecodedLength;

mod incoming;
mod length;

fn _assert_send_sync() {
    fn _assert_send<T: Send>() {}
    fn _assert_sync<T: Sync>() {}

    _assert_send::<Incoming>();
    _assert_sync::<Incoming>();
}
