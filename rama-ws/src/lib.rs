//! WebSocket (WS) support for rama ([RFC 6455]).
//!
//! [RFC 6455]: https://datatracker.ietf.org/doc/html/rfc6455
//!
//! # Cancel safety
//!
//! Reading messages is cancel-safe. `AsyncWebSocket` has no dedicated read
//! methods; messages arrive through its `Stream` implementation, and reading a
//! message via `StreamExt::next` follows that trait's cancel-safety: if the
//! `next()` future is dropped before it resolves (for example, as a branch of
//! `tokio::select!` that another branch completes first), no message is lost.
//! The next poll resumes from the same position in the stream.
//!
//! The `Sink` side (sending) does not carry a documented cancel-safety
//! guarantee.
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]

pub mod handshake;
pub mod protocol;
pub mod runtime;

pub use crate::protocol::{Message, ProtocolError, frame::Utf8Bytes};
pub use runtime::AsyncWebSocket;
