//! QUIC wire types, codec, version vocabulary and profiles for Rama.
//!
//! This crate is the deterministic protocol layer beneath [`rama-quic`]: the packet and frame
//! codec, the version wire tables and negotiation vocabulary, and the typed, invariant-checked
//! [profiles](profile) describing a client's observable wire image. It has no connection state
//! machine and no async runtime, so tools that only need to read or describe QUIC on the wire —
//! user-agent emulation, fingerprinting, packet analysis — can depend on it without pulling in
//! the engine.
//!
//! # Rama
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>
//!
//! [`rama-quic`]: https://crates.io/crates/rama-quic

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

/// The longest connection ID QUIC version 1 carries, in bytes (RFC 9000 §17.2).
pub const MAX_CID_SIZE: usize = 20;

/// Maximum number of streams that can be uniquely identified by a stream ID (RFC 9000 §2.1).
pub const MAX_STREAM_COUNT: u64 = 1 << 60;

pub mod coding;

mod varint;
pub use varint::{VarInt, VarIntBoundsExceeded};

pub mod version;
pub use version::Version;

pub mod constant_time;
pub mod range_set;

mod shared;
pub use shared::{
    ConnectionId, Dir, EcnCodepoint, InvalidCid, RESET_TOKEN_SIZE, ResetToken, Side, StreamId,
};

mod transport_error;
pub use transport_error::{Code as TransportErrorCode, Error as TransportError};

pub mod frame;

pub mod crypto;

pub mod packet;

pub mod transport_parameters;

pub mod profile;

#[cfg(feature = "std")]
pub mod capture;
