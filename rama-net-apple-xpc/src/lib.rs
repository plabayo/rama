//! Apple XPC support for rama.
//!
//! > **Scope:** this crate has been developed and tested primarily with **macOS System
//! > Extensions** in mind. It may also work in other contexts — app extensions, regular
//! > apps, iOS — but those have not been tested and are not a current maintainer priority.
//! > If you have such a use case and run into issues, feel free to
//! > [open a ticket on GitHub](https://github.com/plabayo/rama/issues/new) and we can
//! > look into it together.
//!
//! XPC is Apple's inter-process communication framework. It provides structured,
//! asynchronous message passing between processes on the same machine, carried over
//! kernel Mach ports. It is the standard mechanism for privilege-separated macOS
//! system software and Network Extensions.
//!
//! This crate wraps `libxpc` with thin, async-friendly Rust types that plug directly
//! into Rama's service model. The low-level layer is a bindgen-generated `pub(crate)`
//! module; it is not part of the public API.
//!
//! # Core concepts
//!
//! ## Roles: listener and client
//!
//! **[`XpcListener`]** — binds to a launchd-registered service name and accepts
//! incoming peer connections. Each accepted connection is an [`XpcConnection`].
//!
//! **[`XpcConnection`]** — a bidirectional, async channel to a peer process. Created
//! via [`XpcConnection::connect`] on the client side, or delivered by
//! [`XpcListener::accept`] on the server side. Implements [`rama_core::Service`]
//! (fire-and-forget send) and [`rama_core::extensions::ExtensionsRef`].
//!
//! **[`XpcConnector`]** — a [`rama_core::Service`] that creates client connections;
//! drop-in for Rama client service stacks.
//!
//! **[`XpcServer`]** — a higher-level Rama-native server adapter that accepts peer
//! connections from a listener or anonymous listener connection and dispatches
//! incoming [`XpcMessage`] values into a regular Rama service.
//!
//! ## Messages
//!
//! All XPC values are represented by [`XpcMessage`], an enum covering every native
//! XPC primitive:
//!
//! | Variant | XPC type |
//! |---|---|
//! | `Null` | `XPC_TYPE_NULL` |
//! | `Bool(bool)` | `XPC_TYPE_BOOL` |
//! | `Int64(i64)` | `XPC_TYPE_INT64` |
//! | `Uint64(u64)` | `XPC_TYPE_UINT64` |
//! | `Double(f64)` | `XPC_TYPE_DOUBLE` |
//! | `String(String)` | `XPC_TYPE_STRING` |
//! | `Data(Vec<u8>)` | `XPC_TYPE_DATA` |
//! | `Fd(RawFd)` | `XPC_TYPE_FD` |
//! | `Uuid([u8; 16])` | `XPC_TYPE_UUID` |
//! | `Date(i64)` | `XPC_TYPE_DATE` (ns since 2001-01-01 UTC) |
//! | `Endpoint(XpcEndpoint)` | `XPC_TYPE_ENDPOINT` |
//! | `Array(Vec<XpcMessage>)` | `XPC_TYPE_ARRAY` |
//! | `Dictionary(BTreeMap<…>)` | `XPC_TYPE_DICTIONARY` |
//!
//! ## Endpoints
//!
//! [`XpcEndpoint`] is a serializable reference to a listener. Embed it in a message
//! and send it to a third process; that process calls [`XpcEndpoint::into_connection`]
//! to establish a peer connection without needing a launchd service name. This is the
//! canonical pattern for dynamic or ephemeral services.
//!
//! For programs that need XPC without any launchd registration, call
//! [`XpcEndpoint::anonymous_channel`] to create an anonymous listener connection plus
//! an [`XpcEndpoint`] directly — no plist required. The listener side first yields
//! [`XpcEvent::Connection`] when a peer connects, after which that peer connection
//! yields normal [`XpcEvent::Message`] values. This is also the easiest way to test
//! XPC code in-process.
//!
//! ## Message passing patterns
//!
//! - **Fire-and-forget** — [`XpcConnection::send`]: queues a message and returns.
//! - **Request-reply** — [`XpcConnection::send_request`]: awaits a reply from the peer.
//!   The server side calls [`ReceivedXpcMessage::reply`] to satisfy the future.
//!   The reply must be a `Dictionary`.
//! - **Event loop** — [`XpcConnection::recv`]: yields the next [`XpcEvent`], which is
//!   either an incoming [`Message`](XpcEvent::Message) or a connection lifecycle
//!   [`Error`](XpcEvent::Error).
//!
//! ## Security
//!
//! Set a [`PeerSecurityRequirement`] on a connection before first use to restrict which
//! processes may connect. The kernel enforces the constraint; if the peer does not
//! qualify, the connection is invalidated before any message is delivered.
//!
//! Peer identity (not subject to PID recycling races) is available via:
//! - [`XpcConnection::pid`] / [`XpcConnection::euid`] / [`XpcConnection::egid`] — process credentials
//! - [`XpcConnection::asid`] — audit session identifier (kernel-stable within a login session)
//! - [`XpcConnection::name`] — service name, if the connection was made by name
//!
//! # Gotchas
//!
//! **launchd registration required for named listeners.** [`XpcListener`] registers under
//! a Mach service name through launchd. The corresponding plist must be installed and
//! loaded before the process starts. Use [`XpcEndpoint`] for dynamic services that do not
//! have a launchd entry.
//!
//! **`NSXPCConnection` is a different protocol.** Swift/ObjC services built on
//! `NSXPCConnection` use `NSKeyedArchiver` framing inside XPC data messages. This crate
//! speaks raw `libxpc` and is not compatible with such services out of the box.
//!
//! **This is not yet the full Apple XPC surface.** The crate focuses on the raw-XPC
//! pieces needed for structured messaging, request-reply, endpoint handoff, peer
//! verification, and a first Rama-native server adapter. Typed codecs, richer
//! request-routing helpers, launchd/plist end-to-end examples, `NSXPCConnection`
//! interoperability, and some newer Apple XPC APIs are still missing. Contributions
//! are welcome.
//!
//! **`suspend`/`resume` must be balanced.** Every [`XpcConnection::suspend`] call must
//! be paired with a [`XpcConnection::resume`] before the connection is released.
//! An imbalanced suspend is a programming error that will crash the process.
//!
//! **Connections are lazy on the client side.** No handshake occurs until the first
//! message is sent. Peer requirement failures surface as
//! [`XpcConnectionError::PeerRequirementFailed`] in the event stream, not at construction.
//!
//! # Official documentation
//!
//! - XPC overview: <https://developer.apple.com/documentation/xpc>
//! - Creating XPC services: <https://developer.apple.com/documentation/xpc/creating_xpc_services>
//! - XPC connections: <https://developer.apple.com/documentation/xpc/xpc-connections?language=objc>
//! - XPC updates: <https://developer.apple.com/documentation/updates/xpc>
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/xpc.html>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png"
)]
#![doc(html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/old_logo.png")]
#![cfg(target_vendor = "apple")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]
#![cfg_attr(
    not(test),
    warn(clippy::print_stdout, clippy::dbg_macro),
    deny(clippy::unwrap_used, clippy::expect_used)
)]

mod ffi;

mod block;
mod call;
mod client;
mod connection;
mod connector;
mod endpoint;
mod error;
mod listener;
mod message;
mod object;
mod peer;
mod router;
mod server;
mod util;

pub mod xpc_serde;

pub use call::XpcCall;
pub use client::XpcClientConfig;
pub use connection::{ReceivedXpcMessage, XpcConnection, XpcEvent};
pub use connector::XpcConnector;
pub use endpoint::XpcEndpoint;
pub use error::{XpcConnectionError, XpcError};
pub use listener::{XpcListener, XpcListenerConfig};
pub use message::XpcMessage;
pub use peer::PeerSecurityRequirement;
pub use router::{XpcMessageRouter, extract_result};
pub use server::XpcServer;
pub use xpc_serde::{from_xpc_message, to_xpc_message};
