//! HTTP Datagrams and the Capsule Protocol (RFC 9297), shared by every HTTP version.
//!
//! [`HttpDatagramSession`] runs on the upgraded I/O of any successful HTTP/1.x upgrade or
//! HTTP/2 and HTTP/3 Extended CONNECT. It sends DATAGRAM and control capsules on the
//! reliable data stream and, when the transport publishes [`NativeDatagrams`] (HTTP/3 with
//! negotiated QUIC DATAGRAM), unreliable native datagrams. [`handshake`] maps an upgrade
//! token onto each HTTP version; nothing above the session needs a version switch.

pub mod capsule;
pub mod handshake;

mod native;
pub use native::{NativeDatagramChannel, NativeDatagrams, NativeSendError, NativeSendPolicy};

mod session;
pub use session::{
    DatagramTransport, HttpDatagramSession, SessionConfig, SessionError, SessionEvent,
    SessionReceiver, SessionSender,
};
