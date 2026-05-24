//! Best-effort breadcrumbs marking that a stream has been transformed,
//! such as moving into a decoding stream or lifted as a multiplex stream.
//! Inserted by services that decode / terminate / multiplex an outer layer;
//! observed by code that wants to either:
//!
//! * trace what happened to a connection on its way through the
//!   stack, or
//! * act on the knowledge that the bytes here are no longer the
//!   raw bytes on the wire — e.g. to skip an optimisation that
//!   only applies to untouched connections.
//!
//! **Not** a strict guarantee. Nothing enforces that every
//! transformer inserts one. Compose your stack with care first;
//! treat these as one slice in a Swiss-cheese defense and as
//! handy trace breadcrumbs.

use rama_core::extensions::Extension;

/// A handshake / transition completed on this stream: from here
/// the bytes (or their meaning) are no longer the raw wire form.
/// Examples: TLS termination, HTTP upgrade, SOCKS5 handshake,
/// HTTP/1 or HTTP/2 connection handshake.
#[derive(Debug, Clone, Copy, Extension)]
#[extension(tags(net))]
pub struct StreamTransformed {
    /// Free-form tag for the inserting site; surfaces in traces.
    pub by: &'static str,
}

/// This point sees one of several logical streams multiplexed
/// over a shared underlying transport (HTTP/2, HTTP/3, gRPC).
#[derive(Debug, Clone, Copy, Extension)]
#[extension(tags(net))]
pub struct StreamMultiplexed {
    /// Free-form tag for the inserting site; surfaces in traces.
    pub by: &'static str,
}
