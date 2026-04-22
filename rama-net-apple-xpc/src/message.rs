use std::{collections::BTreeMap, os::fd::RawFd};

use crate::endpoint::XpcEndpoint;

/// A typed XPC value.
///
/// Covers every native XPC primitive type. XPC objects are always typed; there is no
/// dynamic or untyped variant. Unknown types received from the wire produce
/// [`XpcError::UnsupportedObjectType`](crate::XpcError::UnsupportedObjectType).
///
/// ## Notes on specific variants
///
/// - **`Fd`** — file descriptors are duplicated when received; the caller owns the fd
///   and is responsible for closing it.
/// - **`Date`** — stored as nanoseconds since the Mac absolute reference date
///   (2001-01-01 00:00:00 UTC), matching `xpc_date_get_value` / `xpc_date_create`.
/// - **`Endpoint`** — wraps a kernel endpoint object. Pass one in a message to let the
///   receiver call [`XpcEndpoint::into_connection`](crate::XpcEndpoint::into_connection)
///   without knowing a service name.
/// - **Reply messages** — [`ReceivedXpcMessage::reply`](crate::ReceivedXpcMessage::reply)
///   requires the reply to be a `Dictionary`.
#[derive(Debug, Clone, PartialEq)]
pub enum XpcMessage {
    Null,
    Bool(bool),
    Int64(i64),
    Uint64(u64),
    Double(f64),
    String(String),
    Data(Vec<u8>),
    /// File descriptor. Duplicated on receipt; the caller owns it.
    Fd(RawFd),
    /// Raw 16-byte UUID in network byte order.
    Uuid([u8; 16]),
    /// Nanoseconds since the Mac absolute reference date (2001-01-01 00:00:00 UTC).
    Date(i64),
    /// An XPC endpoint that can be sent to another process to establish a connection.
    Endpoint(XpcEndpoint),
    Array(Vec<Self>),
    Dictionary(BTreeMap<String, Self>),
}
