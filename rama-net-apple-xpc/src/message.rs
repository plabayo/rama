use std::{
    collections::BTreeMap,
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
};

use crate::endpoint::XpcEndpoint;

/// A typed XPC value.
///
/// Covers every native XPC primitive type. XPC objects are always typed; there is no
/// dynamic or untyped variant. Unknown types received from the wire produce
/// [`XpcError::UnsupportedObjectType`](crate::XpcError::UnsupportedObjectType).
///
/// ## Notes on specific variants
///
/// - **`Fd`** — file descriptors are duplicated when sent and when received; the
///   descriptor is closed when the last clone of the `Arc` is dropped.
/// - **`Date`** — stored as nanoseconds since the Unix epoch, matching
///   `xpc_date_get_value` / `xpc_date_create`.
/// - **`Endpoint`** — wraps a kernel endpoint object. Pass one in a message to let the
///   receiver call [`XpcEndpoint::into_connection`](crate::XpcEndpoint::into_connection)
///   without knowing a service name.
/// - **Reply messages** — [`ReceivedXpcMessage::reply`](crate::ReceivedXpcMessage::reply)
///   requires the reply to be a `Dictionary`.
#[derive(Debug, Clone)]
pub enum XpcMessage {
    Null,
    Bool(bool),
    Int64(i64),
    Uint64(u64),
    Double(f64),
    /// A UTF-8 string.
    ///
    /// XPC strings must not contain interior NUL bytes (`\0`). Attempting to send a
    /// string with an interior NUL returns [`XpcError::InvalidCString`](crate::XpcError::InvalidCString).
    /// On receipt, the string is decoded from the C string returned by
    /// `xpc_string_get_string_ptr` using lossless UTF-8 conversion (replacement
    /// character for invalid sequences).
    String(String),
    Data(Vec<u8>),
    /// File descriptor.
    ///
    /// Sending boxes a duplicate (`xpc_fd_create`), so this value keeps its descriptor.
    /// A received descriptor is a new duplicate (`xpc_fd_dup`) owned by this value and
    /// closed when the last clone is dropped. Two `Fd` values are equal when they hold
    /// the same descriptor.
    Fd(Arc<OwnedFd>),
    /// Raw 16-byte UUID bytes.
    ///
    /// XPC does not assign meaning to UUID values — they are opaque identifiers chosen
    /// by the sender. Use a crate such as [`uuid`](https://crates.io/crates/uuid) to
    /// generate random (v4) or time-based (v7) UUIDs. The bytes are stored and
    /// transmitted in the order `xpc_uuid_create` / `xpc_uuid_get_bytes` use, which
    /// matches the standard 16-byte RFC 4122 layout (big-endian fields).
    Uuid([u8; 16]),
    /// Nanoseconds since the Unix epoch (1970-01-01 00:00:00 UTC).
    ///
    /// To capture the current time, convert a `SystemTime` to Unix nanoseconds or use
    /// `xpc_date_create_from_current` via the raw `libxpc` FFI.
    Date(i64),
    /// An XPC endpoint that can be sent to another process to establish a connection.
    ///
    /// See [`XpcEndpoint`] for the full workflow.
    Endpoint(XpcEndpoint),
    /// An ordered sequence of XPC values.
    ///
    /// XPC arrays are heterogeneous — each element may be a different `XpcMessage`
    /// variant. They are iterated in insertion order. Nested arrays and dictionaries
    /// are supported. An empty array is represented as `Array(vec![])`.
    Array(Vec<Self>),
    /// A key-value map with UTF-8 string keys.
    ///
    /// XPC dictionaries are the most common top-level message type. They are required
    /// by [`ReceivedXpcMessage::reply`](crate::ReceivedXpcMessage::reply) and by `xpc_connection_send_message_with_reply`
    /// on the protocol level. Values may be any `XpcMessage` variant, including nested
    /// dictionaries. Keys are deduplicated by XPC; if you insert the same key twice,
    /// the second value wins. The `BTreeMap` here preserves sorted key order for
    /// deterministic serialisation, though XPC itself does not guarantee key order on
    /// the wire.
    Dictionary(BTreeMap<String, Self>),
}

impl PartialEq for XpcMessage {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Int64(a), Self::Int64(b)) | (Self::Date(a), Self::Date(b)) => a == b,
            (Self::Uint64(a), Self::Uint64(b)) => a == b,
            (Self::Double(a), Self::Double(b)) => a == b,
            (Self::String(a), Self::String(b)) => a == b,
            (Self::Data(a), Self::Data(b)) => a == b,
            // an open descriptor number has one owner, so equal numbers mean the same fd
            (Self::Fd(a), Self::Fd(b)) => a.as_raw_fd() == b.as_raw_fd(),
            (Self::Uuid(a), Self::Uuid(b)) => a == b,
            (Self::Endpoint(a), Self::Endpoint(b)) => a == b,
            (Self::Array(a), Self::Array(b)) => a == b,
            (Self::Dictionary(a), Self::Dictionary(b)) => a == b,
            _ => false,
        }
    }
}
