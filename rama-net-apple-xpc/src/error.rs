use std::fmt;

use rama_utils::str::arcstr::ArcStr;

/// A connection-level error delivered through the XPC event stream.
///
/// After any of these variants, the connection is permanently closed.
/// See `XPC_ERROR_CONNECTION_INTERRUPTED` and `XPC_ERROR_CONNECTION_INVALID`
/// in `<xpc/connection.h>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XpcConnectionError {
    /// The remote process exited or crashed; the connection may be re-established.
    Interrupted,
    /// The connection was invalidated and cannot be recovered.
    /// The inner string is the reason reported by the kernel, if available.
    Invalidated(Option<ArcStr>),
    /// The peer did not satisfy the [`PeerSecurityRequirement`](crate::PeerSecurityRequirement)
    /// set on this connection.
    PeerRequirementFailed(Option<ArcStr>),
}

/// Errors returned by XPC operations.
#[derive(Debug)]
pub enum XpcError {
    /// A string argument contained an interior NUL byte and could not be converted to a C string.
    InvalidCString(ArcStr),
    /// `xpc_connection_create*` returned NULL.
    NullConnection(&'static str),
    /// An XPC API returned a NULL object where one was required.
    NullObject(&'static str),
    /// An XPC object had a type that this crate does not handle.
    UnsupportedObjectType(&'static str),
    /// `dispatch_queue_create` returned NULL.
    QueueCreationFailed,
    /// Applying a [`PeerSecurityRequirement`](crate::PeerSecurityRequirement) failed.
    PeerRequirementFailed { code: i32, context: &'static str },
    /// [`ReceivedXpcMessage::reply`](crate::ReceivedXpcMessage::reply) was called with a
    /// non-Dictionary message. XPC replies must be dictionaries.
    ReplyNotExpected,
    /// The connection closed before the reply callback was invoked.
    ReplyCanceled,
    /// A connection-level error received from the XPC event stream.
    Connection(XpcConnectionError),
    /// An XPC message does not conform to the expected protocol structure
    /// (e.g. missing `$selector` key, wrong argument type).
    InvalidMessage(ArcStr),
    /// A Rust value could not be serialized into an [`XpcMessage`](crate::XpcMessage).
    SerializationFailed(ArcStr),
    /// An [`XpcMessage`](crate::XpcMessage) could not be deserialized into the expected Rust type.
    DeserializationFailed(ArcStr),
}

impl fmt::Display for XpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCString(value) => write!(f, "string contains interior NUL: {value:?}"),
            Self::NullConnection(context) => {
                write!(f, "xpc connection creation returned NULL: {context}")
            }
            Self::NullObject(context) => write!(f, "xpc returned NULL object: {context}"),
            Self::UnsupportedObjectType(kind) => write!(f, "unsupported xpc object type: {kind}"),
            Self::QueueCreationFailed => f.write_str("failed to create dispatch queue"),
            Self::PeerRequirementFailed { code, context } => {
                write!(f, "xpc peer requirement failed with code {code}: {context}")
            }
            Self::ReplyNotExpected => f.write_str("incoming xpc message does not support replies"),
            Self::ReplyCanceled => {
                f.write_str("xpc reply callback dropped before delivering a response")
            }
            Self::Connection(err) => write!(f, "{err:?}"),
            Self::InvalidMessage(msg) => write!(f, "invalid xpc message structure: {msg}"),
            Self::SerializationFailed(msg) => write!(f, "xpc serialization failed: {msg}"),
            Self::DeserializationFailed(msg) => write!(f, "xpc deserialization failed: {msg}"),
        }
    }
}

impl std::error::Error for XpcError {}
