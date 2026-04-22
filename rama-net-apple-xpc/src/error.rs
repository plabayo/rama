use std::fmt;

use rama_utils::str::arcstr::ArcStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XpcConnectionError {
    Interrupted,
    Invalidated(Option<String>),
    PeerRequirementFailed(Option<String>),
}

#[derive(Debug)]
pub enum XpcError {
    InvalidCString(ArcStr),
    NullConnection(&'static str),
    NullObject(&'static str),
    UnsupportedObjectType(&'static str),
    QueueCreationFailed,
    PeerRequirementFailed { code: i32, context: &'static str },
    ReplyNotExpected,
    Connection(XpcConnectionError),
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
            Self::Connection(err) => write!(f, "{err:?}"),
        }
    }
}

impl std::error::Error for XpcError {}
