use std::{collections::BTreeMap, os::fd::RawFd};

use crate::endpoint::XpcEndpoint;

#[derive(Debug, Clone, PartialEq)]
pub enum XpcMessage {
    Null,
    Bool(bool),
    Int64(i64),
    Uint64(u64),
    Double(f64),
    String(String),
    Data(Vec<u8>),
    Fd(RawFd),
    /// Raw 16-byte UUID.
    Uuid([u8; 16]),
    /// Nanoseconds since the Mac absolute reference date (2001-01-01 00:00:00 UTC).
    Date(i64),
    /// An XPC endpoint that can be sent to another process to establish a connection.
    Endpoint(XpcEndpoint),
    Array(Vec<Self>),
    Dictionary(BTreeMap<String, Self>),
}
