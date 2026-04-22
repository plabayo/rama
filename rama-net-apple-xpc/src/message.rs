use std::{collections::BTreeMap, os::fd::RawFd};

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
    Array(Vec<Self>),
    Dictionary(BTreeMap<String, Self>),
}
