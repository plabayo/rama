//! Shared sinks and the decode/encode roundtrip every exercise builds on.

use std::{any::type_name, fmt, hint::black_box};

use rama_http_types::{HeaderMap, HeaderValue};

use crate::{HeaderDecode, HeaderEncode, HeaderMapExt};

pub(super) fn sink<T>(value: T) {
    drop(black_box(value));
}

pub(super) fn debug<T: fmt::Debug>(value: &T) {
    sink(format!("{value:?}"));
}

pub(super) fn display<T: fmt::Display + ?Sized>(value: &T) {
    sink(value.to_string());
}

/// Only for hand-written `PartialEq` impls: a derived one cannot panic.
pub(super) fn eq<T: PartialEq + Clone>(value: &T) {
    sink(*value == value.clone());
}

pub(super) fn token<T: fmt::Display + fmt::Debug>(value: &T) {
    debug(value);
    display(value);
}

pub(super) fn decoded<H>(values: &[HeaderValue]) -> Option<H>
where
    H: HeaderDecode + HeaderEncode + Clone + fmt::Debug,
{
    let header = H::decode(&mut values.iter()).ok()?;
    roundtrip(&header);
    let mut encoded = Vec::new();
    header.encode(&mut encoded);
    // whatever decoded must encode to values that decode again
    assert!(
        !encoded.is_empty() && H::decode(&mut encoded.iter()).is_ok(),
        "{} decoded from {values:?} re-encodes to {encoded:?}",
        type_name::<H>(),
    );
    Some(header)
}

pub(super) fn roundtrip<H>(header: &H)
where
    H: HeaderDecode + HeaderEncode + Clone + fmt::Debug,
{
    debug(header);
    sink(header.encode_to_value());
    let mut encoded = Vec::new();
    header.encode(&mut encoded);
    if let Ok(again) = H::decode(&mut encoded.iter()) {
        debug(&again);
        sink(again.encode_to_value());
    }
    let mut map = HeaderMap::new();
    map.typed_insert(header.clone());
    sink(map.typed_try_get::<H>());
}

pub(super) fn low_u8(n: u64) -> u8 {
    let [a, ..] = n.to_le_bytes();
    a
}

pub(super) fn low_u16(n: u64) -> u16 {
    let [a, b, ..] = n.to_le_bytes();
    u16::from_le_bytes([a, b])
}

pub(super) fn low_u32(n: u64) -> u32 {
    let [a, b, c, d, ..] = n.to_le_bytes();
    u32::from_le_bytes([a, b, c, d])
}
