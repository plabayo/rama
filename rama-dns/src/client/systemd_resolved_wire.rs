//! RFC 1035 wire-format parsing for the systemd-resolved varlink backend:
//! `ResolveRecord` replies carry each resource record as raw wire bytes.
//! Dependency-free on purpose so fuzz builds can compile it on any host.

use std::ops::Range;

use rama_core::bytes::Bytes;

#[cfg(any(target_os = "linux", all(test, target_family = "unix")))]
use crate::wire::ServiceBinding;
use crate::wire::{RecordType, Txt};

pub(super) const DNS_CLASS_IN: u16 = 1;

pub(super) enum RrParse<T> {
    Record { ttl: u32, value: T },
    Other,
    Malformed,
}

/// Parse one wire-format RR as produced by `ResolveRecord`'s `raw` field.
/// Owner names are standalone here, so compression pointers cannot be
/// resolved and are treated as malformed.
pub(super) fn parse_txt_rr(raw: &Bytes) -> RrParse<Txt> {
    let Some(rr) = parse_rr(raw) else {
        return RrParse::Malformed;
    };
    if rr.record_type != u16::from(RecordType::TXT) || rr.class != DNS_CLASS_IN {
        return RrParse::Other;
    }
    match Txt::parse_rdata_bytes(&raw.slice(rr.rdata)) {
        Ok(value) => RrParse::Record { ttl: rr.ttl, value },
        Err(_) => RrParse::Malformed,
    }
}

#[cfg(any(target_os = "linux", all(test, target_family = "unix")))]
pub(super) fn parse_service_binding_rr(
    raw: &Bytes,
    expected_type: RecordType,
) -> RrParse<ServiceBinding> {
    let Some(rr) = parse_rr(raw) else {
        return RrParse::Malformed;
    };
    if rr.record_type != u16::from(expected_type) || rr.class != DNS_CLASS_IN {
        return RrParse::Other;
    }
    let rdata = raw.slice(rr.rdata);
    match ServiceBinding::parse_rdata_bytes(&rdata) {
        Ok(value) => RrParse::Record { ttl: rr.ttl, value },
        Err(_) => RrParse::Malformed,
    }
}

struct ParsedRr {
    record_type: u16,
    class: u16,
    ttl: u32,
    rdata: Range<usize>,
}

fn parse_rr(raw: &[u8]) -> Option<ParsedRr> {
    let mut offset = skip_uncompressed_name(raw)?;
    let header_end = offset.checked_add(10)?;
    let header = raw.get(offset..header_end)?;
    let record_type = u16::from_be_bytes([header[0], header[1]]);
    let class = u16::from_be_bytes([header[2], header[3]]);
    let ttl = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let rdlen = u16::from_be_bytes([header[8], header[9]]) as usize;
    offset = header_end;
    let rdata_end = offset.checked_add(rdlen)?;
    if rdata_end != raw.len() {
        return None;
    }
    Some(ParsedRr {
        record_type,
        class,
        ttl,
        rdata: offset..rdata_end,
    })
}

fn skip_uncompressed_name(raw: &[u8]) -> Option<usize> {
    let mut offset = 0;
    loop {
        let len = *raw.get(offset)?;
        if len == 0 {
            return Some(offset + 1);
        }
        if len & 0xC0 != 0 {
            return None;
        }
        offset += 1 + len as usize;
    }
}
