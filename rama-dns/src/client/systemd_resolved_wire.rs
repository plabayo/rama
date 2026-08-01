//! RFC 1035 wire-format parsing for the systemd-resolved varlink backend:
//! `ResolveRecord` replies carry each resource record as raw wire bytes.
//! Dependency-free on purpose so fuzz builds can compile it on any host.

use rama_core::bytes::Bytes;

pub(super) const DNS_CLASS_IN: u16 = 1;
pub(super) const DNS_TYPE_TXT: u16 = 16;

pub(super) enum RrParse {
    Txt { ttl: u32, segments: Vec<Bytes> },
    Other,
    Malformed,
}

/// Parse one wire-format RR as produced by `ResolveRecord`'s `raw` field.
/// Owner names are standalone here, so compression pointers cannot be
/// resolved and are treated as malformed.
pub(super) fn parse_txt_rr(raw: &[u8]) -> RrParse {
    let Some(mut offset) = skip_uncompressed_name(raw) else {
        return RrParse::Malformed;
    };
    let Some(header) = raw.get(offset..offset + 10) else {
        return RrParse::Malformed;
    };
    let rtype = u16::from_be_bytes([header[0], header[1]]);
    let class = u16::from_be_bytes([header[2], header[3]]);
    let ttl = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let rdlen = u16::from_be_bytes([header[8], header[9]]) as usize;
    offset += 10;
    let Some(rdata) = raw.get(offset..offset + rdlen) else {
        return RrParse::Malformed;
    };
    if rtype != DNS_TYPE_TXT || class != DNS_CLASS_IN {
        return RrParse::Other;
    }
    let mut segments = Vec::new();
    let mut cursor = 0;
    while cursor < rdata.len() {
        let len = rdata[cursor] as usize;
        cursor += 1;
        let Some(segment) = rdata.get(cursor..cursor + len) else {
            return RrParse::Malformed;
        };
        segments.push(Bytes::copy_from_slice(segment));
        cursor += len;
    }
    RrParse::Txt { ttl, segments }
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
