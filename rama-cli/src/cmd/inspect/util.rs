//! Shared formatting helpers for the capture decoders.

use std::time::Duration;

use rama::{
    inspect::timeline::Section,
    net::uri::Uri,
    utils::{fmt::hex, str::arcstr::ArcStr},
};

use jiff::Timestamp;

/// Host and port of an absolute URL, or the URL itself when it has no authority.
pub(super) fn authority(url: &str) -> ArcStr {
    let Ok(uri) = url.parse::<Uri>() else {
        return url.into();
    };
    match uri.host() {
        Some(host) => format!("{host}{}", uri.port()).into(),
        None => url.into(),
    }
}

/// Offset of `at` from the capture's origin; a record before the origin sits at zero.
pub(super) fn offset(epoch: Timestamp, at: Timestamp) -> Duration {
    Duration::try_from(at - epoch).unwrap_or(Duration::ZERO)
}

/// Offset of a Unix timestamp in (fractional) seconds, as HAR's WebSocket
/// messages record them.
pub(super) fn offset_seconds(epoch: Timestamp, unix_seconds: f64) -> Duration {
    if !unix_seconds.is_finite() {
        return Duration::ZERO;
    }
    let nanos = unix_seconds * 1_000_000_000.0;
    let Ok(at) = Timestamp::from_nanosecond(nanos as i128) else {
        return Duration::ZERO;
    };
    offset(epoch, at)
}

/// A duration in milliseconds, or the unavailable marker for HAR's `-1`.
pub(super) fn optional_ms(value: Option<i64>) -> ArcStr {
    match value {
        Some(value) if value >= 0 => format!("{value} ms").into(),
        _ => Section::UNAVAILABLE.into(),
    }
}

/// A byte count, or the unavailable marker for HAR's `-1`.
pub(super) fn optional_size(value: i64) -> ArcStr {
    if value < 0 {
        Section::UNAVAILABLE.into()
    } else {
        format!("{value} bytes").into()
    }
}

/// A duration rendered compactly for a timeline column.
pub(super) fn duration(value: Duration) -> String {
    let millis = value.as_secs_f64() * 1000.0;
    if millis < 1.0 {
        format!("{millis:.3}ms")
    } else if millis < 1000.0 {
        format!("{millis:.1}ms")
    } else {
        format!("{seconds:.2}s", seconds = millis / 1000.0)
    }
}

/// Bounded, display-safe rendering of captured text.
///
/// Captured text is data: control characters are escaped so a recorded payload
/// cannot drive the terminal it is displayed in.
pub(super) fn preview(text: &str, limit: usize) -> ArcStr {
    let mut end = text.len().min(limit);
    while end < text.len() && !text.is_char_boundary(end) {
        end += 1;
    }
    let mut out = String::with_capacity(end + 32);
    for c in text[..end].chars() {
        match c {
            '\n' | '\t' => out.push(c),
            c if c.is_control() => out.extend(c.escape_debug()),
            c => out.push(c),
        }
    }
    if end < text.len() {
        out.push_str(&format!(
            "\n… truncated, {} bytes total (--max-body {limit})",
            text.len()
        ));
    }
    out.into()
}

/// Bounded hex rendering of a captured binary payload.
///
/// `0x`-prefixed upper case, the representation rama uses elsewhere for bytes
/// that are not text.
pub(super) fn hex_preview(bytes: &[u8], limit: usize) -> ArcStr {
    let end = bytes.len().min(limit);
    let mut out = format!("{:#X}", hex(&bytes[..end]));
    if end < bytes.len() {
        out.push_str(&format!(
            "\n… truncated, {} bytes total (--max-body {limit})",
            bytes.len()
        ));
    }
    out.into()
}
