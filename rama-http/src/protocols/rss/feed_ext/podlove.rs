//! Podlove Simple Chapters extension
//! (<https://podlove.org/simple-chapters>).
//!
//! Inline per-episode chapter markers, distinct from Podcasting 2.0's
//! `<podcast:chapters>` (which points at an external JSON file). The
//! shape on the wire is:
//!
//! ```xml
//! <psc:chapters version="1.2">
//!   <psc:chapter start="00:00:00.000" title="Intro"/>
//!   <psc:chapter start="00:02:34.500" title="Sponsor" href="https://…"/>
//!   <psc:chapter start="00:05:42"     title="Main topic" image="https://…"/>
//! </psc:chapters>
//! ```

use std::time::Duration;

/// A `<psc:chapters>` element. Item-level only (a chapter list applies to
/// a single episode).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PodloveChapters {
    /// `version` attribute on the root element. Common values are "1.1"
    /// and "1.2"; defaults to "1.2" on serialise if empty.
    pub version: String,
    pub chapters: Vec<PodloveChapter>,
}

/// A single `<psc:chapter>` element.
#[derive(Debug, Clone, PartialEq)]
pub struct PodloveChapter {
    /// `start` attribute, parsed from `[[HH:]MM:]SS[.fff]`. Required by
    /// spec; defaults to [`Duration::ZERO`] when the attribute is missing
    /// or unparseable (matches the lenient parser policy elsewhere).
    pub start: Duration,
    /// `title` attribute. Required by spec; defaults to the empty string
    /// when absent.
    pub title: String,
    /// Optional `href` linking the chapter to a URL.
    pub href: Option<String>,
    /// Optional `image` URL.
    pub image: Option<String>,
}

/// Parse the `start` attribute syntax: `[[HH:]MM:]SS[.fff]`.
///
/// * `12.345` → 12.345 s
/// * `01:23` → 1 min 23 s
/// * `00:01:23.456` → 1 min 23.456 s
///
/// Returns [`Duration::ZERO`] on any failure (non-finite, negative, malformed).
#[must_use]
pub(crate) fn parse_start(s: &str) -> Duration {
    let s = s.trim();
    if s.is_empty() {
        return Duration::ZERO;
    }
    let mut parts = s.split(':').rev();
    let Some(secs_str) = parts.next() else {
        return Duration::ZERO;
    };
    let secs: f64 = match secs_str.parse::<f64>() {
        Ok(v) if v >= 0.0 && v.is_finite() => v,
        _ => return Duration::ZERO,
    };
    let mut total = secs;
    if let Some(min_str) = parts.next() {
        let Ok(mins) = min_str.parse::<u64>() else {
            return Duration::ZERO;
        };
        total += (mins * 60) as f64;
    }
    if let Some(hr_str) = parts.next() {
        let Ok(hours) = hr_str.parse::<u64>() else {
            return Duration::ZERO;
        };
        total += (hours * 3600) as f64;
    }
    // Reject anything left (e.g. "01:02:03:04").
    if parts.next().is_some() {
        return Duration::ZERO;
    }
    Duration::try_from_secs_f64(total).unwrap_or(Duration::ZERO)
}

/// Format a [`Duration`] as `HH:MM:SS.fff` — the canonical Podlove shape.
///
/// `parse_start` clamps anything non-finite or negative to `Duration::ZERO`,
/// so values that come from a round-trip are always sane. User-constructed
/// extreme `Duration`s (up to `Duration::MAX`) are clamped here with
/// saturating arithmetic — no overflow panic in debug builds.
#[must_use]
pub(crate) fn format_start(d: Duration) -> String {
    let total_secs = d.as_secs_f64();
    let hours = (total_secs as u64) / 3600;
    let rem = total_secs - (hours.saturating_mul(3600) as f64);
    let mins = (rem as u64) / 60;
    let secs = rem - (mins.saturating_mul(60) as f64);
    // `{:06.3}` → zero-pad to 6 chars, 3 fractional digits (e.g. "05.700").
    format!("{hours:02}:{mins:02}:{secs:06.3}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_parse_round_trips() {
        for &(s, want_secs) in &[
            ("12.345", 12.345_f64),
            ("01:23", 83.0),
            ("01:23.5", 83.5),
            ("00:01:23.456", 83.456),
            ("02:03:04.000", 7384.0),
        ] {
            let d = parse_start(s);
            let got = d.as_secs_f64();
            assert!(
                (got - want_secs).abs() < 1e-6,
                "{s:?} → {got} (want {want_secs})",
            );
        }
    }

    #[test]
    fn start_parse_rejects_garbage() {
        for s in ["", "abc", "1:2:3:4", "-5", "inf", "nan"] {
            assert_eq!(parse_start(s), Duration::ZERO, "{s:?}");
        }
    }

    #[test]
    fn start_format_shape() {
        assert_eq!(format_start(Duration::ZERO), "00:00:00.000");
        assert_eq!(
            format_start(Duration::from_secs_f64(83.456)),
            "00:01:23.456",
        );
        assert_eq!(
            format_start(Duration::from_secs_f64(7384.0)),
            "02:03:04.000",
        );
    }
}
