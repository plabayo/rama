//! Path / query / fragment walker — shared by origin-form and
//! absolute-form parsers.
//!
//! Single-pass walk from `start` to end of `bytes`:
//! - reject control chars (always fatal)
//! - track section transitions on `?` and `#`
//! - in strict mode, validate per-section byte set + percent-escapes

use rama_core::bytes::Bytes;

use crate::uri::ParseError;

use super::ParserMode;
use super::byte_sets::{is_control_byte, is_path_byte, is_query_fragment_byte};
use super::check_pct_encoded;

/// Result of the path/query/fragment scan: where the path ends and what
/// ranges (if any) the query and fragment occupy in the parent buffer.
#[derive(Debug)]
pub(super) struct PathQueryFragment {
    pub(super) path_end: u16,
    pub(super) query: Option<(u16, u16)>,
    pub(super) fragment: Option<(u16, u16)>,
}

#[derive(Clone, Copy)]
enum Section {
    Path,
    Query,
    Fragment,
}

pub(super) fn scan_path_query_fragment(
    bytes: &Bytes,
    start: usize,
    mode: ParserMode,
) -> Result<PathQueryFragment, ParseError> {
    let len = bytes.len();
    let strict = mode == ParserMode::Strict;
    let mut section = Section::Path;
    let mut path_end = len;
    let mut query_start: Option<usize> = None;
    let mut fragment_start: Option<usize> = None;

    let mut i = start;
    while i < len {
        let b = bytes[i];
        if is_control_byte(b) {
            return Err(ParseError::ControlCharInUri { at: i, byte: b });
        }

        // Section transitions
        let transitioned = match section {
            Section::Path => match b {
                b'?' => {
                    path_end = i;
                    query_start = Some(i + 1);
                    section = Section::Query;
                    true
                }
                b'#' => {
                    path_end = i;
                    fragment_start = Some(i + 1);
                    section = Section::Fragment;
                    true
                }
                _ => false,
            },
            Section::Query => {
                if b == b'#' {
                    fragment_start = Some(i + 1);
                    section = Section::Fragment;
                    true
                } else {
                    false
                }
            }
            Section::Fragment => false,
        };
        if transitioned {
            i += 1;
            continue;
        }

        if strict {
            if b == b'%' {
                check_pct_encoded(bytes, i)?;
                i += 3;
                continue;
            }
            let ok = match section {
                Section::Path => is_path_byte(b),
                Section::Query | Section::Fragment => is_query_fragment_byte(b),
            };
            if !ok {
                return Err(ParseError::StrictViolation);
            }
        }
        i += 1;
    }

    let query_range = query_start.map(|qs| {
        let qe = fragment_start.map_or(len, |fs| fs - 1);
        (qs as u16, qe as u16)
    });
    let fragment_range = fragment_start.map(|fs| (fs as u16, len as u16));

    Ok(PathQueryFragment {
        path_end: path_end as u16,
        query: query_range,
        fragment: fragment_range,
    })
}
