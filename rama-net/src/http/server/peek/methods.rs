use super::{HttpMethodMode, MethodList};

pub(super) const STANDARD: MethodList = &[
    "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "QUERY", "TRACE",
];
pub(super) const EXTENSIONS: MethodList = &[
    "ACL",
    "BASELINE-CONTROL",
    "BIND",
    "CHECKIN",
    "CHECKOUT",
    "COPY",
    "LABEL",
    "LINK",
    "LOCK",
    "M-SEARCH",
    "MERGE",
    "MKACTIVITY",
    "MKCALENDAR",
    "MKCOL",
    "MKREDIRECTREF",
    "MKWORKSPACE",
    "MOVE",
    "NOTIFY",
    "ORDERPATCH",
    "PRI",
    "PROPFIND",
    "PROPPATCH",
    "PURGE",
    "REBIND",
    "REPORT",
    "SEARCH",
    "SUBSCRIBE",
    "UNBIND",
    "UNCHECKOUT",
    "UNLINK",
    "UNLOCK",
    "UNSUBSCRIBE",
    "UPDATE",
    "UPDATEREDIRECTREF",
    "VERSION-CONTROL",
];

// Rust builds this shared table at compile time. Bit i identifies the ith
// name in STANDARD followed by EXTENSIONS. BY_POSITION[offset][byte - b' ']
// contains the bits for every method with that byte at that offset. Each
// name also contributes a space immediately after its final byte.
//
// A peeker carries one u64 of still-possible methods across reads. In
// Standard mode, 'P' leaves PATCH, POST and PUT. Intersecting with the
// second-byte 'O' mask leaves POST. A space at offset 2 clears that bit
// ("PO " is incomplete), while a space after "POST" preserves it.
const WIDTH: usize = (b'Z' - b' ' + 1) as usize;
// Longest supported name plus its delimiter. An overlong entry fails the build.
const ROWS: usize = 18;
const STANDARD_BITS: u64 = (1 << STANDARD.len()) - 1;
static BY_POSITION: [[u64; WIDTH]; ROWS] = {
    let mut rows = [[0; WIDTH]; ROWS];
    let mut index = 0;
    while index < STANDARD.len() + EXTENSIONS.len() {
        let name = if index < STANDARD.len() {
            STANDARD[index]
        } else {
            EXTENSIONS[index - STANDARD.len()]
        };
        let bit = 1u64 << index;
        let bytes = name.as_bytes();
        let mut position = 0;
        while position < bytes.len() {
            rows[position][(bytes[position] - b' ') as usize] |= bit;
            position += 1;
        }
        rows[position][0] |= bit;
        index += 1;
    }
    rows
};

// One row per byte position. An exclusion becomes decisive on its final
// token byte, so the end mask belongs to that row, without a delimiter.
#[derive(Debug, Clone)]
pub(super) struct ExclusionRow {
    letters: [u64; 94], // printable ASCII from '!' through '~'
    ends: u64,
}

#[derive(Debug, Clone)]
pub(super) enum MethodMatcher {
    Known(u64),
    Any,
    Mask {
        rows: std::sync::Arc<[ExclusionRow]>,
        remaining: u64,
    },
    Sorted {
        names: std::sync::Arc<[&'static str]>,
        range: std::ops::Range<usize>,
    },
}

impl From<HttpMethodMode> for MethodMatcher {
    fn from(mode: HttpMethodMode) -> Self {
        match mode {
            HttpMethodMode::Standard => Self::Known(STANDARD_BITS),
            HttpMethodMode::Extended => Self::Known(u64::MAX),
            HttpMethodMode::Any => Self::Any,
            HttpMethodMode::ExceptMethod(list) => Self::excluding(list),
        }
    }
}

impl MethodMatcher {
    fn excluding(list: &[&'static str]) -> Self {
        let mut names: Vec<_> = list
            .iter()
            .copied()
            .filter(|name| rama_utils::byte_set::is_http_token(name.as_bytes()))
            .collect();
        names.sort_unstable();
        names.dedup();
        let Some(longest) = names.iter().map(|name| name.len()).max() else {
            return Self::Any;
        };
        // Keep the dense index within 24 KiB even for a single unusually long
        // token. The sorted index stores references regardless of token length.
        if names.len() <= u64::BITS as usize && longest <= 32 {
            let mut rows = vec![
                ExclusionRow {
                    letters: [0; 94],
                    ends: 0
                };
                longest
            ];
            for (index, name) in names.iter().enumerate() {
                let bit = 1u64 << index;
                for (row, byte) in rows.iter_mut().zip(name.bytes()) {
                    row.letters[(byte - b'!') as usize] |= bit;
                }
                rows[name.len() - 1].ends |= bit;
            }
            Self::Mask {
                rows: rows.into(),
                remaining: u64::MAX,
            }
        } else {
            Self::Sorted {
                range: 0..names.len(),
                names: names.into(),
            }
        }
    }

    pub(super) fn accepts_byte(&mut self, position: usize, byte: u8) -> bool {
        match self {
            Self::Known(candidates) => {
                let column = byte.wrapping_sub(b' ') as usize;
                *candidates &= BY_POSITION
                    .get(position)
                    .and_then(|row| row.get(column))
                    .copied()
                    .unwrap_or(0);
                *candidates != 0
            }
            Self::Any => true,
            Self::Mask { rows, remaining } => {
                if byte == b' ' || *remaining == 0 {
                    return true;
                }
                let Some(row) = rows.get(position) else {
                    return true;
                };
                *remaining &= row.letters[(byte - b'!') as usize];
                *remaining & row.ends == 0
            }
            Self::Sorted { names, range } => {
                if byte == b' ' || range.start == range.end {
                    return true;
                }
                // Every candidate already matched the preceding bytes. Within
                // that range the next bytes are sorted, and an exact match
                // precedes every longer name with the same prefix.
                let candidates = &names[range.clone()];
                let low = candidates.partition_point(|name| name.as_bytes()[position] < byte);
                let tail = &candidates[low..];
                let count = tail.partition_point(|name| name.as_bytes()[position] == byte);
                range.start += low;
                range.end = range.start + count;
                count == 0 || tail[0].len() != position + 1
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_exclusion_indexes_match_the_literal_oracle() {
        // Adjacent pairs are distinct valid tokens and exercise punctuation
        // and case. Keep one overlapping pair in every configuration.
        const ALPHABET: &str =
            "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz~!#$%&'*+-.";
        const LONG: &str = "X-this-method-exceeds-the-small-table-length";
        for (count, long) in [(1, false), (63, false), (64, false), (65, false), (2, true)] {
            let mut names = vec!["X-private"];
            if long {
                names.push(LONG);
            } else if count > 1 {
                names.push("X-private-extension");
                names.extend((0..count - 2).map(|i| &ALPHABET[i..i + 2]));
            }
            let matcher = MethodMatcher::excluding(&names);
            assert_eq!(
                matches!(matcher, MethodMatcher::Sorted { .. }),
                count > 64 || long
            );
            for name in names
                .iter()
                .copied()
                .chain(["X", "X-Private", "x-private", "MISSING", ""])
            {
                for offset in 0..=name.len() {
                    for next in
                        (0..=127).filter(|&b| rama_utils::byte_set::is_http_tchar(b) || b == b' ')
                    {
                        let mut input = name.as_bytes()[..offset].to_vec();
                        input.push(next);
                        let expected = names.iter().any(|item| input.starts_with(item.as_bytes()));
                        let mut cursor = matcher.clone();
                        let excluded = input
                            .iter()
                            .enumerate()
                            .any(|(i, &b)| !cursor.accepts_byte(i, b));
                        assert_eq!(excluded, expected, "{count} names, {input:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn every_prefix_and_next_byte_agrees_with_literal_matching() {
        for mode in [HttpMethodMode::Standard, HttpMethodMode::Extended] {
            let mut names = STANDARD.to_vec();
            if mode == HttpMethodMode::Extended {
                names.extend_from_slice(EXTENSIONS);
            }
            for name in STANDARD.iter().chain(EXTENSIONS) {
                let mut matcher = MethodMatcher::from(mode);
                for offset in 0..=name.len() {
                    let prefix = &name.as_bytes()[..offset];
                    for byte in 0..=u8::MAX {
                        let expected = names.iter().any(|candidate| {
                            candidate
                                .as_bytes()
                                .strip_prefix(prefix)
                                .is_some_and(|tail| {
                                    if byte == b' ' {
                                        tail.is_empty()
                                    } else {
                                        tail.first() == Some(&byte)
                                    }
                                })
                        });
                        let mut probe = matcher.clone();
                        assert_eq!(
                            probe.accepts_byte(offset, byte),
                            expected,
                            "{mode:?} {name} at {offset}, byte {byte}"
                        );
                    }
                    if let Some(&next) = name.as_bytes().get(offset) {
                        matcher.accepts_byte(offset, next);
                    }
                }
            }
        }
    }
}
