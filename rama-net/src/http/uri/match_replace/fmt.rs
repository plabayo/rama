use std::{borrow::Cow, fmt};

use rama_core::error::{ErrorContext as _, OpaqueError};
use rama_http_types::Uri;

#[derive(Clone)]
pub(super) struct UriFormatter {
    template: Cow<'static, [u8]>,
    captures: Vec<RuleCapture>,
    include_query: bool,
    literal_len: usize,
}

impl fmt::Debug for UriFormatter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("UriFormatter");
        if let Ok(s) = std::str::from_utf8(self.template.as_ref()) {
            d.field("template", &s);
        } else {
            d.field("template", &"<[u8]>");
        };
        d.field("captures", &self.captures)
            .field("include_query", &self.include_query)
            .field("literal_len", &self.literal_len)
            .finish()
    }
}

#[derive(Clone, Copy)]
struct RuleCapture {
    offset: usize,
    length: usize,
    index: usize,
}

impl fmt::Debug for RuleCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}..{}]#{}",
            self.offset,
            self.offset + self.length,
            self.index
        )
    }
}

impl UriFormatter {
    pub(super) fn template(&self) -> &[u8] {
        &self.template
    }

    pub(super) fn include_query(&self) -> bool {
        self.include_query
    }

    pub(super) fn try_new(template: Cow<'static, [u8]>) -> Result<Self, OpaqueError> {
        #[derive(Debug, PartialEq, Eq)]
        enum State {
            Literal,
            Capture,
        }
        let mut offset = 0;
        let mut state = State::Literal;

        let mut include_query = false;
        let mut captures: Vec<RuleCapture> = Default::default();

        let bytes = template.as_ref();
        let mut index = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            match state {
                State::Literal => {
                    if byte == b'$' {
                        state = State::Capture;
                        offset = index + 1;
                    } else if byte == b'?' {
                        if include_query {
                            return Err(OpaqueError::from_display(
                                "uri can only contain a single '?': multiple found",
                            ));
                        }
                        include_query = true;
                    } else {
                        // assume it is fine, uri format will fail otherwise on runtime,
                        // but that's a user issue for now, as it can be a bit tricky
                        // given we would also need to consider escaped (%) and other
                        // such stateful rules...
                        //
                        // TODO: once uri is part of rama-net we could look if this can be more exhaustive...
                        // for example by allowing such state machine to be reused here
                    }
                    index += 1;
                }
                State::Capture => {
                    if byte.is_ascii_digit() {
                        index += 1;
                    } else {
                        captures.push(try_rule_capture_from_byte_range(bytes, offset, index)?);
                        offset = index + 1;
                        state = State::Literal;
                    }
                }
            }
        }

        // trailing capture...
        if state == State::Capture {
            captures.push(try_rule_capture_from_byte_range(bytes, offset, index)?);
        }

        let literal_len =
            template.len() - captures.iter().map(|capture| capture.length).sum::<usize>();
        if literal_len + captures.len() >= MAX_URI_LEN {
            return Err(OpaqueError::from_display(
                "Uri Formatter potential length exceeds max URI length",
            ));
        }

        Ok(Self {
            template,
            captures,
            include_query,
            literal_len,
        })
    }

    pub(super) fn fmt_uri(&self, parts: &[&[u8]]) -> Result<Uri, OpaqueError> {
        let uri_len = self.literal_len + parts.iter().map(|part| part.len()).sum::<usize>();
        let mut buffer = Vec::with_capacity(uri_len); // allocate on heap already, as Uri requires this anyway

        let bytes = self.template.as_ref();
        let mut offset = 0;

        for capture in self.captures.iter() {
            buffer.extend_from_slice(&bytes[offset..capture.offset]);
            let index = capture.index - 1;
            if index < parts.len() {
                buffer.extend_from_slice(parts[index]);
            }
            offset = capture.offset + capture.length;
        }

        // (maybe) trailer data
        buffer.extend_from_slice(&bytes[offset..bytes.len()]);

        buffer.try_into().context("parse formatted bytes as Uri")
    }
}

fn try_rule_capture_from_byte_range(
    bytes: &[u8],
    offset: usize,
    index: usize,
) -> Result<RuleCapture, OpaqueError> {
    let length = index.saturating_sub(offset);
    if length == 0 || length > 2 {
        return Err(OpaqueError::from_display(
            "invalid capture raw byte length (OOR)",
        ));
    }

    let capture_index: usize = bytes[offset..offset + length]
        .iter()
        .enumerate()
        .map(|(idx, b)| {
            // b assumed to be in range 0..9 due to other cpature rules
            ((b - b'0') as usize) * 10usize.pow((length - 1 - idx) as u32)
        })
        .sum();

    if capture_index == 0 || capture_index > 16 {
        return Err(OpaqueError::from_display(
            "uri formatter is invalid: capture index has to be within inclusive range [1, 16]",
        ));
    }

    Ok(RuleCapture {
        offset: offset - 1, // add '$'
        length: length + 1,
        index: capture_index,
    })
}

// u16::MAX is reserved for None
const MAX_URI_LEN: usize = (u16::MAX - 1) as usize;

#[cfg(test)]
mod tests_try_new {
    use super::*;

    // ---------- helpers ----------

    fn mk(template: &'static str) -> Result<UriFormatter, OpaqueError> {
        UriFormatter::try_new(template.as_bytes().into())
    }

    fn cap_triples(fmt: &UriFormatter) -> Vec<(usize, usize, usize)> {
        fmt.captures
            .iter()
            .map(|c| (c.offset, c.length, c.index))
            .collect()
    }

    fn expect_ok(
        tmpl: &'static str,
        expected_caps: &[(usize, usize, usize)],
        expected_include_query: bool,
        expected_literal_len: usize,
    ) -> UriFormatter {
        let fmt = mk(tmpl).unwrap_or_else(|_| panic!("expected Ok for template: {tmpl:?}"));
        assert_eq!(
            cap_triples(&fmt),
            expected_caps,
            "captures mismatch for template: {tmpl:?}; fmt = {fmt:?}"
        );
        assert_eq!(
            fmt.include_query, expected_include_query,
            "include_query mismatch for template: {tmpl:?}; fmt = {fmt:?}"
        );

        assert_eq!(
            fmt.literal_len, expected_literal_len,
            "literal_len mismatch for template: {tmpl:?}; fmt = {fmt:?}"
        );

        // sanity check against MAX_URI_LEN bound used by constructor
        assert!(
            fmt.literal_len + fmt.captures.len() < MAX_URI_LEN,
            "sanity bound should hold for template: {tmpl:?}; fmt = {fmt:?}"
        );
        fmt
    }

    fn expect_err(tmpl: &'static str) {
        assert!(
            mk(tmpl).is_err(),
            "expected Err for template, got Ok: {tmpl:?}"
        );
    }

    // ---------- valid capture tests ----------

    #[test]
    fn valid_single_and_multi_captures() {
        struct Case<'a> {
            tmpl: &'a str,
            // tuples are (offset, length, index)
            caps: Vec<(usize, usize, usize)>,
            include_query: bool,
            literal_len: usize,
        }

        let cases = [
            Case {
                tmpl: "$1$2",
                caps: vec![(0, 2, 1), (2, 2, 2)],
                include_query: false,
                literal_len: 0,
            },
            Case {
                tmpl: "https://www.foo.com/$1",
                caps: vec![(20, 2, 1)],
                include_query: false,
                literal_len: 20,
            },
            Case {
                tmpl: "https://$1",
                caps: vec![(8, 2, 1)],
                include_query: false,
                literal_len: 8,
            },
            Case {
                tmpl: "/a/$1/b",
                caps: vec![(3, 2, 1)],
                include_query: false,
                literal_len: 5,
            },
            Case {
                tmpl: "/a/$1",
                caps: vec![(3, 2, 1)],
                include_query: false,
                literal_len: 3,
            },
            Case {
                tmpl: "/$1/x/$16/y",
                caps: vec![(1, 2, 1), (6, 3, 16)],
                include_query: false,
                literal_len: 6,
            },
            Case {
                tmpl: "/v/$8?q=1",
                caps: vec![(3, 2, 8)],
                include_query: true,
                literal_len: 7,
            },
            Case {
                tmpl: "/prefix/$12/suffix?x",
                caps: vec![(8, 3, 12)],
                include_query: true,
                literal_len: 17,
            },
            Case {
                tmpl: "$7",
                caps: vec![(0, 2, 7)],
                include_query: false,
                literal_len: 0,
            },
        ];

        for c in cases {
            expect_ok(c.tmpl, &c.caps, c.include_query, c.literal_len);
        }
    }

    #[test]
    fn valid_templates_with_no_captures() {
        let cases = [
            ("/plain/path", false),
            ("/has/query?x=1", true),
            ("justtext", false),
            ("?", true),
        ];
        for (tmpl, include_query) in cases {
            let fmt = expect_ok(tmpl, &[], include_query, tmpl.len());
            assert_eq!(
                fmt.template.as_ref(),
                tmpl.as_bytes(),
                "template bytes should be preserved"
            );
        }
    }

    // ---------- edge cases that should error ----------

    #[test]
    fn multiple_question_marks_is_error() {
        expect_err("/a?b?c");
        expect_err("?one?two");
        expect_err("/?$1?x");
    }

    #[test]
    fn capture_with_zero_length_is_error() {
        // trailing '$' never followed by a digit
        expect_err("endswith$");
        expect_err("/a/$/b");
        expect_err("$");
    }

    #[test]
    fn capture_with_non_digit_first_is_error() {
        expect_err("/a/$x");
        expect_err("prefix $- something"); // any non digit after '$'
        expect_err("$?");
    }

    #[test]
    fn capture_index_invalid_is_error() {
        expect_err("$0"); // index-1, hello Lua
        expect_err("$17"); // max 16
        expect_err("$1234");
        expect_err("/x/$0000/y");
        expect_err("pre$12345post");
    }

    #[test]
    fn literal_len_guard_trips_when_near_limit() {
        // This test is defensive. It only runs when MAX_URI_LEN is small in the current build.
        // We construct a case that should overflow based on the constructor rule:
        // potential max length is literal_len + number_of_captures.
        if MAX_URI_LEN <= 10 {
            // Use a template whose computed bound meets or exceeds MAX_URI_LEN
            // For example, 10 literal bytes and zero captures would exceed when MAX_URI_LEN <= 10
            let long_literal = "0123456789"; // len 10
            assert!(
                mk(long_literal).is_err(),
                "expected overflow error when MAX_URI_LEN is small"
            );
        }
    }

    // ---------- small deterministic fuzz ----------

    #[test]
    fn tiny_product_fuzz_no_panics() {
        // Small alphabet to explore tricky state edges
        let alphabet: &[u8] = b"$/?0123abc";
        // Generate all strings up to len 4 from this alphabet. This is deterministic and fast.
        let mut buf = [0u8; 4];

        for len in 0..=4 {
            // mixed radix odometer over the alphabet
            let mut indices = vec![0usize; len];
            loop {
                for (i, idx) in indices.iter().enumerate() {
                    buf[i] = alphabet[*idx];
                }
                let b = &buf[..len];

                // The fuzzer property: constructor never panics
                // We call it and then perform a couple of cheap invariants when Ok.
                let Ok(fmt) = UriFormatter::try_new(b.to_vec().into()) else {
                    break;
                };

                // invariant 1: capture byte ranges must be within template
                for (off, len, _) in cap_triples(&fmt) {
                    assert!(
                        off + len <= b.len(),
                        "capture range OOB for template: {b:?}, off={off}, len={len}"
                    );
                }
                // invariant 2: computed literal_len matches spec
                let expected_literal_len =
                    b.len() - fmt.captures.iter().map(|c| c.length).sum::<usize>();
                assert_eq!(
                    fmt.literal_len, expected_literal_len,
                    "fuzz: literal_len mismatch for template: {b:?}"
                );
                // invariant 3: include_query is true only when there is a '?'
                assert_eq!(
                    fmt.include_query,
                    b.contains(&b'?'),
                    "fuzz: include_query mismatch for template: {b:?}"
                );

                // increment odometer
                if len == 0 {
                    break;
                }
                let mut pos = len - 1;
                loop {
                    indices[pos] += 1;
                    if indices[pos] < alphabet.len() {
                        break;
                    }
                    indices[pos] = 0;
                    if pos == 0 {
                        // completed all strings for this length
                        pos = usize::MAX; // sentinel to break outer
                        break;
                    } else {
                        pos -= 1;
                    }
                }
                if pos == usize::MAX {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests_fmt_uri {
    use super::*;

    // ---------- helpers ----------

    fn mk(template: &'static str) -> UriFormatter {
        UriFormatter::try_new(template.as_bytes().into())
            .unwrap_or_else(|_| panic!("valid UriFormatter expected for {template:?}"))
    }

    /// Render using `fmt_uri`, returning its string form for easy assertions.
    fn render(fmt: &UriFormatter, parts: &[&[u8]]) -> Result<String, OpaqueError> {
        let uri = fmt.fmt_uri(parts)?;
        Ok(uri.to_string())
    }

    // ---------- success cases: capture substitution ----------

    #[test]
    fn substitutes_single_and_multiple_captures() {
        struct Case<'a> {
            tmpl: &'a str,
            parts: Vec<&'a [u8]>,
            want: &'a str,
        }

        let cases = [
            Case {
                tmpl: "/a/$1/b",
                parts: vec![b"X"],
                want: "/a/X/b",
            },
            Case {
                tmpl: "/$2/$1/$2",
                parts: vec![b"A", b"B"],
                want: "/B/A/B",
            },
        ];

        for c in cases.into_iter() {
            let fmt = mk(c.tmpl);
            let got = render(&fmt, &c.parts).expect("fmt_uri should succeed");
            assert_eq!(got, c.want, "template: {:?} parts: {:?}", c.tmpl, c.parts);
        }
    }

    #[test]
    fn preserves_literals_around_and_without_captures() {
        // with captures and a query
        let fmt = mk("/prefix/$1/suffix?x=1&y=$2");
        let got = render(&fmt, &[b"AA", b"BB"]).expect("fmt_uri should succeed");
        assert_eq!(got, "/prefix/AA/suffix?x=1&y=BB");

        // no captures at all
        let fmt_plain = mk("/just/literal?and=query");
        let got_plain = render(&fmt_plain, &[]).expect("fmt_uri should succeed");
        assert_eq!(got_plain, "/just/literal?and=query");
    }

    #[test]
    fn missing_parts_are_safely_skipped() {
        // "$2" with only one part means nothing is inserted for that capture
        let fmt = mk("/a/$2/b");
        let got = render(&fmt, &[b"only"]).expect("fmt_uri should succeed");
        assert_eq!(got, "/a//b", "missing part should yield empty insertion");
    }

    #[test]
    fn supports_repeated_and_adjacent_captures() {
        let fmt = mk("/$1$1/$2$2");
        let got = render(&fmt, &[b"X", b"Y"]).expect("fmt_uri should succeed");
        assert_eq!(got, "/XX/YY");
    }

    // ---------- error surfaces from Uri parsing ----------

    #[test]
    fn invalid_uri_bytes_result_in_error() {
        // raw space is typically invalid in URIs, expect parse error propagated
        let fmt = mk("/bad/$1");
        let err = render(&fmt, &[b"has space"]).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("parse formatted bytes as Uri")
                || msg.to_lowercase().contains("parse")
                || msg.to_lowercase().contains("invalid"),
            "expected parse context in error message, got: {msg}"
        );
    }

    // ---------- small deterministic fuzz ----------

    #[test]
    fn tiny_fuzz_never_panics_and_matches_simple_model() {
        let templates = ["/a/$1/b", "/$1", "/x$1y$2z", "/plain", "/q?$1&k=v"]
            .into_iter()
            .map(mk)
            .collect::<Vec<_>>();

        let parts_alphabet: &[&[u8]] = &[b"", b"a", b"Z", b"123", b"ok"];
        // generate all pairs for up to 2 parts
        let part_sets: Vec<Vec<&[u8]>> = {
            let mut sets = Vec::new();
            // len 0, 1, 2
            sets.push(vec![]);
            for p in parts_alphabet {
                sets.push(vec![*p]);
            }
            for p1 in parts_alphabet {
                for p2 in parts_alphabet {
                    sets.push(vec![*p1, *p2]);
                }
            }
            sets
        };

        for fmt in &templates {
            for parts in &part_sets {
                // 1) method should not panic and should return Result
                let res = fmt.fmt_uri(parts);

                // 2) if it succeeds, a simple reference builder should match exactly.
                // Reference builder: expand "$N" with 1-based index N if present, otherwise empty,
                // and preserve all literal bytes (including trailing).
                if let Ok(uri) = res {
                    let expected = {
                        let bytes = fmt.template.as_ref();
                        let mut out = Vec::new();
                        let mut cursor = 0usize;
                        for c in &fmt.captures {
                            // literal before capture
                            out.extend_from_slice(&bytes[cursor..c.offset]);

                            let idx0 = c.index - 1;
                            if idx0 < parts.len() {
                                out.extend_from_slice(parts[idx0]);
                            }
                            cursor = c.offset + c.length;
                        }
                        // trailing literal after last capture (or full template if no captures)
                        out.extend_from_slice(&bytes[cursor..]);
                        String::from_utf8(out).expect("expected utf8 for comparison")
                    };
                    assert_eq!(
                        uri.to_string(),
                        expected,
                        "template: {:?}, parts: {:?}",
                        String::from_utf8_lossy(fmt.template.as_ref()),
                        parts
                            .iter()
                            .map(|p| String::from_utf8_lossy(p))
                            .collect::<Vec<_>>()
                    );
                }
            }
        }
    }
}
