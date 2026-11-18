use rama_error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _};
use serde::de::DeserializeOwned;
use serde_json::Deserializer;

#[derive(Default)]
enum Position {
    #[default]
    Open,
    First,
    Element,
    Separator,
    Closed,
}

#[derive(Default)]
struct Boundary {
    depth: usize,
    quoted: bool,
    escaped: bool,
}

fn whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

impl Boundary {
    fn scan(&mut self, input: &[u8]) -> usize {
        for (index, &byte) in input.iter().enumerate() {
            if self.quoted {
                if self.escaped {
                    self.escaped = false;
                } else if byte == b'\\' {
                    self.escaped = true;
                } else if byte == b'"' {
                    self.quoted = false;
                }
            } else {
                match byte {
                    b'"' => self.quoted = true,
                    b'[' | b'{' => self.depth += 1,
                    b']' | b'}' if self.depth > 0 => self.depth -= 1,
                    _ if self.depth == 0 && (matches!(byte, b',' | b']') || whitespace(byte)) => {
                        return index;
                    }
                    _ => (),
                }
            }
        }
        input.len()
    }
}

#[derive(Default)]
pub(super) struct JsonArrayEngine {
    position: Position,
    partial: Vec<u8>,
    boundary: Boundary,
}

impl JsonArrayEngine {
    pub(super) fn next<T: DeserializeOwned>(
        &mut self,
        input: &mut &[u8],
        limit: usize,
    ) -> Result<Option<T>, BoxError> {
        loop {
            if self.partial.is_empty() {
                while input.first().is_some_and(|&byte| whitespace(byte)) {
                    *input = &input[1..];
                }
            }
            let Some((&byte, rest)) = input.split_first() else {
                return Ok(None);
            };
            match self.position {
                Position::Open if byte == b'[' => self.position = Position::First,
                Position::Open => return Err(BoxError::from_static_str("expected a JSON array")),
                Position::First | Position::Separator
                    if byte == b']' && self.partial.is_empty() =>
                {
                    self.position = Position::Closed
                }
                Position::Separator if byte == b',' => self.position = Position::Element,
                Position::Separator => {
                    return Err(BoxError::from_static_str(
                        "expected comma or closing array bracket",
                    ));
                }
                Position::Closed => {
                    return Err(BoxError::from_static_str("trailing data after JSON array"));
                }
                Position::First | Position::Element => {
                    if self.partial.is_empty() && matches!(byte, b',' | b']') {
                        return Err(BoxError::from_static_str("expected JSON array element"));
                    }
                    let value = self.element(input, limit)?;
                    if value.is_some() {
                        self.position = Position::Separator;
                    }
                    return Ok(value);
                }
            }
            *input = rest;
        }
    }

    fn element<T: DeserializeOwned>(
        &mut self,
        input: &mut &[u8],
        limit: usize,
    ) -> Result<Option<T>, BoxError> {
        // One byte of lookahead distinguishes an exact-limit value from an oversized one.
        let remaining = limit - self.partial.len();
        let window = &input[..input.len().min(remaining.saturating_add(1))];
        if self.partial.is_empty() {
            let mut parser = Deserializer::from_slice(window).into_iter::<T>();
            if let Some(Ok(value)) = parser.next() {
                let used = parser.byte_offset();
                if used < window.len() {
                    *input = &input[used..];
                    return Ok(Some(value));
                }
            }
        }
        // A spanning value is scanned incrementally, then deserialized once at its boundary.
        let used = self.boundary.scan(window);
        if used > remaining {
            return Err(
                BoxError::from_static_str("JSON array element exceeds byte limit")
                    .context_field("max_element_bytes", limit),
            );
        }
        let required = self.partial.len() + used;
        if required > self.partial.capacity() {
            // Grow geometrically but never past the limit, which bounds a stalled reader.
            let capacity = required
                .max(self.partial.capacity().saturating_mul(2))
                .min(limit);
            self.partial.reserve_exact(capacity - self.partial.len());
        }
        self.partial.extend_from_slice(&window[..used]);
        *input = &input[used..];
        if used == window.len() {
            return Ok(None);
        }
        let value =
            serde_json::from_slice(&self.partial).context("deserialize JSON array element")?;
        self.partial = Vec::new();
        self.boundary = Boundary::default();
        Ok(Some(value))
    }

    pub(super) fn finish(&self) -> Result<(), BoxError> {
        match self.position {
            Position::Closed => Ok(()),
            _ => Err(BoxError::from_static_str("unexpected end of JSON array")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_utils::octets::kib;
    use serde_json::{Value, json};
    use std::hint::black_box;

    fn decode<T: DeserializeOwned>(
        chunks: impl IntoIterator<Item = impl AsRef<[u8]>>,
        limit: usize,
    ) -> Result<Vec<T>, BoxError> {
        let mut engine = JsonArrayEngine::default();
        let mut values = Vec::new();
        for chunk in chunks {
            let mut input = chunk.as_ref();
            while let Some(value) = engine.next(&mut input, limit)? {
                values.push(value);
            }
            assert!(input.is_empty());
        }
        engine.finish()?;
        Ok(values)
    }

    #[test]
    fn all_split_points_match_serde() {
        for doc in [
            "[]",
            "[ ]",
            " \n [ 0 , -123 , 1.25e5 , 0.125e-9 , true , false , null ] \t\r",
            r#"["é雪","\uD83D\uDE80","a\"]},\\b",[],{},{"nested":[12,{"b":false}]}]"#,
            "[1e5,123,-1]",
            "[null,true]",
            r#"[{"a":["x",{}]}]"#,
        ] {
            let bytes = doc.as_bytes();
            let expected = serde_json::from_slice::<Vec<Value>>(bytes).unwrap();
            for cut in 0..=bytes.len() {
                assert_eq!(
                    decode::<Value>([&bytes[..cut], &bytes[cut..]], usize::MAX).unwrap(),
                    expected,
                    "{doc} at {cut}"
                );
            }
            assert_eq!(
                decode::<Value>(bytes.chunks(1), usize::MAX).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn varied_documents_and_chunk_sizes() {
        let mut state = 217_u32;
        let mut random = || {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            state
        };
        for _ in 0..128 {
            let values: Vec<_> = (0..random() % 48)
                .map(|_| {
                    let n = random();
                    match n % 4 {
                        0 => json!({"number":n,"children":[false,null]}),
                        1 => json!([n, "雪\\\""]),
                        2 => json!(n),
                        _ => json!("x".repeat((n % 47) as usize)),
                    }
                })
                .collect();
            let doc = serde_json::to_vec(&values).unwrap();
            let mut remaining = doc.as_slice();
            let chunks = std::iter::from_fn(|| {
                if remaining.is_empty() {
                    return None;
                }
                let (chunk, rest) =
                    remaining.split_at(remaining.len().min(1 + random() as usize % 32));
                remaining = rest;
                Some(chunk)
            });
            assert_eq!(decode::<Value>(chunks, usize::MAX).unwrap(), values);
        }
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self, bound: usize) -> usize {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) as usize % bound
        }
    }

    // Writes JSON by hand to cover escapes, whitespace and brackets inside strings.
    fn write_value(rng: &mut Lcg, depth: usize, out: &mut Vec<u8>) {
        const STRING_PARTS: &[&[u8]] = &[
            b"a",
            b"\\\"",
            b"\\\\",
            b"\\/",
            b"\\n",
            b"\\u00e9",
            b"\\uD83D\\uDE80",
            b"]",
            b"}",
            b",",
            b"[{",
            "雪".as_bytes(),
            b" ",
        ];
        const SPACE: &[&[u8]] = &[b"", b" ", b"\n\t", b"\r\n  "];
        let kind = if depth >= 4 { rng.next(5) } else { rng.next(7) };
        match kind {
            0 => out.extend_from_slice([&b"0"[..], b"-12", b"3.25e-4", b"1E+9"][rng.next(4)]),
            1 => out.extend_from_slice([&b"true"[..], b"false", b"null"][rng.next(3)]),
            2..=4 => {
                out.push(b'"');
                for _ in 0..rng.next(6) {
                    out.extend_from_slice(STRING_PARTS[rng.next(STRING_PARTS.len())]);
                }
                out.push(b'"');
            }
            5 => {
                out.push(b'[');
                for index in 0..rng.next(4) {
                    if index > 0 {
                        out.push(b',');
                    }
                    out.extend_from_slice(SPACE[rng.next(SPACE.len())]);
                    write_value(rng, depth + 1, out);
                }
                out.push(b']');
            }
            _ => {
                out.push(b'{');
                for index in 0..rng.next(4) {
                    if index > 0 {
                        out.push(b',');
                    }
                    write_value(rng, 4, out);
                    out.extend_from_slice(SPACE[rng.next(SPACE.len())]);
                    out.push(b':');
                    write_value(rng, depth + 1, out);
                }
                out.push(b'}');
            }
        }
    }

    fn random_chunks<'a>(rng: &mut Lcg, mut input: &'a [u8]) -> Vec<&'a [u8]> {
        let mut chunks = Vec::new();
        while !input.is_empty() {
            let (chunk, rest) = input.split_at(input.len().min(1 + rng.next(24)));
            chunks.push(chunk);
            input = rest;
        }
        chunks
    }

    #[test]
    fn agrees_with_serde_on_valid_and_corrupted_documents() {
        const NOISE: &[u8] = b"\"\\[]{},: 0a\x00\xff";
        let mut rng = Lcg(0x5eed);
        for _ in 0..4096 {
            let mut doc = vec![b'['];
            for index in 0..rng.next(6) {
                if index > 0 {
                    doc.push(b',');
                }
                write_value(&mut rng, 0, &mut doc);
            }
            doc.push(b']');
            // Half the documents are corrupted to compare error decisions too.
            if rng.next(2) == 0 {
                let at = rng.next(doc.len() + 1);
                match rng.next(4) {
                    0 => doc.truncate(at),
                    1 => doc.insert(at, NOISE[rng.next(NOISE.len())]),
                    2 if at < doc.len() => _ = doc.remove(at),
                    _ if at < doc.len() => doc[at] = NOISE[rng.next(NOISE.len())],
                    _ => doc.push(NOISE[rng.next(NOISE.len())]),
                }
            }
            let expected = serde_json::from_slice::<Vec<Value>>(&doc).ok();
            let actual = decode::<Value>(random_chunks(&mut rng, &doc), usize::MAX).ok();
            assert_eq!(actual, expected, "{}", String::from_utf8_lossy(&doc));
        }
    }

    #[test]
    fn elements_inside_one_frame_are_parsed_in_place() {
        let doc = br#"[1, {"a":"\"]"}, "x", [true], -0.5 ]"#;
        let mut engine = JsonArrayEngine::default();
        let mut input = doc.as_slice();
        let mut count = 0;
        while let Some(value) = engine.next::<Value>(&mut input, usize::MAX).unwrap() {
            black_box(value);
            count += 1;
            assert_eq!(engine.partial.capacity(), 0);
        }
        assert_eq!(count, 5);
        engine.finish().unwrap();
    }

    #[test]
    fn spanning_element_buffer_grows_progressively_up_to_the_limit() {
        let limit = kib(24);
        let mut engine = JsonArrayEngine::default();
        let mut input = b"[".as_slice();
        assert!(engine.next::<Value>(&mut input, limit).unwrap().is_none());
        // 1 KiB chunks fill the buffer exactly at each power of two.
        let mut first = [b'x'; kib(1)];
        first[0] = b'"';
        let rest = [b'x'; kib(1)];
        for index in 0..22 {
            let mut input = if index == 0 {
                first.as_slice()
            } else {
                rest.as_slice()
            };
            assert!(engine.next::<Value>(&mut input, limit).unwrap().is_none());
            let (len, capacity) = (engine.partial.len(), engine.partial.capacity());
            assert!(capacity < 2 * len, "{capacity} for {len} buffered bytes");
            assert!(capacity <= limit, "{capacity} above the limit");
        }
        let mut input = b"\"]".as_slice();
        let value = engine.next::<Value>(&mut input, limit).unwrap().unwrap();
        assert_eq!(value.as_str().map(str::len), Some(kib(22) - 1));
        assert_eq!(engine.partial.capacity(), 0);
        assert!(engine.next::<Value>(&mut input, limit).unwrap().is_none());
        engine.finish().unwrap();
    }

    #[test]
    fn invalid_arrays_and_truncation() {
        for doc in [
            "[1,]",
            "[,1]",
            "[1 2]",
            "{}",
            "[1]x",
            "[}",
            "[\u{000b}]",
            "[true false]",
        ] {
            for cut in 0..=doc.len() {
                decode::<Value>([&doc.as_bytes()[..cut], &doc.as_bytes()[cut..]], usize::MAX)
                    .unwrap_err();
            }
        }
        let doc = br#"[{"a":[true,1.4e-3]},"end"]"#;
        for end in 0..doc.len() {
            decode::<Value>(doc[..end].chunks(1), usize::MAX).unwrap_err();
        }
        decode::<u8>([br#"["wrong"]"#], usize::MAX).unwrap_err();
    }

    #[test]
    fn element_limit_excludes_surrounding_whitespace_and_delimiters() {
        let doc = br#"[ 123 , "x" ]"#;
        for size in 1..=doc.len() {
            assert_eq!(
                decode::<Value>(doc.chunks(size), 3).unwrap(),
                [json!(123), json!("x")]
            );
            decode::<Value>(doc.chunks(size), 2).unwrap_err();
        }
    }
}
