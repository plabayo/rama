//! Sans-IO framing writer for a `multipart/form-data` body.

use super::Boundary;
use rama_core::bytes::{BufMut as _, Bytes, BytesMut};
use rama_http_types::HeaderMap;

/// Sans-IO writer of the framing of a `multipart/form-data` body.
///
/// A body is the bytes of [`part`](Self::part), then the data of that part,
/// repeated for every part, and closed by the bytes of
/// [`finish`](Self::finish). Data is written by the caller as it is, which
/// keeps what a [`Parser`](super::Parser) hands out zero-copy on its way
/// through.
///
/// Data that a parser of the same boundary yielded cannot hold the delimiter.
/// Data from anywhere else has to be free of `CRLF "--" boundary`, and so
/// does the start of the data of a part after `"--" boundary`.
#[derive(Debug)]
pub struct Encoder {
    boundary: Boundary,
    /// Whether a part was opened, after which a delimiter is led by the CRLF ending that part.
    opened: bool,
}

impl Encoder {
    /// Create an encoder for a body framed by `boundary`.
    #[must_use]
    pub fn new(boundary: &Boundary) -> Self {
        Self {
            boundary: boundary.clone(),
            opened: false,
        }
    }

    /// Open a part: the delimiter line, the header lines and the empty line
    /// after which the data of the part follows.
    pub fn part(&mut self, headers: &HeaderMap) -> Bytes {
        let headers_len: usize = headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len() + 4)
            .sum();
        let mut out = BytesMut::with_capacity(self.boundary.delimiter.len() + headers_len + 4);
        self.put_delimiter(&mut out);
        out.put_slice(b"\r\n");
        for (name, value) in headers {
            out.put_slice(name.as_str().as_bytes());
            out.put_slice(b": ");
            out.put_slice(value.as_bytes());
            out.put_slice(b"\r\n");
        }
        out.put_slice(b"\r\n");
        out.freeze()
    }

    /// Close the body: the close delimiter line.
    #[must_use]
    pub fn finish(mut self) -> Bytes {
        let mut out = BytesMut::with_capacity(self.boundary.delimiter.len() + 4);
        self.put_delimiter(&mut out);
        out.put_slice(b"--\r\n");
        out.freeze()
    }

    fn put_delimiter(&mut self, out: &mut BytesMut) {
        let from = if self.opened { 0 } else { 2 };
        out.put_slice(&self.boundary.delimiter[from..]);
        self.opened = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::multipart::{Event, FormData, ParseError, Parser};
    use rama_http_types::{HeaderValue, header::CONTENT_TYPE};

    fn boundary() -> Boundary {
        Boundary::new("b").unwrap()
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(*name, HeaderValue::from_static(value));
        }
        headers
    }

    #[test]
    fn empty_body() {
        assert_eq!(&Encoder::new(&boundary()).finish()[..], b"--b--\r\n");
    }

    #[test]
    fn framing() {
        let mut encoder = Encoder::new(&boundary());
        let mut body = Vec::new();
        body.extend_from_slice(&encoder.part(&headers(&[
            (
                "content-disposition",
                "form-data; name=\"a\"; filename=\"a.txt\"",
            ),
            ("content-type", "text/plain"),
        ])));
        body.extend_from_slice(b"first");
        body.extend_from_slice(&encoder.part(&HeaderMap::new()));
        body.extend_from_slice(&encoder.finish());
        assert_eq!(
            body.escape_ascii().to_string(),
            b"--b\r\n\
            content-disposition: form-data; name=\"a\"; filename=\"a.txt\"\r\n\
            content-type: text/plain\r\n\
            \r\nfirst\r\n--b\r\n\r\n\r\n--b--\r\n"
                .escape_ascii()
                .to_string()
        );
    }

    /// What to do with a part of the body passing through.
    enum Action {
        Forward,
        Drop,
        Replace(&'static [u8]),
    }

    /// Rewrite `input` fed in the given chunks: `decide` rules on each part, and a part named
    /// `added` is appended. Returns the output chunks.
    fn rewrite<'a>(
        chunks: impl IntoIterator<Item = &'a Bytes>,
        mut decide: impl FnMut(&FormData) -> Action,
    ) -> Result<Vec<Bytes>, ParseError> {
        let boundary = boundary();
        let mut parser = Parser::new(&boundary);
        let mut encoder = Encoder::new(&boundary);
        let mut chunks = chunks.into_iter();
        let mut out = Vec::new();
        let mut forward = false;
        loop {
            match parser.step()? {
                Event::NeedInput => match chunks.next() {
                    Some(chunk) => parser.feed(chunk.clone()),
                    None => parser.set_eof(),
                },
                Event::Part(mut headers) => {
                    let disposition = FormData::from_headers(&headers).unwrap();
                    match decide(&disposition) {
                        Action::Forward => {
                            forward = true;
                            out.push(encoder.part(&headers));
                        }
                        Action::Drop => forward = false,
                        Action::Replace(data) => {
                            forward = false;
                            headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
                            out.push(encoder.part(&headers));
                            out.push(Bytes::from_static(data));
                        }
                    }
                }
                Event::Data(data) => {
                    if forward {
                        out.push(data);
                    }
                }
                Event::PartEnd => {}
                Event::End => break,
            }
        }
        out.push(encoder.part(&headers(&[(
            "content-disposition",
            "form-data; name=\"added\"",
        )])));
        out.push(Bytes::from_static(b"by the proxy"));
        out.push(encoder.finish());
        Ok(out)
    }

    /// Parse `body` into `(name, file name, content type, data)` per part.
    fn read(body: &[u8]) -> Vec<(String, Option<String>, Option<String>, Vec<u8>)> {
        let mut parser = Parser::new(&boundary());
        let mut parts = Vec::new();
        let mut fed = false;
        loop {
            match parser.step().unwrap() {
                Event::NeedInput => {
                    assert!(!fed, "output is incomplete");
                    fed = true;
                    parser.feed(Bytes::copy_from_slice(body));
                }
                Event::Part(headers) => {
                    let disposition = FormData::from_headers(&headers).unwrap();
                    parts.push((
                        disposition.name().unwrap().to_owned(),
                        disposition.file_name().map(ToOwned::to_owned),
                        headers
                            .get(CONTENT_TYPE)
                            .map(|value| value.to_str().unwrap().to_owned()),
                        Vec::new(),
                    ));
                }
                Event::Data(data) => parts.last_mut().unwrap().3.extend_from_slice(&data),
                Event::PartEnd => {}
                Event::End => return parts,
            }
        }
    }

    const INPUT: &[u8] = b"preamble\r\n--b \r\n\
        Content-Disposition: form-data; name=\"keep\"; filename=\"k.bin\"\r\n\
        Content-Type: application/octet-stream\r\n\
        \r\n\r\n--\x00\r\n-- kept \r\n\r\n--b\r\n\
        Content-Disposition: form-data; name=\"secret\"\r\n\
        \r\nhunter2\r\n--b\r\n\
        Content-Disposition: form-data; name=\"scan\"; filename=\"virus.exe\"\r\n\
        \r\nMZ\x90\x00\r\n--b\r\n\
        Content-Disposition: form-data; name=\"tail\"\r\n\
        \r\n\r\n--b--\r\nepilogue";

    fn decide(disposition: &FormData) -> Action {
        match disposition.name() {
            Some("secret") => Action::Drop,
            Some("scan") => Action::Replace(b"removed"),
            _ => Action::Forward,
        }
    }

    fn expected() -> Vec<(String, Option<String>, Option<String>, Vec<u8>)> {
        let part =
            |name: &str, file_name: Option<&str>, content_type: Option<&str>, data: &[u8]| {
                (
                    name.to_owned(),
                    file_name.map(ToOwned::to_owned),
                    content_type.map(ToOwned::to_owned),
                    data.to_vec(),
                )
            };
        vec![
            part(
                "keep",
                Some("k.bin"),
                Some("application/octet-stream"),
                b"\r\n--\x00\r\n-- kept \r\n",
            ),
            part("scan", Some("virus.exe"), Some("text/plain"), b"removed"),
            part("tail", None, None, b""),
            part("added", None, None, b"by the proxy"),
        ]
    }

    #[test]
    fn rewrite_drops_replaces_and_adds_parts_at_every_split() {
        let whole = Bytes::from_static(INPUT);
        let out = rewrite([&whole], decide).unwrap().concat();
        assert_eq!(read(&out), expected());
        assert!(
            out.starts_with(b"--b\r\n"),
            "preamble and padding are not carried over"
        );
        assert!(
            out.ends_with(b"\r\n--b--\r\n"),
            "epilogue is not carried over"
        );
        assert!(!out.windows(7).any(|window| window == b"hunter2"));

        for at in 1..INPUT.len() {
            let (head, tail) = (whole.slice(..at), whole.slice(at..));
            let split = rewrite([&head, &tail], decide).unwrap().concat();
            assert_eq!(split, out, "split at {at}");
        }
        let bytes: Vec<Bytes> = (0..INPUT.len()).map(|at| whole.slice(at..=at)).collect();
        assert_eq!(rewrite(&bytes, decide).unwrap().concat(), out);
    }

    #[test]
    fn forwarded_data_is_not_copied() {
        let whole = Bytes::from_static(INPUT);
        let range = whole.as_ptr_range();
        let out = rewrite([&whole], decide).unwrap();
        let passed: usize = out
            .iter()
            .filter(|chunk| range.contains(&chunk.as_ptr()))
            .map(Bytes::len)
            .sum();
        assert_eq!(passed, b"\r\n--\x00\r\n-- kept \r\n".len());
    }

    #[test]
    fn rewrite_stops_at_a_malformed_body() {
        let truncated = Bytes::from_static(&INPUT[..INPUT.len() - 20]);
        assert_eq!(
            rewrite([&truncated], decide).unwrap_err(),
            ParseError::Incomplete
        );
        let smuggled = Bytes::from_static(b"--b\r\n\r\nx\r\n--bX\r\n\r\ny\r\n--b--\r\n");
        assert_eq!(
            rewrite([&smuggled], decide).unwrap_err(),
            ParseError::InvalidDelimiter
        );
    }
}
