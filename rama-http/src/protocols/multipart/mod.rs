//! Sans-IO `multipart/form-data` codec (RFC 7578, framing per RFC 2046 §5.1.1).
//!
//! [`Parser`] turns body chunks into [`Event`]s and [`Encoder`] renders the
//! framing of a body, neither doing any I/O of its own. Part data is handed
//! out as slices of the chunks that were fed, so a body can be read, or
//! rewritten while it streams through a proxy, without buffering or copying
//! what its parts hold.
//!
//! To rewrite a body in flight, step the parser and answer each event:
//! forward a part by passing its headers to [`Encoder::part`] and its
//! [`Event::Data`] chunks through as they are, drop a part by skipping its
//! events, replace its data by writing other bytes, add a part by calling
//! [`Encoder::part`] with headers of your own, and close the body with
//! [`Encoder::finish`]. The output is framed afresh: preamble, epilogue and
//! transport padding of the input are not carried over.
//!
//! The server-side extractor built on this parser is
//! [`Multipart`](crate::service::web::extract::multipart::Multipart), the
//! client-side form builder lives in [`crate::service::client::multipart`].

use rama_core::bytes::Bytes;
use std::fmt;

mod content_disposition;
mod encoder;
mod parser;

pub use content_disposition::{FormData, InvalidContentDisposition};
pub use encoder::Encoder;
pub use parser::{Event, ParseError, Parser};

/// A validated `multipart` boundary, the `boundary` parameter of the body's
/// `Content-Type`.
#[derive(Debug, Clone)]
pub struct Boundary {
    /// `CRLF "--" boundary`.
    delimiter: Bytes,
}

impl Boundary {
    /// Longest boundary RFC 2046 §5.1.1 allows.
    pub const MAX_LEN: usize = 70;

    /// Accept a boundary of 1 to 70 printable ASCII bytes that does not end in a space.
    pub fn new(boundary: impl AsRef<[u8]>) -> Result<Self, InvalidBoundary> {
        let boundary = boundary.as_ref();
        let valid = (1..=Self::MAX_LEN).contains(&boundary.len())
            && boundary.iter().all(|b| (0x20..=0x7E).contains(b))
            && boundary.last() != Some(&b' ');
        if !valid {
            return Err(InvalidBoundary);
        }
        let mut delimiter = Vec::with_capacity(boundary.len() + 4);
        delimiter.extend_from_slice(b"\r\n--");
        delimiter.extend_from_slice(boundary);
        Ok(Self {
            delimiter: delimiter.into(),
        })
    }

    /// The boundary, without the dashes that lead a delimiter line.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.delimiter[4..]
    }

    /// `CRLF "--" boundary`, what ends the data of a part.
    fn delimiter(&self) -> Bytes {
        self.delimiter.clone()
    }
}

/// The boundary cannot frame a `multipart` body.
#[derive(Debug)]
#[non_exhaustive]
pub struct InvalidBoundary;

impl fmt::Display for InvalidBoundary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid multipart boundary")
    }
}

impl std::error::Error for InvalidBoundary {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_validation() {
        for boundary in [
            "b",
            "-",
            "---",
            "----WebKitFormBoundary7MA4YWxkTrZu0gW",
            "a b",
            "'()+_,-./:=?",
            &"x".repeat(70),
        ] {
            let parsed = Boundary::new(boundary).unwrap();
            assert_eq!(parsed.as_bytes(), boundary.as_bytes());
        }
        for boundary in ["", "b ", "a\rb", "a\nb", "a\tb", "\u{e9}", &"x".repeat(71)] {
            assert!(Boundary::new(boundary).is_err(), "{boundary:?}");
        }
    }
}
