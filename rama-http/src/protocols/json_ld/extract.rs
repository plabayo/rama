use rama_core::bytes::{ByteStr, Bytes};
use std::collections::VecDeque;
use std::fmt;
use std::ops::Range;
use std::str::FromStr;

use crate::mime::Mime;
use crate::protocols::html::tokenizer::{
    EndTag, HtmlTag, ParsingAmbiguityError, StartTag, Text, TokenSink, Tokenizer,
};

use super::JsonLd;

const CHUNK_SIZE: usize = 4 * 1024;

/// Lazily extract embedded JSON-LD documents from an HTML string.
///
/// The iterator tokenizes bounded chunks as they are requested. Each item is
/// fallible because an identified application/ld+json block can contain
/// malformed JSON or lack its closing script tag.
#[must_use]
pub fn extract_from_html(html: &str) -> ExtractJsonLd<'_> {
    ExtractJsonLd::new(html)
}

/// A lazy iterator over JSON-LD data blocks embedded in HTML.
pub struct ExtractJsonLd<'html> {
    html: &'html str,
    tokenizer: Tokenizer,
    sink: ExtractSink,
    input_offset: usize,
    finished: bool,
    pending_error: Option<ExtractJsonLdError>,
}

impl<'html> ExtractJsonLd<'html> {
    fn new(html: &'html str) -> Self {
        Self {
            html,
            tokenizer: Tokenizer::new(),
            sink: ExtractSink::default(),
            input_offset: 0,
            finished: false,
            pending_error: None,
        }
    }

    fn next_candidate(&mut self) -> Option<Result<EmbeddedJsonLd<'html>, ExtractJsonLdError>> {
        let candidate = self.sink.found.pop_front()?;
        if !candidate.terminated {
            return Some(Err(ExtractJsonLdError::UnterminatedScript {
                element_range: candidate.element_range,
            }));
        }

        let Some(body) = self.html.get(candidate.body_range.clone()) else {
            return Some(Err(ExtractJsonLdError::InternalRange));
        };
        if let Err(source) = serde_json::from_str::<serde::de::IgnoredAny>(body) {
            return Some(Err(ExtractJsonLdError::InvalidJson {
                body_range: candidate.body_range,
                source,
            }));
        }

        Some(Ok(EmbeddedJsonLd {
            body,
            id: candidate.id,
            media_type: candidate.media_type,
            element_range: candidate.element_range,
            body_range: candidate.body_range,
        }))
    }
}

impl<'html> Iterator for ExtractJsonLd<'html> {
    type Item = Result<EmbeddedJsonLd<'html>, ExtractJsonLdError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(candidate) = self.next_candidate() {
                return Some(candidate);
            }
            if let Some(error) = self.pending_error.take() {
                return Some(Err(error));
            }
            if self.finished {
                return None;
            }

            if self.input_offset < self.html.len() {
                let end = (self.input_offset + CHUNK_SIZE).min(self.html.len());
                let chunk = &self.html.as_bytes()[self.input_offset..end];
                self.input_offset = end;
                if let Err(error) = self.tokenizer.write(chunk, &mut self.sink) {
                    self.finished = true;
                    self.pending_error = Some(error.into());
                }
                continue;
            }

            self.finished = true;
            match self.tokenizer.end(&mut self.sink) {
                Ok(()) => self.sink.finish(self.html.len()),
                Err(error) => self.pending_error = Some(error.into()),
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.sink.found.len(), None)
    }
}

impl std::iter::FusedIterator for ExtractJsonLd<'_> {}

/// A valid JSON-LD data block borrowed from an HTML document.
#[derive(Debug, Clone)]
pub struct EmbeddedJsonLd<'html> {
    body: &'html str,
    id: Option<ByteStr>,
    media_type: Mime,
    element_range: Range<usize>,
    body_range: Range<usize>,
}

impl<'html> EmbeddedJsonLd<'html> {
    /// Return the JSON text as parsed by the HTML tokenizer.
    #[must_use]
    pub fn body(&self) -> &'html str {
        self.body
    }

    /// Return the script element's decoded id attribute, when present.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// Return the parsed type attribute, including any media type parameters.
    #[must_use]
    pub fn media_type(&self) -> &Mime {
        &self.media_type
    }

    /// Return the complete script element's byte range in the source HTML.
    #[must_use]
    pub fn element_range(&self) -> Range<usize> {
        self.element_range.clone()
    }

    /// Return the script body's byte range in the source HTML.
    #[must_use]
    pub fn body_range(&self) -> Range<usize> {
        self.body_range.clone()
    }

    /// Deserialize the embedded document into T.
    pub fn deserialize<T>(&self) -> Result<T, serde_json::Error>
    where
        T: serde::de::DeserializeOwned,
    {
        serde_json::from_str(self.body)
    }

    /// Copy the embedded document into an owned, script-data-safe JsonLd.
    pub fn to_owned(&self) -> Result<JsonLd, serde_json::Error> {
        JsonLd::from_bytes(Bytes::copy_from_slice(self.body.as_bytes()))
    }
}

/// Error yielded while extracting an embedded JSON-LD document.
#[derive(Debug)]
pub enum ExtractJsonLdError {
    /// The HTML tokenizer rejected an ambiguous streaming context.
    Html(ParsingAmbiguityError),
    /// A JSON-LD script body was not valid JSON.
    InvalidJson {
        /// The invalid body's byte range in the source HTML.
        body_range: Range<usize>,
        /// The JSON syntax error.
        source: serde_json::Error,
    },
    /// A JSON-LD script element reached EOF without an end tag.
    UnterminatedScript {
        /// The unterminated element's byte range in the source HTML.
        element_range: Range<usize>,
    },
    /// The tokenizer produced a range outside the original input.
    InternalRange,
}

impl fmt::Display for ExtractJsonLdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Html(error) => write!(formatter, "failed to tokenize HTML: {error}"),
            Self::InvalidJson { body_range, source } => {
                write!(formatter, "invalid JSON-LD at {body_range:?}: {source}")
            }
            Self::UnterminatedScript { element_range } => {
                write!(
                    formatter,
                    "unterminated JSON-LD script at {element_range:?}"
                )
            }
            Self::InternalRange => formatter.write_str("invalid internal JSON-LD source range"),
        }
    }
}

impl std::error::Error for ExtractJsonLdError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Html(error) => Some(error),
            Self::InvalidJson { source, .. } => Some(source),
            Self::UnterminatedScript { .. } | Self::InternalRange => None,
        }
    }
}

impl From<ParsingAmbiguityError> for ExtractJsonLdError {
    fn from(value: ParsingAmbiguityError) -> Self {
        Self::Html(value)
    }
}

#[derive(Debug)]
struct Candidate {
    body_range: Range<usize>,
    element_range: Range<usize>,
    id: Option<ByteStr>,
    media_type: Mime,
    terminated: bool,
}

#[derive(Debug)]
struct OpenScript {
    element_start: usize,
    body_start: usize,
    id: Option<ByteStr>,
    media_type: Option<Mime>,
}

#[derive(Debug, Default)]
struct ExtractSink {
    cursor: usize,
    open_script: Option<OpenScript>,
    found: VecDeque<Candidate>,
}

impl ExtractSink {
    fn finish(&mut self, input_len: usize) {
        let Some(open) = self.open_script.take() else {
            return;
        };
        let Some(media_type) = open.media_type else {
            return;
        };
        self.found.push_back(Candidate {
            body_range: open.body_start..input_len,
            element_range: open.element_start..input_len,
            id: open.id,
            media_type,
            terminated: false,
        });
    }
}

impl TokenSink for ExtractSink {
    fn start_tag(&mut self, tag: &StartTag<'_>) {
        let start = self.cursor;
        self.cursor += tag.raw().len();

        if !matches!(tag.tag(), HtmlTag::Script) {
            return;
        }

        let mut id = None;
        let mut media_type = None;
        let mut saw_id = false;
        let mut saw_type = false;
        for attribute in tag.attributes() {
            if !saw_type && attribute.name().eq_ignore_ascii_case(b"type") {
                saw_type = true;
                let value = attribute.value_decoded();
                media_type = Mime::from_str(value.trim()).ok().filter(is_json_ld);
            } else if !saw_id && attribute.name().eq_ignore_ascii_case(b"id") {
                saw_id = true;
                id = Some(ByteStr::from(attribute.value_decoded().into_owned()));
            }
        }

        self.open_script = Some(OpenScript {
            element_start: start,
            body_start: self.cursor,
            id,
            media_type,
        });
    }

    fn text(&mut self, text: &Text<'_>) {
        self.cursor += text.raw().len();
    }

    fn end_tag(&mut self, tag: &EndTag<'_>) {
        let body_end = self.cursor;
        self.cursor += tag.raw().len();

        if !matches!(tag.tag(), HtmlTag::Script) {
            return;
        }
        let Some(open) = self.open_script.take() else {
            return;
        };
        let Some(media_type) = open.media_type else {
            return;
        };
        self.found.push_back(Candidate {
            body_range: open.body_start..body_end,
            element_range: open.element_start..self.cursor,
            id: open.id,
            media_type,
            terminated: true,
        });
    }

    fn comment(&mut self, comment: &crate::protocols::html::tokenizer::Comment<'_>) {
        self.cursor += comment.raw().len();
    }

    fn cdata(&mut self, cdata: &crate::protocols::html::tokenizer::Cdata<'_>) {
        self.cursor += cdata.raw().len();
    }

    fn doctype(&mut self, doctype: &crate::protocols::html::tokenizer::Doctype<'_>) {
        self.cursor += doctype.raw().len();
    }
}

fn is_json_ld(media_type: &Mime) -> bool {
    media_type.type_() == "application"
        && media_type.subtype() == "ld"
        && media_type.suffix().is_some_and(|suffix| suffix == "json")
}
