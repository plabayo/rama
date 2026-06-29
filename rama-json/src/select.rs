//! Streaming JSONPath token selection.

use crate::path::{JsonPath, PathElement};
use crate::tokenizer::{Token, TokenSink};
use crate::{JsonError, JsonErrorKind};

/// Concrete path to a JSON value encountered in a stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValuePath {
    segments: Vec<PathElement>,
}

impl ValuePath {
    /// The root value path (`$`).
    #[must_use]
    pub fn root() -> Self {
        Self::default()
    }

    /// Concrete path segments after `$`.
    #[must_use]
    pub fn segments(&self) -> &[PathElement] {
        &self.segments
    }

    pub(crate) fn segments_mut(&mut self) -> &mut Vec<PathElement> {
        &mut self.segments
    }
}

impl std::fmt::Display for ValuePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("$")?;
        for segment in &self.segments {
            write!(f, "{segment}")?;
        }
        Ok(())
    }
}

/// Handles value tokens selected by one or more JSONPath expressions.
pub trait SelectionHandler {
    /// Handles a selected value token.
    ///
    /// `selector` is the index of the matching selector in registration order.
    fn handle_selection(
        &mut self,
        selector: usize,
        path: &ValuePath,
        token: Token<'_>,
    ) -> Result<(), JsonError>;
}

/// A [`TokenSink`] that tracks value paths and reports selected tokens.
pub struct SelectingSink<H> {
    selectors: Vec<JsonPath>,
    handler: H,
    stack: Vec<Frame>,
    path: ValuePath,
}

impl<H> SelectingSink<H> {
    /// Creates a selecting sink.
    #[must_use]
    pub fn new(selectors: impl Into<Vec<JsonPath>>, handler: H) -> Self {
        Self {
            selectors: selectors.into(),
            handler,
            stack: Vec::new(),
            path: ValuePath::root(),
        }
    }

    /// Consumes the sink and returns the wrapped handler.
    #[must_use]
    pub fn into_handler(self) -> H {
        self.handler
    }
}

impl<H: SelectionHandler> TokenSink for SelectingSink<H> {
    fn token(&mut self, token: Token<'_>) -> Result<(), JsonError> {
        match token {
            Token::ObjectKey(key) => {
                let decoded = key.decode()?;
                let Some(Frame::Object { pending_key, .. }) = self.stack.last_mut() else {
                    return Err(JsonError::new(JsonErrorKind::UnexpectedToken("object key")));
                };
                *pending_key = Some(decoded.into_boxed_str());
            }
            Token::StartObject(_) | Token::StartArray(_) => {
                let parent_path_len = self.push_value_path()?;
                self.report(token)?;
                match token {
                    Token::StartObject(_) => self.stack.push(Frame::Object {
                        parent_path_len,
                        pending_key: None,
                    }),
                    Token::StartArray(_) => self.stack.push(Frame::Array {
                        parent_path_len,
                        next_index: 0,
                    }),
                    _ => {}
                }
            }
            Token::EndObject(_) | Token::EndArray(_) => {
                let Some(frame) = self.stack.pop() else {
                    return Err(JsonError::new(JsonErrorKind::UnexpectedToken(
                        "container end",
                    )));
                };
                self.finish_value_after_path(frame.parent_path_len());
            }
            Token::String(_)
            | Token::Number(_)
            | Token::True(_)
            | Token::False(_)
            | Token::Null(_) => {
                let parent_path_len = self.push_value_path()?;
                self.report(token)?;
                self.finish_value_after_path(parent_path_len);
            }
            Token::Whitespace(_) | Token::Colon(_) | Token::Comma(_) => {}
        }
        Ok(())
    }
}

impl<H: SelectionHandler> SelectingSink<H> {
    fn report(&mut self, token: Token<'_>) -> Result<(), JsonError> {
        for index in 0..self.selectors.len() {
            if self.selectors[index].matches_path(self.path.segments()) {
                self.handler.handle_selection(index, &self.path, token)?;
            }
        }
        Ok(())
    }
}

impl<H> SelectingSink<H> {
    fn push_value_path(&mut self) -> Result<usize, JsonError> {
        let parent_path_len = self.path.segments.len();
        match self.stack.last_mut() {
            None => {}
            Some(Frame::Object { pending_key, .. }) => {
                let Some(key) = pending_key.take() else {
                    return Err(JsonError::new(JsonErrorKind::UnexpectedToken(
                        "object value",
                    )));
                };
                self.path.segments.push(PathElement::Member(key));
            }
            Some(Frame::Array { next_index, .. }) => {
                self.path.segments.push(PathElement::Index(*next_index));
            }
        }
        Ok(parent_path_len)
    }

    fn finish_value_after_path(&mut self, parent_path_len: usize) {
        self.path.segments.truncate(parent_path_len);
        match self.stack.last_mut() {
            Some(Frame::Array { next_index, .. }) => {
                *next_index += 1;
            }
            Some(Frame::Object { .. }) | None => {}
        }
    }
}

#[derive(Debug, Clone)]
enum Frame {
    Object {
        parent_path_len: usize,
        pending_key: Option<Box<str>>,
    },
    Array {
        parent_path_len: usize,
        next_index: usize,
    },
}

impl Frame {
    fn parent_path_len(&self) -> usize {
        match self {
            Self::Object {
                parent_path_len, ..
            }
            | Self::Array {
                parent_path_len, ..
            } => *parent_path_len,
        }
    }
}

impl<F> SelectionHandler for F
where
    F: FnMut(usize, &ValuePath, Token<'_>) -> Result<(), JsonError>,
{
    fn handle_selection(
        &mut self,
        selector: usize,
        path: &ValuePath,
        token: Token<'_>,
    ) -> Result<(), JsonError> {
        self(selector, path, token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokenizer::{Tokenizer, tokenize};

    #[derive(Default)]
    struct Hits {
        hits: Vec<(usize, String, Vec<u8>)>,
    }

    impl SelectionHandler for Hits {
        fn handle_selection(
            &mut self,
            selector: usize,
            path: &ValuePath,
            token: Token<'_>,
        ) -> Result<(), JsonError> {
            self.hits
                .push((selector, path.to_string(), token.raw().to_vec()));
            Ok(())
        }
    }

    #[test]
    fn selects_matching_values() {
        let selectors = vec![
            "$.store.book[*].author".parse().unwrap(),
            "$..price".parse().unwrap(),
        ];
        let mut sink = SelectingSink::new(selectors, Hits::default());
        tokenize(
            br#"{"store":{"book":[{"author":"a","price":1},{"author":"b","price":2}]}}"#,
            &mut sink,
        )
        .unwrap();
        let hits = sink.into_handler().hits;
        assert_eq!(
            hits,
            vec![
                (0, "$.store.book[0].author".to_owned(), br#""a""#.to_vec()),
                (1, "$.store.book[0].price".to_owned(), b"1".to_vec()),
                (0, "$.store.book[1].author".to_owned(), br#""b""#.to_vec()),
                (1, "$.store.book[1].price".to_owned(), b"2".to_vec()),
            ]
        );
    }

    #[test]
    fn closure_selection_handler_is_called() {
        let selectors = vec!["$..id".parse().unwrap()];
        let hits = std::cell::RefCell::new(Vec::new());
        let mut sink = SelectingSink::new(
            selectors,
            |selector: usize, path: &ValuePath, token: Token<'_>| {
                hits.borrow_mut()
                    .push((selector, path.to_string(), token.raw().to_vec()));
                Ok(())
            },
        );
        tokenize(br#"{"items":[{"id":1},{"id":2}]}"#, &mut sink).unwrap();
        assert_eq!(
            hits.into_inner(),
            vec![
                (0, "$.items[0].id".to_owned(), b"1".to_vec()),
                (0, "$.items[1].id".to_owned(), b"2".to_vec()),
            ]
        );
    }

    #[test]
    fn selection_survives_chunk_boundaries() {
        let selectors = vec!["$..id".parse().unwrap()];
        let mut sink = SelectingSink::new(selectors, Hits::default());
        let mut tokenizer = Tokenizer::new();
        for chunk in br#"{"items":[{"id":1},{"id":2}]}"#.chunks(3) {
            tokenizer.write(chunk, &mut sink).unwrap();
        }
        tokenizer.end(&mut sink).unwrap();
        let paths: Vec<_> = sink
            .into_handler()
            .hits
            .into_iter()
            .map(|(_, path, raw)| (path, raw))
            .collect();
        assert_eq!(
            paths,
            vec![
                ("$.items[0].id".to_owned(), b"1".to_vec()),
                ("$.items[1].id".to_owned(), b"2".to_vec()),
            ]
        );
    }

    #[test]
    fn selects_union_and_slice_values() {
        let selectors = vec![
            "$.items[1:4:2].id".parse().unwrap(),
            "$.items[0,2].id".parse().unwrap(),
            "$..[1].id".parse().unwrap(),
            "$..[\"missing\",3].id".parse().unwrap(),
        ];
        let mut sink = SelectingSink::new(selectors, Hits::default());
        tokenize(
            br#"{"items":[{"id":0},{"id":1},{"id":2},{"id":3}]}"#,
            &mut sink,
        )
        .unwrap();

        let hits = sink.into_handler().hits;
        assert_eq!(
            hits,
            vec![
                (1, "$.items[0].id".to_owned(), b"0".to_vec()),
                (0, "$.items[1].id".to_owned(), b"1".to_vec()),
                (2, "$.items[1].id".to_owned(), b"1".to_vec()),
                (1, "$.items[2].id".to_owned(), b"2".to_vec()),
                (0, "$.items[3].id".to_owned(), b"3".to_vec()),
                (3, "$.items[3].id".to_owned(), b"3".to_vec()),
            ]
        );
    }
}
