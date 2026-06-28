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
}

impl<H> SelectingSink<H> {
    /// Creates a selecting sink.
    #[must_use]
    pub fn new(selectors: impl Into<Vec<JsonPath>>, handler: H) -> Self {
        Self {
            selectors: selectors.into(),
            handler,
            stack: Vec::new(),
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
                let path = self.current_value_path()?;
                self.report(&path, token)?;
                match token {
                    Token::StartObject(_) => self.stack.push(Frame::Object {
                        path,
                        pending_key: None,
                    }),
                    Token::StartArray(_) => self.stack.push(Frame::Array {
                        path,
                        next_index: 0,
                    }),
                    _ => {}
                }
            }
            Token::EndObject(_) | Token::EndArray(_) => {
                if self.stack.pop().is_none() {
                    return Err(JsonError::new(JsonErrorKind::UnexpectedToken(
                        "container end",
                    )));
                }
                self.finish_value();
            }
            Token::String(_)
            | Token::Number(_)
            | Token::True(_)
            | Token::False(_)
            | Token::Null(_) => {
                let path = self.current_value_path()?;
                self.report(&path, token)?;
                self.finish_value();
            }
            Token::Whitespace(_) | Token::Colon(_) | Token::Comma(_) => {}
        }
        Ok(())
    }
}

impl<H: SelectionHandler> SelectingSink<H> {
    fn report(&mut self, path: &ValuePath, token: Token<'_>) -> Result<(), JsonError> {
        for index in 0..self.selectors.len() {
            if self.selectors[index].matches_path(path.segments()) {
                self.handler.handle_selection(index, path, token)?;
            }
        }
        Ok(())
    }
}

impl<H> SelectingSink<H> {
    fn current_value_path(&self) -> Result<ValuePath, JsonError> {
        match self.stack.last() {
            None => Ok(ValuePath::root()),
            Some(Frame::Object { path, pending_key }) => {
                let mut value_path = path.clone();
                let Some(key) = pending_key else {
                    return Err(JsonError::new(JsonErrorKind::UnexpectedToken(
                        "object value",
                    )));
                };
                value_path.segments.push(PathElement::Member(key.clone()));
                Ok(value_path)
            }
            Some(Frame::Array { path, next_index }) => {
                let mut value_path = path.clone();
                value_path.segments.push(PathElement::Index(*next_index));
                Ok(value_path)
            }
        }
    }

    fn finish_value(&mut self) {
        match self.stack.last_mut() {
            Some(Frame::Object { pending_key, .. }) => {
                pending_key.take();
            }
            Some(Frame::Array { next_index, .. }) => {
                *next_index += 1;
            }
            None => {}
        }
    }
}

#[derive(Debug, Clone)]
enum Frame {
    Object {
        path: ValuePath,
        pending_key: Option<Box<str>>,
    },
    Array {
        path: ValuePath,
        next_index: usize,
    },
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
}
