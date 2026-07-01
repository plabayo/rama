//! This module contains the low-level NDJSON parsing logic in the form of the [NdjsonEngine]. You
//! should usually not have to use this directly, but rather access a higher-level interface such as
//! iterators.

use crate::std::collections::VecDeque;
use core::str;

use serde::Deserialize;
use serde::de::Error as _;
use serde_json::error::Result as JsonResult;

use super::config::{EmptyLineHandling, ParseConfig};

const NEW_LINE: u8 = b'\n';

/// The low-level engine parsing NDJSON-data given as byte slices into objects of the type parameter
/// `T`. Data is supplied in chunks and parsed objects can subsequently be read from a queue.
///
/// Users of this crate should usually not have to use this struct but rather a higher-level
/// interface such as iterators.
pub(super) struct NdjsonEngine<T> {
    in_queue: Vec<u8>,
    out_queue: VecDeque<JsonResult<T>>,
    config: ParseConfig,
    /// Set when an oversized line was detected mid-stream. Bytes are dropped until the next
    /// newline; once that newline arrives the engine resumes normal operation.
    skipping_oversized_line: bool,
}

impl<T> NdjsonEngine<T> {
    /// Creates a new NDJSON-engine for objects of the given type parameter with default
    /// [ParseConfig].
    pub(super) fn new() -> Self {
        Self::with_config(ParseConfig::default())
    }

    /// Creates a new NDJSON-engine for objects of the given type parameter with the given
    /// [ParseConfig] to control its behavior. See [ParseConfig] for more details.
    pub(super) fn with_config(config: ParseConfig) -> Self {
        Self {
            in_queue: Vec::new(),
            out_queue: VecDeque::new(),
            config,
            skipping_oversized_line: false,
        }
    }

    /// Reads the next element from the queue of parsed items, if sufficient NDJSON-data has been
    /// supplied previously via [NdjsonEngine::input], that is, a newline character has been
    /// observed. If the input until the newline is not valid JSON, the parse error is returned. If
    /// no element is available in the queue, `None` is returned.
    pub(super) fn pop(&mut self) -> Option<JsonResult<T>> {
        self.out_queue.pop_front()
    }
}

fn is_blank(string: &str) -> bool {
    string.chars().all(char::is_whitespace)
}

fn oversized_line_error(max: usize) -> serde_json::Error {
    serde_json::Error::custom(format_args!(
        "ndjson line exceeded configured max_line_bytes ({max}); resynchronising to next newline",
    ))
}

fn parse_line<T>(bytes: &[u8], empty_line_handling: EmptyLineHandling) -> Option<JsonResult<T>>
where
    for<'deserialize> T: Deserialize<'deserialize>,
{
    let should_ignore = match empty_line_handling {
        EmptyLineHandling::ParseAlways => false,
        EmptyLineHandling::IgnoreEmpty => bytes.is_empty() || bytes == *b"\r",
        EmptyLineHandling::IgnoreBlank => str::from_utf8(bytes).is_ok_and(is_blank),
    };

    if should_ignore {
        None
    } else {
        Some(serde_json::from_slice(bytes))
    }
}

impl<T> NdjsonEngine<T>
where
    for<'deserialize> T: Deserialize<'deserialize>,
{
    /// Parses the given data as NDJSON. In case the end does not match up with a newline, the rest
    /// is stored in an internal cache. Consequently, the rest from a previous call to this method
    /// is prepended to the given data in case a newline is encountered.
    pub(super) fn input(&mut self, data: impl AsRef<[u8]>) {
        let mut data = data.as_ref();
        let max_line_bytes = self.config.max_line_bytes.map(core::num::NonZeroUsize::get);

        while let Some(newline_idx) = data.iter().position(|item| *item == NEW_LINE) {
            let data_until_split = &data[..newline_idx];

            if self.skipping_oversized_line {
                // The previous oversized line ends here; drop these bytes and resume.
                self.skipping_oversized_line = false;
                data = &data[(newline_idx + 1)..];
                continue;
            }

            if let Some(max) = max_line_bytes
                && self.in_queue.len().saturating_add(data_until_split.len()) > max
            {
                self.in_queue.clear();
                self.out_queue.push_back(Err(oversized_line_error(max)));
                data = &data[(newline_idx + 1)..];
                continue;
            }

            let next_item_bytes = if self.in_queue.is_empty() {
                data_until_split
            } else {
                self.in_queue.extend_from_slice(data_until_split);
                &self.in_queue
            };

            if let Some(item) = parse_line(next_item_bytes, self.config.empty_line_handling) {
                self.out_queue.push_back(item);
            }

            self.in_queue.clear();
            data = &data[(newline_idx + 1)..];
        }

        if self.skipping_oversized_line {
            // Still searching for a newline; drop trailing bytes.
            return;
        }

        if let Some(max) = max_line_bytes
            && self.in_queue.len().saturating_add(data.len()) > max
        {
            self.in_queue.clear();
            self.out_queue.push_back(Err(oversized_line_error(max)));
            self.skipping_oversized_line = true;
            return;
        }

        self.in_queue.extend_from_slice(data);
    }

    /// Parses the rest leftover from previous calls to [NdjsonEngine::input], i.e. the data after
    /// the last given newline character, if all of the following conditions are met.
    ///
    /// * The engine uses a config with [ParseConfig::with_parse_rest] set to `true`.
    /// * There is non-empty data left to parse. In other words, the previous provided input did not
    ///   end with a newline character.
    /// * The rest is not considered empty by the handling configured in
    ///   [ParseConfig::with_empty_line_handling]. That is, if the rest consists only of whitespace
    ///   and [EmptyLineHandling::IgnoreBlank] is used, the rest is not parsed.
    ///
    /// In any case, the rest is discarded from the input buffer. Therefore, this function is
    /// idempotent.
    ///
    /// Note: This function is intended to be called after the input ended, but there is no
    /// validation in place to check that [NdjsonEngine::input] is not called afterwards. Doing this
    /// anyway may lead to unexpected behavior, as JSON-lines may be partially discarded.
    pub(super) fn finalize(&mut self) {
        if self.skipping_oversized_line {
            // The oversized-line error has already been emitted; discard any tail bytes
            // and reset so the engine is reusable.
            self.in_queue.clear();
            self.skipping_oversized_line = false;
            return;
        }
        if self.config.parse_rest {
            let empty_line_handling = match self.config.empty_line_handling {
                EmptyLineHandling::ParseAlways => EmptyLineHandling::IgnoreEmpty,
                empty_line_handling @ (EmptyLineHandling::IgnoreBlank
                | EmptyLineHandling::IgnoreEmpty) => empty_line_handling,
            };

            if let Some(item) = parse_line(&self.in_queue, empty_line_handling) {
                self.out_queue.push_back(item);
            }
        }

        self.in_queue.clear();
    }
}

impl<T> Default for NdjsonEngine<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::iter;
    use serde_json::error::Result as JsonResult;

    #[derive(Debug, Deserialize, Eq, PartialEq)]
    struct TestStruct {
        key: u64,
        value: u64,
    }

    fn collect_output(mut engine: NdjsonEngine<TestStruct>) -> Vec<JsonResult<TestStruct>> {
        iter::from_fn(|| engine.pop()).collect::<Vec<_>>()
    }

    #[test]
    fn no_input() {
        let engine: NdjsonEngine<TestStruct> = NdjsonEngine::new();

        assert!(collect_output(engine).is_empty());
    }

    #[test]
    fn incomplete_input() {
        let mut engine: NdjsonEngine<TestStruct> = NdjsonEngine::new();

        engine.input("{\"key\":3,\"val");

        assert!(collect_output(engine).is_empty());
    }

    #[test]
    fn single_exact_input() {
        let mut engine: NdjsonEngine<TestStruct> = NdjsonEngine::new();

        engine.input("{\"key\":3,\"value\":4}\n");

        let mut result = collect_output(engine).into_iter();
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct { key: 3, value: 4 }
        );
        assert!(result.next().is_none());
    }

    #[test]
    fn single_item_split_into_two_inputs() {
        let mut engine: NdjsonEngine<TestStruct> = NdjsonEngine::new();

        engine.input("{\"key\":42,");
        engine.input("\"value\":24}\n");

        let mut result = collect_output(engine).into_iter();
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct { key: 42, value: 24 }
        );
        assert!(result.next().is_none());
    }

    #[test]
    fn two_items_in_single_input() {
        let mut engine: NdjsonEngine<TestStruct> = NdjsonEngine::new();

        engine.input("{\"key\":1,\"value\":1}\n{\"key\":2,\"value\":2}\n");

        let mut result = collect_output(engine).into_iter();
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct { key: 1, value: 1 }
        );
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct { key: 2, value: 2 }
        );
        assert!(result.next().is_none());
    }

    #[test]
    fn two_items_in_many_inputs_with_rest() {
        let mut engine: NdjsonEngine<TestStruct> = NdjsonEngine::new();

        engine.input("{\"key\":12,\"v");
        engine.input("alue\":3");
        engine.input("4}\n{\"key");
        engine.input("\":56,\"valu");
        engine.input("e\":78}\n{\"key\":");

        let mut result = collect_output(engine).into_iter();
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct { key: 12, value: 34 }
        );
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct { key: 56, value: 78 }
        );
        assert!(result.next().is_none());
    }

    #[test]
    fn input_completing_previous_rest_then_multiple_complete_items_and_more_rest() {
        let mut engine: NdjsonEngine<TestStruct> = NdjsonEngine::new();

        engine.input("{\"key\":9,\"value\":");
        engine.input("8}\n{\"key\":7,\"value\":6}\n{\"key\":5,\"value\":4}\n{\"key\":");
        engine.input("3,\"value\":2}\n{");

        let mut result = collect_output(engine).into_iter();
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct { key: 9, value: 8 }
        );
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct { key: 7, value: 6 }
        );
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct { key: 5, value: 4 }
        );
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct { key: 3, value: 2 }
        );
        assert!(result.next().is_none());
    }

    #[test]
    fn carriage_return_handled_gracefully() {
        let mut engine: NdjsonEngine<TestStruct> = NdjsonEngine::new();

        engine.input("{\"key\":1,\"value\":2}\r\n{\"key\":3,\"value\":4}\r\n");

        let mut result = collect_output(engine).into_iter();
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct { key: 1, value: 2 }
        );
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct { key: 3, value: 4 }
        );
        assert!(result.next().is_none());
    }

    #[test]
    fn whitespace_handled_gracefully() {
        let mut engine: NdjsonEngine<TestStruct> = NdjsonEngine::new();

        engine.input("\t{ \"key\":\t13,  \"value\":   37 } \r\n");

        let mut result = collect_output(engine).into_iter();
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct { key: 13, value: 37 }
        );
        assert!(result.next().is_none());
    }

    #[test]
    fn erroneous_entry_emitted_as_json_error() {
        let mut engine: NdjsonEngine<TestStruct> = NdjsonEngine::new();

        engine.input("{\"key\":1}\n{\"key\":1,\"value\":1}\n");

        let mut result = collect_output(engine).into_iter();
        result.next().unwrap().unwrap_err();
        result.next().unwrap().unwrap();
        assert!(result.next().is_none());
    }

    #[test]
    fn error_from_split_entry() {
        let mut engine: NdjsonEngine<TestStruct> = NdjsonEngine::new();

        engine.input("{\"key\":100,\"value\":200}\n{\"key\":");
        engine.input("\"should be a number\",\"value\":0}\n{\"key\":300,\"value\":400}\n");

        let mut result = collect_output(engine).into_iter();
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct {
                key: 100,
                value: 200
            }
        );
        result.next().unwrap().unwrap_err();
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct {
                key: 300,
                value: 400
            }
        );
        assert!(result.next().is_none());
    }

    #[test]
    fn old_data_is_discarded() {
        let mut engine: NdjsonEngine<TestStruct> = NdjsonEngine::new();
        let count = 20;

        engine.input("{ \"key\": 1, ");

        for _ in 0..(count - 1) {
            engine.input("\"value\": 2 }\r\n{ \"key\": 1, ");
        }

        engine.input("\"value\": 2 }\r\n");

        assert!(engine.in_queue.is_empty());
        assert_eq!(count, engine.out_queue.len());
    }

    fn configured_engine(
        configure: impl FnOnce(ParseConfig) -> ParseConfig,
    ) -> NdjsonEngine<TestStruct> {
        let config = configure(ParseConfig::default());
        NdjsonEngine::with_config(config)
    }

    fn engine_with_empty_line_handling(
        empty_line_handling: EmptyLineHandling,
    ) -> NdjsonEngine<TestStruct> {
        configured_engine(|config| config.with_empty_line_handling(empty_line_handling))
    }

    #[test]
    fn raises_error_when_parsing_empty_line_in_parse_always_mode() {
        let mut engine = engine_with_empty_line_handling(EmptyLineHandling::ParseAlways);

        engine.input("{\"key\":1,\"value\":2}\n\n{\"key\":3,\"value\":4}\n");

        assert!(collect_output(engine).iter().any(Result::is_err));
    }

    #[test]
    fn does_not_raise_error_when_parsing_empty_line_in_ignore_empty_mode() {
        let mut engine = engine_with_empty_line_handling(EmptyLineHandling::IgnoreEmpty);

        engine.input("{\"key\":1,\"value\":2}\n\n{\"key\":3,\"value\":4}\n");

        assert!(collect_output(engine).iter().all(Result::is_ok));
    }

    #[test]
    fn does_not_raise_error_when_parsing_empty_line_with_carriage_return_in_ignore_empty_mode() {
        let mut engine = engine_with_empty_line_handling(EmptyLineHandling::IgnoreEmpty);

        engine.input("{\"key\":1,\"value\":2}\r\n\r\n{\"key\":3,\"value\":4}\n");

        assert!(collect_output(engine).iter().all(Result::is_ok));
    }

    #[test]
    fn raises_error_when_parsing_non_empty_blank_line_in_ignore_empty_mode() {
        let mut engine = engine_with_empty_line_handling(EmptyLineHandling::IgnoreEmpty);

        engine.input("{\"key\":1,\"value\":2}\n \t\r\n{\"key\":3,\"value\":4}\n");

        assert!(collect_output(engine).iter().any(Result::is_err));
    }

    #[test]
    fn does_not_raise_error_when_parsing_non_empty_blank_line_in_ignore_blank_mode() {
        let mut engine = engine_with_empty_line_handling(EmptyLineHandling::IgnoreBlank);

        engine.input("{\"key\":1,\"value\":2}\n \t\r\n{\"key\":3,\"value\":4}\n");

        assert!(collect_output(engine).iter().all(Result::is_ok));
    }

    #[test]
    fn finalize_ignores_rest_if_parse_rest_is_false() {
        let mut engine = configured_engine(|config| config.with_parse_rest(false));

        engine.input("{\"key\":1,\"value\":2}");
        engine.finalize();

        assert!(collect_output(engine).is_empty());
    }

    #[test]
    fn finalize_parses_valid_rest() {
        const EMPTY_LINE_HANDLINGS: [EmptyLineHandling; 3] = [
            EmptyLineHandling::ParseAlways,
            EmptyLineHandling::IgnoreEmpty,
            EmptyLineHandling::IgnoreBlank,
        ];

        for empty_line_handling in EMPTY_LINE_HANDLINGS {
            let mut engine = configured_engine(|config| {
                config
                    .with_empty_line_handling(empty_line_handling)
                    .with_parse_rest(true)
            });

            engine.input("{\"key\":1,\"value\":2}");
            engine.finalize();

            let mut result = collect_output(engine).into_iter();
            assert_eq!(
                result.next().unwrap().unwrap(),
                TestStruct { key: 1, value: 2 }
            );
            assert!(result.next().is_none());
        }
    }

    #[test]
    fn finalize_raises_error_on_invalid_rest() {
        let mut engine = configured_engine(|config| config.with_parse_rest(true));

        engine.input("invalid json");
        engine.finalize();

        let mut result = collect_output(engine).into_iter();
        result.next().unwrap().unwrap_err();
        assert!(result.next().is_none());
    }

    #[test]
    fn finalize_ignores_empty_rest_even_if_empty_line_handling_is_parse_always() {
        let mut engine = configured_engine(|config| {
            config
                .with_empty_line_handling(EmptyLineHandling::ParseAlways)
                .with_parse_rest(true)
        });

        engine.finalize();

        assert!(collect_output(engine).is_empty());
    }

    #[test]
    fn finalize_ignores_empty_rest_if_empty_line_handling_is_ignore_empty() {
        let mut engine = configured_engine(|config| {
            config
                .with_empty_line_handling(EmptyLineHandling::IgnoreEmpty)
                .with_parse_rest(true)
        });

        engine.finalize();

        assert!(collect_output(engine).is_empty());
    }

    #[test]
    fn finalize_does_not_ignore_non_empty_blank_rest_if_empty_line_handling_is_ignore_empty() {
        let mut engine = configured_engine(|config| {
            config
                .with_empty_line_handling(EmptyLineHandling::IgnoreEmpty)
                .with_parse_rest(true)
        });

        engine.input(" ");
        engine.finalize();

        let mut result = collect_output(engine).into_iter();
        result.next().unwrap().unwrap_err();
        assert!(result.next().is_none());
    }

    #[test]
    fn finalize_ignores_non_empty_blank_rest_if_empty_line_handling_is_ignore_blank() {
        let mut engine = configured_engine(|config| {
            config
                .with_empty_line_handling(EmptyLineHandling::IgnoreBlank)
                .with_parse_rest(true)
        });

        engine.input(" ");
        engine.finalize();

        assert!(collect_output(engine).is_empty());
    }

    #[test]
    fn max_line_bytes_emits_error_and_recovers_on_next_line() {
        let max = core::num::NonZeroUsize::new(8).unwrap();
        let mut engine = configured_engine(|config| config.with_max_line_bytes(max));

        // First line clearly exceeds 8 bytes — should error and resync.
        engine.input("{\"key\":1,\"value\":2}\n{\"key\":3,\"value\":4}\n");

        let mut result = collect_output(engine).into_iter();
        result.next().unwrap().unwrap_err();
        // Second line also exceeds; another error follows.
        result.next().unwrap().unwrap_err();
        assert!(result.next().is_none());
    }

    #[test]
    fn max_line_bytes_allows_lines_under_limit() {
        let max = core::num::NonZeroUsize::new(64).unwrap();
        let mut engine = configured_engine(|config| config.with_max_line_bytes(max));

        engine.input("{\"key\":1,\"value\":2}\n");

        let mut result = collect_output(engine).into_iter();
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct { key: 1, value: 2 }
        );
        assert!(result.next().is_none());
    }

    #[test]
    fn max_line_bytes_resyncs_across_chunked_input() {
        let max = core::num::NonZeroUsize::new(4).unwrap();
        let mut engine = configured_engine(|config| config.with_max_line_bytes(max));

        // Chunked oversized line followed by a small valid line.
        engine.input("{\"key\"");
        engine.input(":1,\"val");
        engine.input("ue\":2}\n");
        // Now under the limit on its own; but parsing requires the value to be valid JSON.
        // With max=4 it'll also exceed; use a value that fits exactly: "1\n".
        engine.input("1\n");

        let mut result = collect_output(engine).into_iter();
        // First emit is the oversized error.
        result.next().unwrap().unwrap_err();
        // Second emit decodes the small line — fails type coercion to TestStruct.
        result.next().unwrap().unwrap_err();
        assert!(result.next().is_none());
    }

    #[test]
    fn default_empty_line_handling_is_ignore_empty() {
        // rama-default: empty lines should be gracefully ignored, not raise an error.
        let mut engine: NdjsonEngine<TestStruct> = NdjsonEngine::new();

        engine.input("{\"key\":1,\"value\":2}\n\n{\"key\":3,\"value\":4}\n");

        let results = collect_output(engine);
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(2, results.len());
    }

    #[test]
    fn finalize_is_idempotent() {
        let mut engine = configured_engine(|config| config.with_parse_rest(true));

        engine.input("{\"key\":13,\"value\":37}");
        engine.finalize();
        engine.finalize();

        let mut result = collect_output(engine).into_iter();
        assert_eq!(
            result.next().unwrap().unwrap(),
            TestStruct { key: 13, value: 37 }
        );
        assert!(result.next().is_none());
    }
}
