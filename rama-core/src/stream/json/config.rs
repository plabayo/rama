use crate::extensions::Extension;
use core::num::NonZeroUsize;
use rama_utils::{macros::generate_set_and_with, octets::kib};

/// Default for [`ParseConfig::with_max_line_bytes`]: far above any line a real peer sends.
pub const DEFAULT_MAX_LINE_BYTES: NonZeroUsize =
    NonZeroUsize::new(rama_utils::octets::mib(16)).expect("16 MiB is not zero");

/// Controls how the parser deals with lines that contain no JSON values.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum EmptyLineHandling {
    /// Parse every line, i.e. every segment between `\n` characters, even if it is empty. This will
    /// result in errors for empty lines.
    ParseAlways,

    /// Ignore lines, i.e. segments between `\n` characters, which are empty, i.e. contain no
    /// characters. For compatibility with `\r\n`-style linebreaks, this also ignores lines which
    /// consist of only a single `\r` character.
    ///
    /// This is the default — rama is proxy-first and graceful: a stray `\n\n` from a remote peer
    /// should not surface as a hard parse error. Opt in to [`EmptyLineHandling::ParseAlways`] when
    /// you want strict handling.
    #[default]
    IgnoreEmpty,

    /// Ignore lines, i.e. segments between `\n` characters, which contain only whitespace
    /// characters.
    IgnoreBlank,
}

/// Configuration for the NDJSON-parser which controls the behavior in various situations.
///
/// By default, the parser will skip empty lines ([`EmptyLineHandling::IgnoreEmpty`]) and accept
/// lines up to [`DEFAULT_MAX_LINE_BYTES`]. Tighten that with
/// [`ParseConfig::with_max_line_bytes`] for untrusted input, or lift it with
/// [`ParseConfig::without_max_line_bytes`]. Oversized lines are reported as a parse error and
/// the engine resyncs to the next newline so subsequent lines can still be decoded.
///
/// You can construct a config by first calling [`ParseConfig::default`] and then using the
/// builder-style associated functions to configure it. See the example below.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ParseConfig {
    pub(crate) empty_line_handling: EmptyLineHandling,
    pub(crate) parse_rest: bool,
    pub(crate) max_line_bytes: Option<NonZeroUsize>,
}

impl Default for ParseConfig {
    fn default() -> Self {
        Self {
            empty_line_handling: Default::default(),
            parse_rest: true,
            max_line_bytes: Some(DEFAULT_MAX_LINE_BYTES),
        }
    }
}

impl ParseConfig {
    generate_set_and_with! {
        /// Creates a new config from this config which has a different handling for lines that contain
        /// no JSON values. See [EmptyLineHandling] for more details.
        ///
        /// # Returns
        ///
        /// A new config with all the same values as this one, except the empty-line-handling.
        pub fn empty_line_handling(mut self, empty_line_handling: EmptyLineHandling) -> Self {
            self.empty_line_handling = empty_line_handling;
            self
        }
    }

    generate_set_and_with! {
        /// Creates a new config from this config which has the given configuration on whether to parse
        /// or ignore the rest, i.e. the part after the last newline character. If `parse_rest` is set
        /// to `false`, the rest will always be ignored, while `true` causes it to only be ignored if it
        /// is empty or considered empty by the handling configured in
        /// [ParseConfig::with_empty_line_handling], which by default is only truly empty. Otherwise,
        /// the rest is parsed like an ordinary JSON record. By default, this is set to `true`.
        ///
        /// # Returns
        ///
        /// A new config with all the same values as this one, except the parse-rest-flag.
        pub fn parse_rest(mut self, parse_rest: bool) -> Self {
            self.parse_rest = parse_rest;
            self
        }
    }

    generate_set_and_with! {
        /// Caps the size of a single NDJSON line. When the accumulated bytes for a single line
        /// (i.e. between two `\n` characters) exceed this limit, the engine emits a parse error
        /// and resynchronises to the next newline; subsequent lines can still be decoded.
        ///
        /// Defaults to [`DEFAULT_MAX_LINE_BYTES`]. `None` means no limit, appropriate only for
        /// trusted input sources.
        ///
        /// # Returns
        ///
        /// A new config with all the same values as this one, except the max-line-bytes.
        pub fn max_line_bytes(mut self, max_line_bytes: Option<NonZeroUsize>) -> Self {
            self.max_line_bytes = max_line_bytes;
            self
        }
    }
}

/// Default maximum encoded size of one element in a streamed JSON array.
pub const DEFAULT_MAX_ELEMENT_BYTES: NonZeroUsize =
    NonZeroUsize::new(kib(32)).expect("32 KiB is positive");

/// Bounds how many encoded bytes can be buffered for a single JSON array element.
#[derive(Debug, Clone, Copy, Extension)]
#[extension(tags(http))]
pub struct ArrayParseConfig {
    pub(crate) max_element_bytes: NonZeroUsize,
}

impl Default for ArrayParseConfig {
    fn default() -> Self {
        Self {
            max_element_bytes: DEFAULT_MAX_ELEMENT_BYTES,
        }
    }
}

impl ArrayParseConfig {
    generate_set_and_with! {
        /// Set the per-element byte limit, excluding whitespace surrounding the element.
        pub fn max_element_bytes(mut self, max_element_bytes: NonZeroUsize) -> Self {
            self.max_element_bytes = max_element_bytes;
            self
        }
    }
}
