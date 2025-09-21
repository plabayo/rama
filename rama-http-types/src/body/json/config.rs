use rama_utils::macros::generate_set_and_with;

/// Controls how the parser deals with lines that contain no JSON values.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum EmptyLineHandling {
    /// Parse every line, i.e. every segment between `\n` characters, even if it is empty. This will
    /// result in errors for empty lines.
    #[default]
    ParseAlways,

    /// Ignore lines, i.e. segments between `\n` characters, which are empty, i.e. contain no
    /// characters. For compatibility with `\r\n`-style linebreaks, this also ignores lines which
    /// consist of only a single `\r` character.
    IgnoreEmpty,

    /// Ignore lines, i.e. segments between `\n` characters, which contain only whitespace
    /// characters.
    IgnoreBlank,
}

/// Configuration for the NDJSON-parser which controls the behavior in various situations.
///
/// By default, the parser will attempt to parse every line, i.e. every segment between `\n`
/// characters, even if it is empty. This will result in errors for empty lines.
///
/// You can construct a config by first calling [ParseConfig::default] and then using the
/// builder-style associated functions to configure it. See the example below.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ParseConfig {
    pub(crate) empty_line_handling: EmptyLineHandling,
    pub(crate) parse_rest: bool,
}

impl Default for ParseConfig {
    fn default() -> Self {
        Self {
            empty_line_handling: Default::default(),
            parse_rest: true,
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
}
