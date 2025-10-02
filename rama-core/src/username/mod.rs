//! Utilities to work with usernames and pull information out of it.
//!
//! # Username Parsing
//!
//! The [`parse_username`] function is used to parse a username and extract information from
//! its labels. The function takes a parser, which is used to parse the labels from the username.
//!
//! The parser is expected to implement the [`UsernameLabelParser`] trait, which has two methods:
//!
//! - `parse_label`: This method is called for each label in the username, and is expected to return
//!   whether the label was used or ignored.
//! - `build`: This method is called after all labels have been parsed, and is expected to consume
//!   the parser and store any relevant information.
//!
//! The parser can be a single parser or a tuple of parsers. Tuple parsers all receive all labels,
//! unless wrapped by a [`ExclusiveUsernameParsers`], in which case the first parser that consumes
//! a label will stop the iteration over the parsers.
//!
//! Parsers are to return [`UsernameLabelState::Used`] in case they consumed the label, and
//! [`UsernameLabelState::Ignored`] in case they did not. This way the parser-caller (e.g. [`parse_username`])
//! can decide whether to fail on ignored labels.
//!
//! # Username Composing
//!
//! Composing a username is the opposite of "Username Parsing",
//! and is used to suffix labels to a username.

/// The default username label separator used by most built-in rama support.
pub const DEFAULT_USERNAME_LABEL_SEPARATOR: char = '-';

mod parse;
#[doc(inline)]
pub use parse::{
    ExclusiveUsernameParsers, UsernameLabelParser, UsernameLabelState, UsernameLabels,
    UsernameOpaqueLabelParser, parse_username, parse_username_with_separator,
};

mod compose;
#[doc(inline)]
pub use compose::{
    ComposeError, Composer, UsernameLabelWriter, compose_username, compose_username_with_separator,
};

#[cfg(test)]
mod tests {
    use crate::extensions::Extensions;

    use super::*;

    #[test]
    fn parse_compose_username_labels() {
        const COMPOSED_USERNAME: &str = "john-foo-bar-baz";

        let mut ext = Extensions::new();
        let username = parse_username(
            &mut ext,
            UsernameOpaqueLabelParser::new(),
            COMPOSED_USERNAME,
        )
        .unwrap();
        assert_eq!("john", username);
        let labels = ext.get::<UsernameLabels>().unwrap();

        let compose_username_result = compose_username("john".to_owned(), labels).unwrap();
        assert_eq!(COMPOSED_USERNAME, compose_username_result);
    }
}
