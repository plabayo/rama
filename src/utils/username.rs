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
//! ## Example
//!
//! [`ProxyFilterUsernameParser`] is a real-world example of a parser that uses the username labels.
//! It support proxy filter definitions directly within the username.
//!
//! [`ProxyFilterUsernameParser`]: crate::proxy::ProxyFilterUsernameParser
//!
//! ```rust
//! use rama::proxy::{ProxyFilter, ProxyFilterUsernameParser};
//! use rama::utils::username::{DEFAULT_USERNAME_LABEL_SEPARATOR, parse_username};
//! use rama::service::context::Extensions;
//!
//! let mut ext = Extensions::default();
//!
//! let parser = ProxyFilterUsernameParser::default();
//!
//! let username = parse_username(
//!     &mut ext, parser,
//!     "john-residential-country-us",
//!     DEFAULT_USERNAME_LABEL_SEPARATOR,
//! ).unwrap();
//!
//! assert_eq!(username, "john");
//!
//! let filter = ext.get::<ProxyFilter>().unwrap();
//! assert_eq!(filter.residential, Some(true));
//! assert_eq!(filter.country, Some(vec!["us".into()]));
//! assert!(filter.datacenter.is_none());
//! assert!(filter.mobile.is_none());
//! ```

use crate::error::{BoxError, OpaqueError};
use crate::service::context::Extensions;
use std::{convert::Infallible, fmt};

/// The default username label separator used by most built-in rama support.
pub const DEFAULT_USERNAME_LABEL_SEPARATOR: char = '-';

/// Parse a username, extracting the username (first part)
/// and passing everything else to the [`UsernameLabelParser`].
pub fn parse_username<P>(
    ext: &mut Extensions,
    mut parser: P,
    username_ref: impl AsRef<str>,
    separator: char,
) -> Result<String, OpaqueError>
where
    P: UsernameLabelParser,
    P::Error: Into<BoxError>,
{
    let username_ref = username_ref.as_ref();
    let mut label_it = username_ref.split(separator);

    let username = match label_it.next() {
        Some(username) => {
            if username.is_empty() {
                return Err(OpaqueError::from_display("empty username"));
            } else {
                username
            }
        }
        None => return Err(OpaqueError::from_display("missing username")),
    };

    for label in label_it {
        if parser.parse_label(label) == UsernameLabelState::Ignored {
            return Err(OpaqueError::from_display(format!(
                "ignored username label: {}",
                label
            )));
        }
    }

    parser
        .build(ext)
        .map_err(|err| OpaqueError::from_boxed(err.into()))?;

    Ok(username.to_owned())
}

/// The parse state of a username label.
///
/// This can be used to signal that a label was recognised in the case
/// that you wish to fail on labels that weren't recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsernameLabelState {
    /// The label was used by this parser.
    ///
    /// Note in case multiple parsers are used it should in generally be ok,
    /// for multiple to "use" the same label.
    Used,

    /// The label was ignored by this parser,
    /// reasons for which are not important here.
    ///
    /// A parser-user can choose to error a request in case
    /// a label was ignored by its parser.
    Ignored,
}

/// A parser which can parse labels from a username.
///
/// [`Default`] is to be implemented for every [`UsernameLabelParser`],
/// as it is what is used to create the parser instances for one-time usage.
pub trait UsernameLabelParser: Default + Send + Sync + 'static {
    /// Error which can occur during the building phase.
    type Error: Into<BoxError>;

    /// Interpret the label and return whether or not the label was recognised and valid.
    ///
    /// [`UsernameLabelState::Ignored`] should be returned in case the label was not recognised or was not valid.
    fn parse_label(&mut self, label: &str) -> UsernameLabelState;

    /// Consume self and store/use any of the relevant info seen.
    fn build(self, ext: &mut Extensions) -> Result<(), Self::Error>;
}

/// Wrapper type that can be used with a tuple of [`UsernameLabelParser`]s
/// in order for it to stop iterating over the parsers once there was one that consumed the label.
pub struct ExclusiveUsernameParsers<P>(pub P);

impl<P: Clone> Clone for ExclusiveUsernameParsers<P> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<P: Default> Default for ExclusiveUsernameParsers<P> {
    fn default() -> Self {
        Self(P::default())
    }
}

impl<P: fmt::Debug> fmt::Debug for ExclusiveUsernameParsers<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ExclusiveUsernameParsers")
            .field(&self.0)
            .finish()
    }
}

macro_rules! username_label_parser_tuple_impl {
    ($($T:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<$($T,)+> UsernameLabelParser for ($($T,)+)
        where
            $(
                $T: UsernameLabelParser,
                $T::Error: Into<BoxError>,
            )+
        {
            type Error = OpaqueError;

            fn parse_label(&mut self, label: &str) -> UsernameLabelState {
                let ($(ref mut $T,)+) = self;
                let mut state = UsernameLabelState::Ignored;
                $(
                    if $T.parse_label(label) == UsernameLabelState::Used {
                        state = UsernameLabelState::Used;
                    }
                )+
                state
            }

            fn build(self, ext: &mut Extensions) -> Result<(), Self::Error> {
                let ($($T,)+) = self;
                $(
                    $T.build(ext).map_err(|err| OpaqueError::from_boxed(err.into()))?;
                )+
                Ok(())
            }
        }
    };
}

all_the_tuples_no_last_special_case!(username_label_parser_tuple_impl);

macro_rules! username_label_parser_tuple_exclusive_labels_impl {
    ($($T:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<$($T,)+> UsernameLabelParser for ExclusiveUsernameParsers<($($T,)+)>
        where
            $(
                $T: UsernameLabelParser,
                $T::Error: Into<BoxError>,
            )+
        {
            type Error = OpaqueError;

            fn parse_label(&mut self, label: &str) -> UsernameLabelState {
                let ($(ref mut $T,)+) = self.0;
                $(
                    if $T.parse_label(label) == UsernameLabelState::Used {
                        return UsernameLabelState::Used;
                    }
                )+
                UsernameLabelState::Ignored
            }

            fn build(self, ext: &mut Extensions) -> Result<(), Self::Error> {
                let ($($T,)+) = self.0;
                $(
                    $T.build(ext).map_err(|err| OpaqueError::from_boxed(err.into()))?;
                )+
                Ok(())
            }
        }
    };
}

all_the_tuples_no_last_special_case!(username_label_parser_tuple_exclusive_labels_impl);

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// A [`UsernameLabelParser`] which does nothing and returns [`UsernameLabelState::Used`] for all labels.
///
/// This is useful in case you want to allow labels to be ignored,
/// for locations where the parser-user fails on ignored labels.
pub struct UsernameLabelParserVoid;

impl UsernameLabelParserVoid {
    /// Create a new [`UsernameLabelParserVoid`].
    pub fn new() -> Self {
        Self
    }
}

impl UsernameLabelParser for UsernameLabelParserVoid {
    type Error = Infallible;

    fn parse_label(&mut self, _label: &str) -> UsernameLabelState {
        UsernameLabelState::Used
    }

    fn build(self, _ext: &mut Extensions) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
/// Opaque string labels parsed collected using the [`UsernameOpaqueLabelParser`].
///
/// Useful in case you want to collect all labels from the username,
/// without any specific parsing logic.
pub struct UsernameLabels(pub Vec<String>);

#[derive(Debug, Clone, Default)]
/// A [`UsernameLabelParser`] which collects all labels from the username,
/// without any specific parsing logic.
pub struct UsernameOpaqueLabelParser {
    labels: Vec<String>,
}

impl UsernameOpaqueLabelParser {
    /// Create a new [`UsernameOpaqueLabelParser`].
    pub fn new() -> Self {
        Self::default()
    }
}

impl UsernameLabelParser for UsernameOpaqueLabelParser {
    type Error = Infallible;

    fn parse_label(&mut self, label: &str) -> UsernameLabelState {
        self.labels.push(label.to_owned());
        UsernameLabelState::Used
    }

    fn build(self, ext: &mut Extensions) -> Result<(), Self::Error> {
        if !self.labels.is_empty() {
            ext.insert(UsernameLabels(self.labels));
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Debug, Clone, Default)]
    #[non_exhaustive]
    struct UsernameNoLabelParser;

    impl UsernameLabelParser for UsernameNoLabelParser {
        type Error = Infallible;

        fn parse_label(&mut self, _label: &str) -> UsernameLabelState {
            UsernameLabelState::Ignored
        }

        fn build(self, _ext: &mut Extensions) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Debug, Clone, Default)]
    #[non_exhaustive]
    struct UsernameNoLabelPanicParser;

    impl UsernameLabelParser for UsernameNoLabelPanicParser {
        type Error = Infallible;

        fn parse_label(&mut self, _label: &str) -> UsernameLabelState {
            unreachable!("this parser should not be called");
        }

        fn build(self, _ext: &mut Extensions) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Debug, Clone, Default)]
    #[non_exhaustive]
    struct MyLabelParser {
        labels: Vec<String>,
    }

    #[derive(Debug, Clone, Default)]
    struct MyLabels(Vec<String>);

    impl UsernameLabelParser for MyLabelParser {
        type Error = Infallible;

        fn parse_label(&mut self, label: &str) -> UsernameLabelState {
            self.labels.push(label.to_owned());
            UsernameLabelState::Used
        }

        fn build(self, ext: &mut Extensions) -> Result<(), Self::Error> {
            if !self.labels.is_empty() {
                ext.insert(MyLabels(self.labels));
            }
            Ok(())
        }
    }

    #[test]
    fn test_parse_username_empty() {
        let mut ext = Extensions::default();

        assert!(parse_username(
            &mut ext,
            UsernameLabelParserVoid::new(),
            "",
            DEFAULT_USERNAME_LABEL_SEPARATOR
        )
        .is_err());
        assert!(parse_username(
            &mut ext,
            UsernameLabelParserVoid::new(),
            "-",
            DEFAULT_USERNAME_LABEL_SEPARATOR
        )
        .is_err());
    }

    #[test]
    fn test_parse_username_no_labels() {
        let mut ext = Extensions::default();

        assert_eq!(
            parse_username(
                &mut ext,
                UsernameNoLabelParser,
                "username",
                DEFAULT_USERNAME_LABEL_SEPARATOR
            )
            .unwrap(),
            "username"
        );
    }

    #[test]
    fn test_parse_username_label_collector() {
        let mut ext = Extensions::default();
        assert_eq!(
            parse_username(
                &mut ext,
                UsernameOpaqueLabelParser::new(),
                "username-label1-label2",
                DEFAULT_USERNAME_LABEL_SEPARATOR
            )
            .unwrap(),
            "username"
        );

        let labels = ext.get::<UsernameLabels>().unwrap();
        assert_eq!(labels.0, vec!["label1".to_owned(), "label2".to_owned()]);
    }

    #[test]
    fn test_username_labels_multi_parser() {
        let mut ext = Extensions::default();

        let parser = (
            UsernameOpaqueLabelParser::new(),
            UsernameNoLabelParser::default(),
        );

        assert_eq!(
            parse_username(
                &mut ext,
                parser,
                "username-label1-label2",
                DEFAULT_USERNAME_LABEL_SEPARATOR
            )
            .unwrap(),
            "username"
        );

        let labels = ext.get::<UsernameLabels>().unwrap();
        assert_eq!(labels.0, vec!["label1".to_owned(), "label2".to_owned()]);
    }

    #[test]
    fn test_username_labels_multi_consumer_parser() {
        let mut ext = Extensions::default();

        let parser = (
            UsernameNoLabelParser::default(),
            MyLabelParser::default(),
            UsernameOpaqueLabelParser::new(),
        );

        assert_eq!(
            parse_username(
                &mut ext,
                parser,
                "username-label1-label2",
                DEFAULT_USERNAME_LABEL_SEPARATOR
            )
            .unwrap(),
            "username"
        );

        let labels = ext.get::<UsernameLabels>().unwrap();
        assert_eq!(labels.0, vec!["label1".to_owned(), "label2".to_owned()]);

        let labels = ext.get::<MyLabels>().unwrap();
        assert_eq!(labels.0, vec!["label1".to_owned(), "label2".to_owned()]);
    }

    #[test]
    fn test_username_labels_multi_consumer_exclusive_parsers() {
        let mut ext = Extensions::default();

        let parser = ExclusiveUsernameParsers((
            UsernameOpaqueLabelParser::default(),
            MyLabelParser::default(),
            UsernameNoLabelPanicParser::default(),
        ));

        assert_eq!(
            parse_username(
                &mut ext,
                parser,
                "username-label1-label2",
                DEFAULT_USERNAME_LABEL_SEPARATOR
            )
            .unwrap(),
            "username"
        );

        let labels = ext.get::<UsernameLabels>().unwrap();
        assert_eq!(labels.0, vec!["label1".to_owned(), "label2".to_owned()]);

        assert!(ext.get::<MyLabels>().is_none());
    }

    #[test]
    fn test_username_opaque_labels_none() {
        let mut ext = Extensions::default();

        let parser = UsernameOpaqueLabelParser::new();

        assert_eq!(
            parse_username(
                &mut ext,
                parser,
                "username",
                DEFAULT_USERNAME_LABEL_SEPARATOR
            )
            .unwrap(),
            "username"
        );

        assert!(ext.get::<UsernameLabels>().is_none());
    }
}
