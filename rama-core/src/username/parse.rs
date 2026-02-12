use super::DEFAULT_USERNAME_LABEL_SEPARATOR;
use crate::error::BoxError;
use crate::extensions::Extensions;
use rama_error::{ErrorContext as _, ErrorExt};
use rama_utils::macros::all_the_tuples_no_last_special_case;
use std::convert::Infallible;

/// Parse a username, extracting the username (first part)
/// and passing everything else to the [`UsernameLabelParser`].
#[inline]
pub fn parse_username<P>(
    ext: &mut Extensions,
    parser: P,
    username_ref: impl AsRef<str>,
) -> Result<String, BoxError>
where
    P: UsernameLabelParser<Error: Into<BoxError>>,
{
    parse_username_with_separator(ext, parser, username_ref, DEFAULT_USERNAME_LABEL_SEPARATOR)
}

/// Parse a username, extracting the username (first part)
/// and passing everything else to the [`UsernameLabelParser`].
pub fn parse_username_with_separator<P>(
    ext: &mut Extensions,
    mut parser: P,
    username_ref: impl AsRef<str>,
    separator: char,
) -> Result<String, BoxError>
where
    P: UsernameLabelParser<Error: Into<BoxError>>,
{
    let username_ref = username_ref.as_ref();
    let mut label_it = username_ref.split(separator);

    let username = match label_it.next() {
        Some(username) => {
            if username.is_empty() {
                return Err(BoxError::from("empty username"));
            } else {
                username
            }
        }
        None => return Err(BoxError::from("missing username")),
    };

    for (index, label) in label_it.enumerate() {
        match parser.parse_label(label) {
            UsernameLabelState::Used => (), // optimistic smiley
            UsernameLabelState::Ignored => {
                return Err(BoxError::from("ignored username label")
                    .context_field("index", index)
                    .context_str_field("label", label));
            }
            UsernameLabelState::Abort => {
                return Err(BoxError::from("invalid username label")
                    .context_field("index", index)
                    .context_str_field("label", label));
            }
        }
    }

    parser.build(ext).into_box_error()?;

    Ok(username.to_owned())
}

/// The parse state of a username label.
///
/// This can be used to signal that a label was recognised in the case
/// that you wish to fail on labels that weren't recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

    /// Abort the parsing as a state has been reached
    /// from which cannot be recovered.
    Abort,
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
#[derive(Debug, Clone, Default)]
pub struct ExclusiveUsernameParsers<P>(pub P);

macro_rules! username_label_parser_tuple_impl {
    ($($T:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<$($T,)+> UsernameLabelParser for ($($T,)+)
        where
            $(
                $T: UsernameLabelParser<Error: Into<BoxError>>,
            )+
        {
            type Error = BoxError;

            fn parse_label(&mut self, label: &str) -> UsernameLabelState {
                let ($($T,)+) = self;
                let mut state = UsernameLabelState::Ignored;
                $(
                    match $T.parse_label(label) {
                        UsernameLabelState::Ignored => (),
                        UsernameLabelState::Used => state = UsernameLabelState::Used,
                        UsernameLabelState::Abort => return UsernameLabelState::Abort,
                    }
                )+
                state
            }

            fn build(self, ext: &mut Extensions) -> Result<(), Self::Error> {
                let ($($T,)+) = self;
                $(
                    $T.build(ext).into_box_error()?;
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
                $T: UsernameLabelParser<Error: Into<BoxError>>,
            )+
        {
            type Error = BoxError;

            fn parse_label(&mut self, label: &str) -> UsernameLabelState {
                let ($(ref mut $T,)+) = self.0;
                $(
                    match $T.parse_label(label) {
                        UsernameLabelState::Ignored => (),
                        UsernameLabelState::Used => return UsernameLabelState::Used,
                        UsernameLabelState::Abort => return UsernameLabelState::Abort,
                    }
                )+
                UsernameLabelState::Ignored
            }

            fn build(self, ext: &mut Extensions) -> Result<(), Self::Error> {
                let ($($T,)+) = self.0;
                $(
                    $T.build(ext).into_box_error()?;
                )+
                Ok(())
            }
        }
    };
}

all_the_tuples_no_last_special_case!(username_label_parser_tuple_exclusive_labels_impl);

impl UsernameLabelParser for () {
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

impl<const SEPARATOR: char> super::UsernameLabelWriter<SEPARATOR> for UsernameLabels {
    fn write_labels(
        &self,
        composer: &mut super::Composer<SEPARATOR>,
    ) -> Result<(), super::ComposeError> {
        self.0.write_labels(composer)
    }
}

#[derive(Debug, Clone, Default)]
/// A [`UsernameLabelParser`] which collects all labels from the username,
/// without any specific parsing logic.
pub struct UsernameOpaqueLabelParser {
    labels: Vec<String>,
}

impl UsernameOpaqueLabelParser {
    /// Create a new [`UsernameOpaqueLabelParser`].
    #[must_use]
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
    struct UsernameLabelAbortParser;

    impl UsernameLabelParser for UsernameLabelAbortParser {
        type Error = Infallible;

        fn parse_label(&mut self, _label: &str) -> UsernameLabelState {
            UsernameLabelState::Abort
        }

        fn build(self, _ext: &mut Extensions) -> Result<(), Self::Error> {
            unreachable!("should not happen")
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

        assert!(parse_username(&mut ext, (), "",).is_err());
        assert!(parse_username(&mut ext, (), "-",).is_err());
    }

    #[test]
    fn test_parse_username_no_labels() {
        let mut ext = Extensions::default();

        assert_eq!(
            parse_username(&mut ext, UsernameNoLabelParser, "username",).unwrap(),
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
            parse_username(&mut ext, parser, "username-label1-label2",).unwrap(),
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
            parse_username(&mut ext, parser, "username-label1-label2",).unwrap(),
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
            parse_username(&mut ext, parser, "username-label1-label2",).unwrap(),
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
            parse_username(&mut ext, parser, "username",).unwrap(),
            "username"
        );

        assert!(ext.get::<UsernameLabels>().is_none());
    }

    #[test]
    fn test_username_label_parser_abort_tuple() {
        let mut ext = Extensions::default();

        let parser = (
            UsernameLabelAbortParser::default(),
            UsernameOpaqueLabelParser::default(),
        );
        assert!(parse_username(&mut ext, parser, "username-foo",).is_err());

        let parser = (
            UsernameOpaqueLabelParser::default(),
            UsernameLabelAbortParser::default(),
        );
        assert!(parse_username(&mut ext, parser, "username-foo",).is_err());
    }

    #[test]
    fn test_username_label_parser_abort_exclusive_tuple() {
        let mut ext = Extensions::default();

        let parser = ExclusiveUsernameParsers((
            UsernameLabelAbortParser::default(),
            UsernameOpaqueLabelParser::default(),
        ));
        assert!(parse_username(&mut ext, parser, "username-foo",).is_err());

        let parser = (
            UsernameOpaqueLabelParser::default(),
            UsernameLabelAbortParser::default(),
        );
        assert!(parse_username(&mut ext, parser, "username-foo",).is_err());
    }
}
