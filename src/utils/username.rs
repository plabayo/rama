//! Utilities to work with usernames and pull information out of it.

use crate::error::OpaqueError;
use crate::service::Context;
use std::convert::Infallible;

/// Parse a username, extracting the username (first part)
/// and passing everything else to the [`UsernameLabelParser`].
pub fn parse_username<P, State, Request>(
    ctx: &mut Context<State>,
    request: &mut Request,
    mut parser: P,
    username_ref: impl AsRef<str>,
    seperator: char,
) -> Result<String, OpaqueError>
where
    P: UsernameLabelParser<State, Request>,
    P::Error: std::error::Error + Send + Sync + 'static,
{
    let username_ref = username_ref.as_ref();
    let mut label_it = username_ref.split(seperator);

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
        if parser.parse_label(ctx, request, label) == UsernameLabelState::Ignored {
            return Err(OpaqueError::from_display(format!(
                "ignored username label: {}",
                label
            )));
        }
    }

    parser.build(ctx, request).map_err(OpaqueError::from_std)?;

    Ok(username.to_owned())
}

/// A layer which is used to create a [`UsernameLabelParser`], to parse labels from the username.
pub trait UsernameLabelParserLayer<State, Request>: Send + Sync + 'static {
    /// The [`UsernameLabelParser`] which is created by this layer.
    type Parser;

    /// Crates the parser to be used for parsing the username,
    /// this is expected to be a cheap and non-fallible operation.
    fn create_parser(&self, ctx: &Context<State>, req: &Request) -> Self::Parser;
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
pub trait UsernameLabelParser<State, Request>: Send + Sync + 'static {
    /// Error which can occur during the building phase.
    type Error;

    /// Interpret the label and return whether or not the label was recognised and valid.
    ///
    /// [`UsernameLabelState::Ignored`] should be returned in case the label was not recognised or was not valid.
    fn parse_label(
        &mut self,
        ctx: &Context<State>,
        req: &Request,
        label: &str,
    ) -> UsernameLabelState;

    /// Consume self and store/use any of the relevant info seen.
    fn build(self, ctx: &mut Context<State>, req: &mut Request) -> Result<(), Self::Error>;
}

macro_rules! username_label_parser_layer_tuple_impl {
    ($($T:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<State, Request, $($T,)+> UsernameLabelParserLayer<State, Request> for ($($T,)+)
        where
            $(
                $T: UsernameLabelParserLayer<State, Request>,
            )+
        {
            type Parser = ($($T::Parser,)+);

            fn create_parser(&self, ctx: &Context<State>, req: &Request) -> Self::Parser {
                let ($($T,)+) = self;
                ($($T.create_parser(ctx, req),)+)
            }
        }
    };
}

all_the_tuples_no_last_special_case!(username_label_parser_layer_tuple_impl);

macro_rules! username_label_parser_tuple_impl {
    ($($T:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<State, Request, $($T,)+> UsernameLabelParser<State, Request> for ($($T,)+)
        where
            $(
                $T: UsernameLabelParser<State, Request>,
                $T::Error: std::error::Error + Send + Sync + 'static,
            )+
        {
            type Error = OpaqueError;

            fn parse_label(&mut self, ctx: &Context<State>, req: &Request, label: &str) -> UsernameLabelState {
                let ($(ref mut $T,)+) = self;
                let mut state = UsernameLabelState::Ignored;
                $(
                    if $T.parse_label(ctx, req, label) == UsernameLabelState::Used {
                        state = UsernameLabelState::Used;
                    }
                )+
                state
            }

            fn build(self, ctx: &mut Context<State>, req: &mut Request) -> Result<(), Self::Error> {
                let ($($T,)+) = self;
                $(
                    $T.build(ctx, req).map_err(OpaqueError::from_std)?;
                )+
                Ok(())
            }
        }
    };
}

all_the_tuples_no_last_special_case!(username_label_parser_tuple_impl);

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

impl<State, Request> UsernameLabelParserLayer<State, Request> for UsernameLabelParserVoid {
    type Parser = UsernameLabelParserVoid;

    fn create_parser(&self, _ctx: &Context<State>, _req: &Request) -> Self::Parser {
        self.clone()
    }
}

impl<State, Request> UsernameLabelParser<State, Request> for UsernameLabelParserVoid {
    type Error = Infallible;

    fn parse_label(
        &mut self,
        _ctx: &Context<State>,
        _req: &Request,
        _label: &str,
    ) -> UsernameLabelState {
        UsernameLabelState::Used
    }

    fn build(self, _ctx: &mut Context<State>, _req: &mut Request) -> Result<(), Self::Error> {
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

impl<State, Request> UsernameLabelParserLayer<State, Request> for UsernameOpaqueLabelParser {
    type Parser = Self;

    fn create_parser(&self, _ctx: &Context<State>, _req: &Request) -> Self::Parser {
        Self::default()
    }
}

impl<State, Request> UsernameLabelParser<State, Request> for UsernameOpaqueLabelParser {
    type Error = Infallible;

    fn parse_label(
        &mut self,
        _ctx: &Context<State>,
        _req: &Request,
        label: &str,
    ) -> UsernameLabelState {
        self.labels.push(label.to_owned());
        UsernameLabelState::Used
    }

    fn build(self, ctx: &mut Context<State>, _req: &mut Request) -> Result<(), Self::Error> {
        ctx.insert(UsernameLabels(self.labels));
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::http::{Body, Request};
    use crate::service::context::AsRef;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[derive(Debug, Clone, Default)]
    #[non_exhaustive]
    struct UsernameNoLabelParser;

    impl<State, Request> UsernameLabelParser<State, Request> for UsernameNoLabelParser {
        type Error = Infallible;

        fn parse_label(
            &mut self,
            _ctx: &Context<State>,
            _req: &Request,
            _label: &str,
        ) -> UsernameLabelState {
            UsernameLabelState::Ignored
        }

        fn build(self, _ctx: &mut Context<State>, _req: &mut Request) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Debug, Clone, Default)]
    #[non_exhaustive]
    struct MyLabelParser {
        labels: Vec<String>,
    }

    #[derive(Debug, Clone, Default)]
    struct LabelCounter(Arc<AtomicUsize>);

    #[derive(Debug, Clone, Default)]
    struct MyLabels(Vec<String>);

    impl<State, Body> UsernameLabelParser<State, Request<Body>> for MyLabelParser
    where
        State: AsRef<LabelCounter>,
    {
        type Error = Infallible;

        fn parse_label(
            &mut self,
            ctx: &Context<State>,
            _req: &Request<Body>,
            label: &str,
        ) -> UsernameLabelState {
            ctx.state().as_ref().0.fetch_add(1, Ordering::SeqCst);
            self.labels.push(label.to_owned());
            UsernameLabelState::Used
        }

        fn build(
            self,
            ctx: &mut Context<State>,
            req: &mut Request<Body>,
        ) -> Result<(), Self::Error> {
            req.headers_mut()
                .insert("x-labels", self.labels.join(",").parse().unwrap());
            ctx.insert(MyLabels(self.labels));
            Ok(())
        }
    }

    #[test]
    fn test_parse_username_empty() {
        let mut ctx = Context::default();
        let mut req = ();

        assert!(
            parse_username(&mut ctx, &mut req, UsernameLabelParserVoid::new(), "", '-').is_err()
        );
        assert!(
            parse_username(&mut ctx, &mut req, UsernameLabelParserVoid::new(), "-", '-').is_err()
        );
    }

    #[test]
    fn test_parse_username_no_labels() {
        let mut ctx = Context::default();
        let mut req = ();

        assert_eq!(
            parse_username(&mut ctx, &mut req, UsernameNoLabelParser, "username", '-').unwrap(),
            "username"
        );
    }

    #[test]
    fn test_parse_username_label_collector() {
        let mut ctx = Context::default();
        let mut req = ();

        assert_eq!(
            parse_username(
                &mut ctx,
                &mut req,
                UsernameOpaqueLabelParser::new(),
                "username-label1-label2",
                '-'
            )
            .unwrap(),
            "username"
        );

        let labels = ctx.get::<UsernameLabels>().unwrap();
        assert_eq!(labels.0, vec!["label1".to_owned(), "label2".to_owned()]);
    }

    #[test]
    fn test_username_labels_multi_parser() {
        let mut ctx = Context::default();
        let mut req = ();

        let parser = (
            UsernameOpaqueLabelParser::new(),
            UsernameNoLabelParser::default(),
        );

        assert_eq!(
            parse_username(&mut ctx, &mut req, parser, "username-label1-label2", '-').unwrap(),
            "username"
        );

        let labels = ctx.get::<UsernameLabels>().unwrap();
        assert_eq!(labels.0, vec!["label1".to_owned(), "label2".to_owned()]);
    }

    #[test]
    fn test_username_labels_multi_consumer_parser_with_context_and_state_usage() {
        #[derive(Debug, Default, AsRef)]
        struct State {
            counter: LabelCounter,
        }

        let mut ctx = Context::with_state(Arc::new(State::default()));
        let mut req = Request::builder()
            .method("GET")
            .uri("http://www.example.com")
            .body(Body::empty())
            .unwrap();

        let parser = (
            UsernameNoLabelParser::default(),
            MyLabelParser::default(),
            UsernameOpaqueLabelParser::new(),
        );

        assert_eq!(
            parse_username(&mut ctx, &mut req, parser, "username-label1-label2", '-').unwrap(),
            "username"
        );

        let labels = ctx.get::<UsernameLabels>().unwrap();
        assert_eq!(labels.0, vec!["label1".to_owned(), "label2".to_owned()]);

        let labels = ctx.get::<MyLabels>().unwrap();
        assert_eq!(labels.0, vec!["label1".to_owned(), "label2".to_owned()]);

        let header_labels = req.headers().get("x-labels").unwrap();
        assert_eq!(header_labels, "label1,label2");

        assert_eq!(ctx.state().counter.0.load(Ordering::SeqCst), 2);
    }
}
