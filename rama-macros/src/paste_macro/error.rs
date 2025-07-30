use proc_macro::{Delimiter, Group, Ident, Literal, Punct, Spacing, Span, TokenStream, TokenTree};
use std::iter::FromIterator;

pub(super) type Result<T> = std::result::Result<T, Error>;

pub(crate) struct Error {
    begin: Span,
    end: Span,
    msg: String,
}

impl Error {
    pub(super) fn new(span: Span, msg: &str) -> Self {
        Self::new2(span, span, msg)
    }

    pub(super) fn new2(begin: Span, end: Span, msg: &str) -> Self {
        Self {
            begin,
            end,
            msg: msg.to_owned(),
        }
    }

    pub(crate) fn to_compile_error(&self) -> TokenStream {
        // compile_error! { $msg }
        TokenStream::from_iter(vec![
            TokenTree::Ident(Ident::new("compile_error", self.begin)),
            TokenTree::Punct({
                let mut punct = Punct::new('!', Spacing::Alone);
                punct.set_span(self.begin);
                punct
            }),
            TokenTree::Group({
                let mut group = Group::new(Delimiter::Brace, {
                    TokenStream::from_iter(vec![TokenTree::Literal({
                        let mut string = Literal::string(&self.msg);
                        string.set_span(self.end);
                        string
                    })])
                });
                group.set_span(self.end);
                group
            }),
        ])
    }
}
