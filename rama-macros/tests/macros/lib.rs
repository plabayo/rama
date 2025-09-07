extern crate proc_macro;

use proc_macro::{TokenStream, TokenTree};

#[proc_macro_attribute]
pub fn paste_test(args: TokenStream, input: TokenStream) -> TokenStream {
    let mut iter = args.clone().into_iter();

    if !matches!(iter.next(), Some(TokenTree::Ident(_))) {
        panic!("{args}")
    }

    if let Some(TokenTree::Punct(ref punct)) = iter.next()
        && punct.as_char() == '='
    {
    } else {
        panic!("{args}")
    }

    if let Some(TokenTree::Literal(ref literal)) = iter.next()
        && literal.to_string().starts_with('"')
    {
    } else {
        panic!("{args}")
    }

    if iter.next().is_some() {
        panic!("{args}")
    }

    input
}
