extern crate proc_macro;

use proc_macro::{TokenStream, TokenTree};

#[proc_macro_attribute]
pub fn paste_test(args: TokenStream, input: TokenStream) -> TokenStream {
    let mut iter = args.clone().into_iter();
    match iter.next() {
        Some(TokenTree::Ident(_)) => {}
        _ => panic!("{}", args),
    }
    match iter.next() {
        Some(TokenTree::Punct(ref punct)) if punct.as_char() == '=' => {}
        _ => panic!("{}", args),
    }
    match iter.next() {
        Some(TokenTree::Literal(ref literal)) if literal.to_string().starts_with('"') => {}
        _ => panic!("{}", args),
    }
    match iter.next() {
        None => {}
        _ => panic!("{}", args),
    }
    input
}
