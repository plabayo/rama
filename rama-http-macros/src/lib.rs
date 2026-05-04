//! Procedural macros powering `rama_http::html`.
//!
//! End users should not depend on this crate directly — it is re-exported
//! from `rama-http` (and thus `rama`) under the `html` feature gate.
//!
//! The macros and parser logic are a permanent fork of
//! [`vy-macros`](https://github.com/JonahLund/vy), adapted to integrate
//! naturally with the rama ecosystem (in particular re-using
//! `rama_core::combinators::Either` instead of vendoring its own
//! `Either` type).

mod ast;
mod fmt;
#[macro_use]
mod known;
mod root;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{LitStr, Token, parse::Parse, parse_macro_input};

use self::{
    ast::{Element, ElementBody, ElementHead},
    fmt::{Part, Serializer},
    root::resolve_root,
};

mod kw {
    syn::custom_keyword!(__rama_html_import_marker);
}

enum Inner {
    Marker,
    Body(ElementBody),
}

impl Parse for Inner {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        if input.parse::<kw::__rama_html_import_marker>().is_ok() {
            return Ok(Self::Marker);
        }

        Ok(Self::Body(input.parse()?))
    }
}

fn render(head: ElementHead, body: ElementBody) -> TokenStream2 {
    render_with_prefix(head, body, "")
}

fn render_with_prefix(head: ElementHead, body: ElementBody, prefix: &str) -> TokenStream2 {
    let el = match Element::new(head, body) {
        Ok(el) => el,
        Err(err) => return err.to_compile_error(),
    };

    let root = resolve_root();

    let mut text = String::from(prefix);
    let mut ser = Serializer::new(&mut text, root.clone());
    ser.write_element(el);

    let imports = ser.as_imports();
    let parts = ser.into_parts().into_iter().map(|part| match part {
        Part::Str(s) => quote!(#root::html::PreEscaped(#s)),
        Part::Expr(e) => quote!(#e),
    });

    quote!({
        #imports;
        #root::html::HtmlBuf(( #(#parts),* ))
    })
}

fn known_inner(name: &str, input: TokenStream) -> TokenStream {
    let parsed = parse_macro_input!(input as Inner);

    let body = match parsed {
        Inner::Marker => return quote!(()).into(),
        Inner::Body(element_body) => element_body,
    };

    let head = match ElementHead::known(format_ident!("{}", name)) {
        Ok(h) => h,
        Err(err) => return err.to_compile_error().into(),
    };

    // The `<html>` element is always the document root, so the macro
    // emits `<!DOCTYPE html>` as a prefix. The result is therefore a
    // complete HTML page — directly returnable from a handler as
    // `IntoResponse`. If a caller really wants a bare `<html>` element
    // without the doctype (rare), they can use `custom!("html", ...)`.
    let prefix = if name == "html" {
        "<!DOCTYPE html>"
    } else {
        ""
    };

    render_with_prefix(head, body, prefix).into()
}

/// Render an HTML element with a runtime-supplied tag name —
/// useful for [web components] and any other custom element.
///
/// ```ignore
/// // <my-icon size="lg"><span>x</span></my-icon>
/// custom!("my-icon", size = "lg", span!("x"))
/// ```
///
/// The first argument must be a string literal naming the tag. Subsequent
/// arguments behave exactly like the body of a known-element macro:
/// attributes (`name = value` / `name? = optional`) followed by children.
///
/// Custom elements are always rendered as containers — there is no
/// "void" form, since web components are by definition non-void. Also
/// note that the macro performs no validation of the tag name; the caller
/// is responsible for picking a name that is legal HTML.
///
/// [web components]: https://developer.mozilla.org/en-US/docs/Web/API/Web_components
#[proc_macro]
pub fn custom(input: TokenStream) -> TokenStream {
    struct CustomInput {
        tag: LitStr,
        body: Option<ElementBody>,
    }

    impl Parse for CustomInput {
        fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
            let tag: LitStr = input.parse()?;
            let body = if input.is_empty() {
                None
            } else {
                let _: Token![,] = input.parse()?;
                Some(input.parse()?)
            };
            Ok(Self { tag, body })
        }
    }

    let CustomInput { tag, body } = parse_macro_input!(input as CustomInput);
    let head = ElementHead::custom(tag.value());
    let body = body.unwrap_or(ElementBody {
        attrs: Vec::new(),
        nodes: Vec::new(),
    });
    render(head, body).into()
}

macro_rules! define_proc_macro {
    ($($(#[doc=$doc:literal])* $el:ident)+) => {
        $(
            $(#[doc = $doc])*
            #[proc_macro]
            pub fn $el(input: TokenStream) -> TokenStream {
                known_inner(stringify!($el), input)
            }
        )+
    };
}

for_all_elements!(define_proc_macro);
