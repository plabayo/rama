use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::Ident;

/// Resolve the root path under which `rama-http`'s `html` module lives.
///
/// We try, in order:
///   1. the `rama` umbrella crate — produces `::rama::http`,
///   2. the `rama-http` crate — produces `::rama_http`,
///   3. a `crate` fallback (used when the macros are exercised from inside
///      `rama-http` itself, e.g. doctests / tests).
pub(crate) fn resolve_root() -> TokenStream {
    if let Ok(found) = crate_name("rama") {
        let ident = match found {
            FoundCrate::Itself => Ident::new("rama", Span::call_site()),
            FoundCrate::Name(name) => Ident::new(&name, Span::call_site()),
        };
        return quote!(::#ident::http);
    }

    if let Ok(found) = crate_name("rama-http") {
        return match found {
            FoundCrate::Itself => quote!(crate),
            FoundCrate::Name(name) => {
                let ident = Ident::new(&name, Span::call_site());
                quote!(::#ident)
            }
        };
    }

    quote! {
        { compile_error!(
            "rama-http-macros could not find rama-http or rama. \
             Add a dependency on `rama` (with the `html` feature) \
             or `rama-http` (with the `html` feature)."
        ); }
    }
}
