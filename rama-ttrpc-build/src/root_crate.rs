use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::Span;
use quote::quote;
use syn::Ident;

/// Resolve the path prefix through which generated code should reach `rama-ttrpc`.
///
/// Generated stubs must work whether the consumer depends on the umbrella `rama` crate
/// (where the runtime lives at `rama::ttrpc`) or on `rama-ttrpc` directly, so we can't
/// hardcode `rama_ttrpc`. We prefer the standalone crate, fall back
/// to the umbrella (rama) crate, and emit a `compile_error!` otherwise.
pub(super) fn root_crate_name_ts() -> proc_macro2::TokenStream {
    // Prefer to the `rama-ttrpc` crate directly.
    if let Ok(found) = crate_name("rama-ttrpc") {
        return match found {
            FoundCrate::Itself => quote!(crate),
            FoundCrate::Name(name) => {
                let ident = Ident::new(&name, Span::call_site());
                quote!(::#ident)
            }
        };
    }

    // fallback to the umbrella crate.
    if let Ok(found) = crate_name("rama") {
        let ident = match found {
            FoundCrate::Itself => Ident::new("rama", Span::call_site()),
            FoundCrate::Name(name) => Ident::new(&name, Span::call_site()),
        };
        return quote!(::#ident::ttrpc);
    }

    quote! {
        { compile_error!(
            "ttrpc build macro could not find supported crate. \
             Add a dependency on `rama-ttrpc` or `rama`."
        ); }
    }
}
