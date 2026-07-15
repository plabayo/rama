use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::Span;
use quote::quote;
use syn::Ident;

/// Resolve the path prefix through which generated code should reach `rama-grpc`.
///
/// Generated stubs must work whether the consumer depends on `rama-grpc` directly (where the
/// runtime lives at the crate root) or on the umbrella `rama` crate (where it lives at
/// `rama::http::grpc`), so we can't hardcode `rama_grpc`. We prefer the standalone crate, fall
/// back to the umbrella (rama) crate, and emit a `compile_error!` otherwise.
pub(super) fn root_crate_name_ts() -> proc_macro2::TokenStream {
    // Prefer the `rama-grpc` crate directly.
    if let Ok(found) = crate_name("rama-grpc") {
        return match found {
            FoundCrate::Itself => quote!(crate),
            FoundCrate::Name(name) => {
                let ident = Ident::new(&name, Span::call_site());
                quote!(::#ident)
            }
        };
    }

    // Fall back to the umbrella crate.
    if let Ok(found) = crate_name("rama") {
        let ident = match found {
            FoundCrate::Itself => Ident::new("rama", Span::call_site()),
            FoundCrate::Name(name) => Ident::new(&name, Span::call_site()),
        };
        return quote!(::#ident::http::grpc);
    }

    quote! {
        { compile_error!(
            "grpc build macro could not find supported crate. \
             Add a dependency on `rama-grpc` or `rama`."
        ); }
    }
}
