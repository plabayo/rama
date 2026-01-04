use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::Span;
use quote::quote;
use syn::Ident;

pub(super) fn root_crate_name_ts() -> proc_macro2::TokenStream {
    // Prefer the umbrella crate
    if let Ok(found) = crate_name("rama") {
        let ident = match found {
            FoundCrate::Itself => Ident::new("rama", Span::call_site()),
            FoundCrate::Name(name) => Ident::new(&name, Span::call_site()),
        };
        return quote!(::#ident::http::grpc);
    }

    // Fall back to the rama-grpc crate directly
    if let Ok(found) = crate_name("rama-grpc") {
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
            "grpc build macro could not find supported crate. \
             Add a dependency on `rama` or `rama-grpc`."
        ); }
    }
}
