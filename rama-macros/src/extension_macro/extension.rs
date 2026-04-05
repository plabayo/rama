use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::{DeriveInput, GenericParam, parse_quote};

pub(crate) fn expand(mut item: DeriveInput) -> syn::Result<TokenStream> {
    for param in item.generics.params.iter() {
        if matches!(param, GenericParam::Lifetime(_)) {
            return Err(syn::Error::new_spanned(
                &item.generics,
                "`#[derive(Extension)]` doesn't support lifetime parameters",
            ));
        }
    }

    // This will go over all generics in the struct eg item: S, code: T
    // and will for each generic add these bound S: Any + Send + Sync + Debug + 'static
    // These bounds are needed to implement Extension, so all generics need them aswel
    for param in item.generics.params.iter_mut() {
        if let GenericParam::Type(type_param) = param {
            type_param.bounds.push(parse_quote!(::std::any::Any));
            type_param.bounds.push(parse_quote!(::std::marker::Send));
            type_param.bounds.push(parse_quote!(::std::marker::Sync));
            type_param.bounds.push(parse_quote!(::std::fmt::Debug));
            type_param.bounds.push(parse_quote!('static));
        }
    }

    let root_crate = support_root_ts();

    let ident = item.ident;
    let (impl_generics, ty_generics, where_clause) = item.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #root_crate::extensions::Extension for #ident #ty_generics #where_clause {}
    })
}

fn support_root_ts() -> proc_macro2::TokenStream {
    // Prefer the umbrella crate
    if let Ok(found) = crate_name("rama") {
        let ident = match found {
            FoundCrate::Itself => Ident::new("rama", Span::call_site()),
            FoundCrate::Name(name) => Ident::new(&name, Span::call_site()),
        };
        return quote!(::#ident);
    }

    // Fall back to the rama-core crate directly
    if let Ok(found) = crate_name("rama-core") {
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
            "extension derive could not find Extension trait. \
             Add a dependency on `rama` or `rama-core`."
        ); }
    }
}
