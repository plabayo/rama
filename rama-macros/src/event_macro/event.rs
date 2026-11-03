use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, GenericParam, parse_quote};

use crate::utils::support_root_ts;

pub(crate) fn expand(mut item: DeriveInput) -> syn::Result<TokenStream> {
    for param in item.generics.params.iter() {
        if matches!(param, GenericParam::Lifetime(_)) {
            return Err(syn::Error::new_spanned(
                &item.generics,
                "`#[derive(Event)]` doesn't support lifetime parameters",
            ));
        }
    }

    for param in item.generics.params.iter_mut() {
        if let GenericParam::Type(type_param) = param {
            type_param.bounds.push(parse_quote!(::core::clone::Clone));
            type_param.bounds.push(parse_quote!(::core::marker::Send));
            type_param.bounds.push(parse_quote!('static));
        }
    }

    let root_crate = support_root_ts("rama-core", None);

    let ident = item.ident;
    let (impl_generics, ty_generics, where_clause) = item.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #root_crate::telemetry::event::Event for #ident #ty_generics #where_clause {}
    })
}

#[cfg(test)]
mod tests {
    use super::expand;
    use syn::parse_quote;

    #[test]
    fn expand_implements_event() {
        let item: syn::DeriveInput = parse_quote! {
            struct PathChanged {
                peer: u16,
            }
        };
        let out = expand(item).unwrap().to_string();
        assert!(out.contains("Event for PathChanged"));
    }

    #[test]
    fn expand_bounds_each_generic_and_keeps_the_where_clause() {
        let item: syn::DeriveInput = parse_quote! {
            struct Pair<A, B> where A: Clone {
                a: A,
                b: B,
            }
        };
        let out = expand(item).unwrap().to_string();
        assert!(out.contains("for Pair < A , B >"));
        assert!(out.contains("where A : Clone"));
        assert_eq!(out.matches(":: core :: marker :: Send").count(), 2);
        assert_eq!(out.matches(":: core :: clone :: Clone").count(), 2);
        assert!(!out.contains(":: core :: marker :: Sync"));
    }

    #[test]
    fn expand_rejects_lifetime_parameter() {
        let item: syn::DeriveInput = parse_quote! {
            struct Borrowed<'a> {
                inner: &'a str,
            }
        };
        let err = expand(item).unwrap_err();
        assert!(
            err.to_string()
                .contains("doesn't support lifetime parameters"),
            "unexpected error: {err}"
        );
    }
}
