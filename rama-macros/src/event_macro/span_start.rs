use proc_macro2::TokenStream;
use quote::quote;
use syn::{DeriveInput, GenericParam, Path, parse_quote};

use crate::utils::support_root_ts;

pub(crate) fn expand(mut item: DeriveInput) -> syn::Result<TokenStream> {
    for param in item.generics.params.iter() {
        if matches!(param, GenericParam::Lifetime(_)) {
            return Err(syn::Error::new_spanned(
                &item.generics,
                "`#[derive(SpanStart)]` doesn't support lifetime parameters",
            ));
        }
    }

    let end = parse_end(&item)?;

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
        impl #impl_generics #root_crate::telemetry::event::SpanStart for #ident #ty_generics #where_clause {
            type End = #end;
        }
    })
}

fn parse_end(item: &DeriveInput) -> syn::Result<Path> {
    let mut end = None;

    for attr in &item.attrs {
        if !attr.path().is_ident("span") {
            continue;
        }

        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("end") {
                if end.is_some() {
                    return Err(meta.error("duplicate `end` event"));
                }
                end = Some(meta.value()?.parse::<Path>()?);
                Ok(())
            } else {
                Err(meta.error("unknown span attribute, expected `end`"))
            }
        })?;
    }

    end.ok_or_else(|| {
        syn::Error::new_spanned(
            &item.ident,
            "`#[derive(SpanStart)]` needs the end event: `#[span(end = MyEndEvent)]`",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::{expand, parse_end};
    use syn::parse_quote;

    #[test]
    fn expand_implements_span_start_with_its_end_event() {
        let item: syn::DeriveInput = parse_quote! {
            #[span(end = ConnectionClosed)]
            struct ConnectionAccepted;
        };
        let out = expand(item).unwrap().to_string();
        assert!(out.contains("SpanStart for ConnectionAccepted"));
        assert!(out.contains("type End = ConnectionClosed"));
    }

    #[test]
    fn parse_end_accepts_a_path() {
        let item: syn::DeriveInput = parse_quote! {
            #[span(end = crate::events::Closed)]
            struct Started;
        };
        let end = parse_end(&item).unwrap();
        assert_eq!(end.segments.len(), 3);
    }

    #[test]
    fn expand_rejects_a_missing_end() {
        let item: syn::DeriveInput = parse_quote! {
            struct Started;
        };
        let err = expand(item).unwrap_err();
        assert!(
            err.to_string().contains("needs the end event"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn expand_rejects_an_unknown_attribute() {
        let item: syn::DeriveInput = parse_quote! {
            #[span(start = Foo)]
            struct Started;
        };
        let err = expand(item).unwrap_err();
        assert!(
            err.to_string().contains("unknown span attribute"),
            "unexpected error: {err}"
        );
    }
}
