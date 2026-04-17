use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::{DeriveInput, GenericParam, parse_quote};

const KNOWN_TAGS: &[&str] = &["tls", "http", "net", "ua", "proxy", "ws", "dns", "grpc"];

fn tag_to_trait_name(tag: &str) -> Option<&'static str> {
    match tag {
        "tls" => Some("TlsExtension"),
        "http" => Some("HttpExtension"),
        "net" => Some("NetExtension"),
        "ua" => Some("UaExtension"),
        "proxy" => Some("ProxyExtension"),
        "ws" => Some("WsExtension"),
        "dns" => Some("DnsExtension"),
        "grpc" => Some("GrpcExtension"),
        _ => None,
    }
}

pub(crate) fn expand(mut item: DeriveInput) -> syn::Result<TokenStream> {
    for param in item.generics.params.iter() {
        if matches!(param, GenericParam::Lifetime(_)) {
            return Err(syn::Error::new_spanned(
                &item.generics,
                "`#[derive(Extension)]` doesn't support lifetime parameters",
            ));
        }
    }

    let tags = parse_tags(&item)?;

    // This will go over all generics in the struct eg item: S, code: T
    // and will for each generic add these bound S: Any + Send + Sync + Debug + 'static
    // These bounds are needed to implement Extension, so all generics need them aswel
    for param in item.generics.params.iter_mut() {
        if let GenericParam::Type(type_param) = param {
            type_param.bounds.push(parse_quote!(::core::any::Any));
            type_param.bounds.push(parse_quote!(::core::marker::Send));
            type_param.bounds.push(parse_quote!(::core::marker::Sync));
            type_param.bounds.push(parse_quote!(::core::fmt::Debug));
            type_param.bounds.push(parse_quote!('static));
        }
    }

    let root_crate = support_root_ts();

    let ident = item.ident;
    let (impl_generics, ty_generics, where_clause) = item.generics.split_for_impl();

    let mut output = quote! {
        impl #impl_generics #root_crate::extensions::Extension for #ident #ty_generics #where_clause {}
    };

    for tag in &tags {
        let trait_name =
            tag_to_trait_name(tag).expect("tag should have been validated during parsing");
        let trait_ident = Ident::new(trait_name, Span::call_site());
        output.extend(quote! {
            impl #impl_generics #root_crate::extensions::#trait_ident for #ident #ty_generics #where_clause {}
        });
    }

    Ok(output)
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

fn parse_tags(item: &DeriveInput) -> syn::Result<Vec<String>> {
    let mut tags = Vec::new();

    for attr in &item.attrs {
        if !attr.path().is_ident("extension") {
            continue;
        }

        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("tags") {
                // parse: tags(http, proxy)
                meta.parse_nested_meta(|tag_meta| {
                    let ident = tag_meta
                        .path
                        .get_ident()
                        .ok_or_else(|| tag_meta.error("expected a tag name"))?;

                    let tag = ident.to_string();
                    if tag_to_trait_name(&tag).is_none() {
                        return Err(syn::Error::new_spanned(
                            ident,
                            format!(
                                "unknown extension tag `{tag}`. Known tags: {}",
                                KNOWN_TAGS.join(", ")
                            ),
                        ));
                    }

                    if tags.contains(&tag) {
                        return Err(syn::Error::new_spanned(
                            ident,
                            format!("duplicate extension tag `{tag}`"),
                        ));
                    }
                    tags.push(tag);
                    Ok(())
                })?;
            } else {
                return Err(meta.error("unknown extension attribute, expected `tags`"));
            }
            Ok(())
        })?;
    }

    Ok(tags)
}

#[cfg(test)]
mod tests {
    use super::parse_tags;
    use syn::parse_quote;

    #[test]
    fn parse_tags_empty_when_attr_absent() {
        let item: syn::DeriveInput = parse_quote! {
            struct MyExt;
        };

        let tags = parse_tags(&item).unwrap();
        assert!(tags.is_empty());
    }

    #[test]
    fn parse_tags_collects_valid_tags() {
        let item: syn::DeriveInput = parse_quote! {
            #[extension(tags(http, proxy))]
            struct MyExt;
        };

        let tags = parse_tags(&item).unwrap();
        assert_eq!(tags, vec!["http".to_owned(), "proxy".to_owned()]);
    }

    #[test]
    fn parse_tags_rejects_unknown_tag() {
        let item: syn::DeriveInput = parse_quote! {
            #[extension(tags(http, banana))]
            struct MyExt;
        };

        let err = parse_tags(&item).unwrap_err();
        assert!(
            err.to_string().contains("unknown extension tag `banana`"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_tags_rejects_duplicate_tags() {
        let item: syn::DeriveInput = parse_quote! {
            #[extension(tags(http, http))]
            struct MyExt;
        };

        let err = parse_tags(&item).unwrap_err();
        assert!(
            err.to_string().contains("duplicate extension tag `http`"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_tags_rejects_unknown_extension_attribute_field() {
        let item: syn::DeriveInput = parse_quote! {
            #[extension(foo(http))]
            struct MyExt;
        };

        let err = parse_tags(&item).unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown extension attribute, expected `tags`"),
            "unexpected error: {err}"
        );
    }
}
