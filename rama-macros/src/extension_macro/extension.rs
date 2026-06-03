use proc_macro2::{Ident, Span, TokenStream};
use quote::quote;
use syn::{DeriveInput, GenericParam, parse_quote};

use crate::utils::support_root_ts;

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

    let root_crate = support_root_ts("rama-core", None);

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
    use super::{expand, parse_tags};
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

    /// A `where`-clause on the deriving type must survive the expansion
    /// untouched and appear on every emitted `impl` block — both the base
    /// `Extension` impl and any `tags(...)`-driven marker-trait impls.
    #[test]
    fn expand_preserves_where_clause() {
        let item: syn::DeriveInput = parse_quote! {
            #[extension(tags(http))]
            struct MyExt<T> where T: Clone {
                inner: T,
            }
        };
        let out = expand(item).unwrap().to_string();
        // The base Extension impl appears with our where clause attached.
        assert!(out.contains("Extension for MyExt < T >"));
        assert!(out.contains("where T : Clone"));
        // The tagged HttpExtension impl also gets the where clause —
        // emitted twice (one per impl block).
        assert!(out.contains("HttpExtension for MyExt < T >"));
        assert_eq!(out.matches("where T : Clone").count(), 2);
    }

    /// Existing trait-bounds on a generic parameter must be preserved, with
    /// our required `Any + Send + Sync + Debug + 'static` bounds appended.
    /// Verify the user-supplied bound (`SomeTrait`) stays in the bound list.
    #[test]
    fn expand_appends_to_existing_bounds() {
        let item: syn::DeriveInput = parse_quote! {
            struct MyExt<T: SomeTrait + Sync> {
                inner: T,
            }
        };
        let out = expand(item).unwrap().to_string();
        // The user's `SomeTrait` bound is preserved.
        assert!(out.contains("SomeTrait"));
        // And the required Extension bounds are appended.
        assert!(out.contains(":: core :: any :: Any"));
        assert!(out.contains(":: core :: marker :: Send"));
        assert!(out.contains(":: core :: marker :: Sync"));
        assert!(out.contains(":: core :: fmt :: Debug"));
        assert!(out.contains("'static"));
    }

    /// Multiple generic type parameters must each receive the full set of
    /// required Extension bounds independently, and the generated impl
    /// blocks must list all of them in the order they were declared.
    #[test]
    fn expand_bounds_each_of_multiple_generics() {
        let item: syn::DeriveInput = parse_quote! {
            #[extension(tags(http, proxy))]
            struct MyExt<A, B> {
                a: A,
                b: B,
            }
        };
        let out = expand(item).unwrap().to_string();
        // Each impl block lists both generics in order: `<A, B>`.
        assert!(out.contains("for MyExt < A , B >"));
        // The Extension trait + both tag-derived traits appear (3 impls).
        assert_eq!(out.matches("for MyExt < A , B >").count(), 3);
        // The bound block adds `Any + Send + Sync + Debug + 'static` to
        // each of `A` and `B` — `impl_generics` is duplicated once per
        // emitted `impl` block (3 here), so 2 generics × 3 impls = 6
        // occurrences of `:: core :: any :: Any`.
        assert_eq!(out.matches(":: core :: any :: Any").count(), 6);
    }

    /// Lifetime parameters are explicitly rejected — the resulting `'static`
    /// bound that `Extension` requires would conflict with any non-`'static`
    /// borrow. Confirm a clear error message is produced.
    #[test]
    fn expand_rejects_lifetime_parameter() {
        let item: syn::DeriveInput = parse_quote! {
            struct MyExt<'a> {
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

    /// Const generic parameters are not type generics, so they should pass
    /// through without the macro trying to attach trait bounds to them
    /// (which would be a syntax error).
    #[test]
    fn expand_passes_const_generics_through_unchanged() {
        let item: syn::DeriveInput = parse_quote! {
            struct MyExt<const N: usize> {
                buf: [u8; N],
            }
        };
        let out = expand(item).unwrap().to_string();
        assert!(out.contains("for MyExt < N >"));
        // No spurious trait bounds got hung off the const generic — i.e.
        // we should NOT see Send/Sync/Debug being attached to `N`. The
        // const generic syntax `const N : usize` does itself contain
        // `N :`, so we look for the absence of the bound traits.
        assert!(!out.contains(":: core :: marker :: Send"));
        assert!(!out.contains(":: core :: fmt :: Debug"));
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
