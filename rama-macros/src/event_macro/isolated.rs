use proc_macro2::TokenStream;
use quote::quote;
use syn::{FnArg, ItemFn, Pat};

use crate::utils::support_root_ts;

pub(crate) fn expand(item: ItemFn) -> syn::Result<TokenStream> {
    // `modifiers` only holds `default`, which a free test function never has.
    let ItemFn {
        attrs,
        vis,
        mut sig,
        block,
        ..
    } = item;
    let mut inputs = sig.inputs.iter();
    let (Some(input), None) = (inputs.next(), inputs.next()) else {
        return Err(syn::Error::new_spanned(
            &sig.inputs,
            "`#[isolated]` expects exactly one parameter: the `EventDispatcher` of the test",
        ));
    };
    let FnArg::Typed(input) = input else {
        return Err(syn::Error::new_spanned(
            input,
            "`#[isolated]` cannot be used on a method",
        ));
    };
    let Pat::Ident(name) = &*input.pat else {
        return Err(syn::Error::new_spanned(
            &input.pat,
            "`#[isolated]` expects a plain name for the `EventDispatcher` parameter",
        ));
    };
    let name = name.ident.clone();
    let ty = input.ty.clone();

    let root_crate = support_root_ts("rama-core", None);
    let scoped = if sig.asyncness.is_some() {
        quote! { #name.clone().scope(async move #block).await }
    } else {
        quote! { #name.clone().scope_sync(move || #block) }
    };

    sig.inputs.clear();
    Ok(quote! {
        #(#attrs)*
        #vis #sig {
            let #name: #ty = #root_crate::telemetry::event::EventDispatcher::default();
            #scoped
        }
    })
}

#[cfg(test)]
mod tests {
    use super::expand;
    use syn::parse_quote;

    #[test]
    fn an_async_test_runs_its_body_in_a_scope() {
        let tokens = expand(parse_quote! {
            #[tokio::test]
            async fn emits(events: EventDispatcher) {
                events.subscribe(|_: &Emitted<'_, Ping>| {});
            }
        })
        .unwrap()
        .to_string();

        assert!(tokens.contains("# [tokio :: test]"), "{tokens}");
        assert!(tokens.contains("async fn emits ()"), "{tokens}");
        assert!(
            tokens.contains("let events : EventDispatcher ="),
            "{tokens}"
        );
        assert!(tokens.contains(". scope (async move"), "{tokens}");
    }

    #[test]
    fn a_sync_test_uses_the_sync_scope() {
        let tokens = expand(parse_quote! {
            #[test]
            fn emits(dispatcher: EventDispatcher) {}
        })
        .unwrap()
        .to_string();

        assert!(tokens.contains("fn emits ()"), "{tokens}");
        assert!(tokens.contains(". scope_sync (move ||"), "{tokens}");
    }

    #[test]
    fn a_test_without_the_parameter_is_rejected() {
        let error = expand(parse_quote! {
            #[test]
            fn emits() {}
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains("exactly one parameter"), "{error}");
    }
}
