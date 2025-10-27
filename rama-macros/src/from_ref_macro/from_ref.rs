use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::{Ident, Span, TokenStream};
use quote::{quote, quote_spanned};
use syn::{
    Field, ItemStruct, Token, Type,
    parse::{Parse, ParseStream},
    spanned::Spanned,
};

use super::attr_parsing::{Combine, combine_unary_attribute, parse_attrs};

pub(crate) fn expand(item: ItemStruct) -> syn::Result<TokenStream> {
    if !item.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            item.generics,
            "`#[derive(FromRef)]` doesn't support generics",
        ));
    }

    let root_crate = support_root_ts();

    let tokens = item
        .fields
        .iter()
        .enumerate()
        .map(|(idx, field)| expand_field(&item.ident, idx, field, &root_crate))
        .collect();

    Ok(tokens)
}

fn expand_field(state: &Ident, idx: usize, field: &Field, root_crate: &TokenStream) -> TokenStream {
    let FieldAttrs { skip } = match parse_attrs("from_ref", &field.attrs) {
        Ok(attrs) => attrs,
        Err(err) => return err.into_compile_error(),
    };

    if skip.is_some() {
        return TokenStream::default();
    }

    let field_ty = &field.ty;
    let span = field.ty.span();

    let body = if let Some(field_ident) = &field.ident {
        if matches!(field_ty, Type::Reference(_)) {
            quote_spanned! {span=> state.#field_ident }
        } else {
            quote_spanned! {span=> state.#field_ident.clone() }
        }
    } else {
        let idx = syn::Index {
            index: idx as _,
            span: field.span(),
        };
        quote_spanned! {span=> state.#idx.clone() }
    };

    quote_spanned! {span=>
        #[allow(clippy::clone_on_copy, clippy::clone_on_ref_ptr)]
        impl #root_crate::conversion::FromRef<#state> for #field_ty {
            fn from_ref(state: &#state) -> Self {
                #body
            }
        }
    }
}

mod kw {
    syn::custom_keyword!(skip);
}

#[derive(Default)]
pub(super) struct FieldAttrs {
    pub(super) skip: Option<kw::skip>,
}

impl Parse for FieldAttrs {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut skip = None;

        while !input.is_empty() {
            let lh = input.lookahead1();
            if lh.peek(kw::skip) {
                skip = Some(input.parse()?);
            } else {
                return Err(lh.error());
            }

            let _ = input.parse::<Token![,]>();
        }

        Ok(Self { skip })
    }
}

impl Combine for FieldAttrs {
    fn combine(mut self, other: Self) -> syn::Result<Self> {
        let Self { skip } = other;
        combine_unary_attribute(&mut self.skip, skip)?;
        Ok(self)
    }
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
            "from_ref could not find FromRef trait. \
             Add a dependency on `rama` or `rama-core`."
        ); }
    }
}
