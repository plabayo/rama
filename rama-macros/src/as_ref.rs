use proc_macro2::{Ident, TokenStream};
use quote::quote_spanned;
use syn::{
    parse::{Parse, ParseStream},
    spanned::Spanned,
    Field, ItemStruct, Token,
};

use crate::{
    attr_parsing::{combine_unary_attribute, parse_attrs, Combine},
    type_parsing::extract_type_from_arc,
};

pub(crate) fn expand(item: ItemStruct) -> syn::Result<TokenStream> {
    if !item.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            item.generics,
            "`#[derive(AsRef)]` doesn't support generics",
        ));
    }

    let tokens = item
        .fields
        .iter()
        .enumerate()
        .map(|(idx, field)| expand_field(&item.ident, idx, field))
        .collect();

    Ok(tokens)
}

fn expand_field(state: &Ident, idx: usize, field: &Field) -> TokenStream {
    let FieldAttrs { skip, wrap } = match parse_attrs("as_ref", &field.attrs) {
        Ok(attrs) => attrs,
        Err(err) => return err.into_compile_error(),
    };

    if skip.is_some() {
        return TokenStream::default();
    }

    let field_ty = &field.ty;
    let span = field.ty.span();

    let body = if let Some(field_ident) = &field.ident {
        quote_spanned! {span=> &self.#field_ident }
    } else {
        let idx = syn::Index {
            index: idx as _,
            span: field.span(),
        };
        quote_spanned! {span=> &self.#idx }
    };

    if wrap.is_some() {
        return match extract_type_from_arc(field_ty) {
            Some(field_ty) => {
                quote_spanned! {span=>
                    impl<T> ::std::convert::AsRef<T> for #state
                        where #field_ty: ::std::convert::AsRef<T>
                    {
                        fn as_ref(&self) -> &T {
                            use ::core::ops::Deref;
                            #body.deref().as_ref()
                        }
                    }
                }
            }
            None => syn::Error::new_spanned(
                field.ty.clone(),
                "`#[as_ref(wrap)]` is only supported for Arc types",
            )
            .into_compile_error(),
        };
    }

    quote_spanned! {span=>
        impl ::std::convert::AsRef<#field_ty> for #state {
            fn as_ref(&self) -> &#field_ty {
                #body
            }
        }
    }
}

mod kw {
    syn::custom_keyword!(skip);
    syn::custom_keyword!(wrap);
}

#[derive(Default)]
pub(super) struct FieldAttrs {
    pub(super) skip: Option<kw::skip>,
    pub(super) wrap: Option<kw::wrap>,
}

impl Parse for FieldAttrs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut skip = None;
        let mut wrap = None;

        while !input.is_empty() {
            let lh = input.lookahead1();
            if lh.peek(kw::skip) {
                skip = Some(input.parse()?);
            } else if lh.peek(kw::wrap) {
                wrap = Some(input.parse()?);
            } else {
                return Err(lh.error());
            }

            let _ = input.parse::<Token![,]>();
        }

        Ok(Self { skip, wrap })
    }
}

impl Combine for FieldAttrs {
    fn combine(mut self, other: Self) -> syn::Result<Self> {
        let Self { skip, wrap } = other;
        combine_unary_attribute(&mut self.skip, skip)?;
        combine_unary_attribute(&mut self.wrap, wrap)?;
        Ok(self)
    }
}

#[test]
fn ui() {
    crate::run_ui_tests("as_ref");
}
