use proc_macro2::{TokenStream, TokenTree};
use quote::{ToTokens, quote};
use syn::{Data, DeriveInput, Field, Fields, GenericParam, Ident, Index, Member, Type};

use crate::utils::support_root_ts;

const ATTR: &str = "extensions_ref";

pub(crate) fn expand(item: &DeriveInput) -> syn::Result<TokenStream> {
    let fields = match &item.data {
        Data::Struct(data) => &data.fields,
        Data::Enum(data) => {
            return Err(syn::Error::new_spanned(
                data.enum_token,
                "`#[derive(ExtensionsRef)]` only supports structs",
            ));
        }
        Data::Union(data) => {
            return Err(syn::Error::new_spanned(
                data.union_token,
                "`#[derive(ExtensionsRef)]` only supports structs",
            ));
        }
    };

    let mut marked = None;
    for (index, field) in fields.iter().enumerate() {
        for attr in field.attrs.iter().filter(|attr| attr.path().is_ident(ATTR)) {
            attr.meta.require_path_only()?;
            if marked.is_some() {
                return Err(syn::Error::new_spanned(
                    attr,
                    "only one field can be marked with `#[extensions_ref]`",
                ));
            }
            marked = Some((member(index, field), field));
        }
    }

    let selected = marked
        .or_else(|| {
            fields
                .iter()
                .enumerate()
                .find(|(_, field)| field.ident.as_ref().is_some_and(|ident| ident == "inner"))
                .map(|(index, field)| (member(index, field), field))
        })
        .or_else(|| {
            let mut stores = fields
                .iter()
                .enumerate()
                .filter(|(_, field)| is_extensions_type(&field.ty));
            match (stores.next(), stores.next()) {
                (Some((index, field)), None) => Some((member(index, field), field)),
                _ => None,
            }
        })
        .or_else(|| match fields.len() {
            1 => fields.iter().next().map(|field| (member(0, field), field)),
            _ => None,
        });

    let Some((member, field)) = selected else {
        let span_source: &dyn ToTokens = match fields {
            Fields::Unit => &item.ident,
            _ => fields,
        };
        return Err(syn::Error::new_spanned(
            span_source,
            "`#[derive(ExtensionsRef)]` cannot pick a field: mark the field to forward with `#[extensions_ref]`",
        ));
    };

    if let Some(attr) = field
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
    {
        return Err(syn::Error::new_spanned(
            attr,
            "`#[derive(ExtensionsRef)]` cannot forward to a `cfg`-gated field: implement `ExtensionsRef` by hand",
        ));
    }

    let root_crate = support_root_ts("rama-core", None);
    let ident = &item.ident;
    let (impl_generics, ty_generics, where_clause) = item.generics.split_for_impl();
    let mut predicates: Vec<TokenStream> = where_clause
        .map(|clause| {
            clause
                .predicates
                .iter()
                .map(ToTokens::to_token_stream)
                .collect()
        })
        .unwrap_or_default();
    // Concrete field types get no bound so private field types stay out of the public impl.
    let ty = &field.ty;
    if mentions_type_param(ty, item) {
        predicates.push(quote!(#ty: #root_crate::extensions::ExtensionsRef));
    }
    let where_clause = (!predicates.is_empty()).then(|| quote!(where #(#predicates),*));

    Ok(quote! {
        impl #impl_generics #root_crate::extensions::ExtensionsRef for #ident #ty_generics #where_clause {
            #[inline(always)]
            fn extensions(&self) -> &#root_crate::extensions::Extensions {
                #root_crate::extensions::ExtensionsRef::extensions(&self.#member)
            }
        }
    })
}

fn member(index: usize, field: &Field) -> Member {
    match &field.ident {
        Some(ident) => Member::Named(ident.clone()),
        None => Member::Unnamed(Index::from(index)),
    }
}

fn is_extensions_type(ty: &Type) -> bool {
    match ty {
        // `macro_rules!` wrappers such as `pin_project!` pass `$ty:ty` fragments as groups.
        Type::Group(group) => is_extensions_type(&group.elem),
        Type::Paren(paren) => is_extensions_type(&paren.elem),
        Type::Path(path) => {
            path.qself.is_none()
                && path.path.segments.last().is_some_and(|segment| {
                    segment.ident == "Extensions" && segment.arguments.is_none()
                })
        }
        _ => false,
    }
}

fn mentions_type_param(ty: &Type, item: &DeriveInput) -> bool {
    let params: Vec<&Ident> = item
        .generics
        .params
        .iter()
        .filter_map(|param| match param {
            GenericParam::Type(param) => Some(&param.ident),
            GenericParam::Lifetime(_) | GenericParam::Const(_) => None,
        })
        .collect();
    !params.is_empty() && tokens_mention(ty.to_token_stream(), &params)
}

fn tokens_mention(tokens: TokenStream, params: &[&Ident]) -> bool {
    tokens.into_iter().any(|tree| match tree {
        TokenTree::Ident(ident) => params.iter().any(|param| **param == ident),
        TokenTree::Group(group) => tokens_mention(group.stream(), params),
        TokenTree::Punct(_) | TokenTree::Literal(_) => false,
    })
}

#[cfg(test)]
mod tests {
    use super::expand;
    use proc_macro2::{Delimiter, Group, TokenTree};
    use quote::ToTokens;
    use syn::{DeriveInput, parse_quote};

    fn expand_ok(input: &DeriveInput) -> String {
        expand(input)
            .expect("expected expansion to succeed")
            .to_string()
    }

    fn expand_err(input: &DeriveInput) -> String {
        expand(input)
            .expect_err("expected expansion to fail")
            .to_string()
    }

    #[test]
    fn bare_generic_field_bounds_only_that_param() {
        let out = expand_ok(&parse_quote! {
            struct Svc<S, W> {
                #[extensions_ref]
                inner: S,
                writer: W,
            }
        });
        assert!(out.contains("where S : "), "{out}");
        assert!(!out.contains("W :"), "{out}");
        assert!(out.contains("& self . inner"), "{out}");
    }

    #[test]
    fn generic_mentioning_field_bounds_the_field_type() {
        let out = expand_ok(&parse_quote! {
            struct Wrap<T, B> {
                #[extensions_ref]
                io: Framed<T, B>,
            }
        });
        assert!(out.contains("where Framed < T , B > : "), "{out}");
    }

    #[test]
    fn generic_nested_in_group_is_detected() {
        let out = expand_ok(&parse_quote! {
            struct Wrap<S> {
                #[extensions_ref]
                inner: Box<[(S,)]>,
            }
        });
        assert!(out.contains("where Box < [(S ,)] > :"), "{out}");
    }

    #[test]
    fn concrete_field_gets_no_bound() {
        let out = expand_ok(&parse_quote! {
            struct Conn<B> {
                #[extensions_ref]
                stream: TcpStream,
                body: B,
            }
        });
        assert!(!out.contains("where"), "{out}");
        assert!(
            out.contains("ExtensionsRef :: extensions (& self . stream)"),
            "{out}"
        );
    }

    #[test]
    fn tuple_field_uses_index() {
        let out = expand_ok(&parse_quote! {
            struct Wrapped<A, C>(A, #[extensions_ref] C);
        });
        assert!(out.contains("& self . 1"), "{out}");
        assert!(out.contains("where C :"), "{out}");
    }

    #[test]
    fn existing_where_clause_and_lifetimes_are_kept() {
        let out = expand_ok(&parse_quote! {
            struct Tx<'a, IO, const N: usize>
            where
                IO: Send,
            {
                #[extensions_ref]
                conn: &'a Conn<IO>,
            }
        });
        assert!(out.contains("impl < 'a , IO , const N : usize >"), "{out}");
        assert!(out.contains("for Tx < 'a , IO , N >"), "{out}");
        assert!(out.contains("IO : Send , & 'a Conn < IO > :"), "{out}");
    }

    #[test]
    fn field_named_inner_is_inferred() {
        let out = expand_ok(&parse_quote! {
            struct Svc<W, S> {
                writer: W,
                inner: S,
            }
        });
        assert!(out.contains("& self . inner"), "{out}");
        assert!(out.contains("where S : "), "{out}");
    }

    #[test]
    fn single_named_field_is_inferred() {
        let out = expand_ok(&parse_quote! {
            struct Conn<IO> {
                io: IO,
            }
        });
        assert!(out.contains("& self . io"), "{out}");
    }

    #[test]
    fn single_tuple_field_is_inferred() {
        let out = expand_ok(&parse_quote! {
            struct Wrapped<C>(C);
        });
        assert!(out.contains("& self . 0"), "{out}");
    }

    #[test]
    fn extensions_field_is_inferred() {
        let out = expand_ok(&parse_quote! {
            struct Conn<B> {
                body: B,
                extensions: rama_core::extensions::Extensions,
            }
        });
        assert!(
            out.contains("ExtensionsRef :: extensions (& self . extensions)"),
            "{out}"
        );
        assert!(!out.contains("where"), "{out}");

        let out = expand_ok(&parse_quote! {
            struct Store<A>(A, Extensions);
        });
        assert!(
            out.contains("ExtensionsRef :: extensions (& self . 1)"),
            "{out}"
        );
    }

    #[test]
    fn extensions_field_from_macro_fragment_is_inferred() {
        let mut item: DeriveInput = parse_quote! {
            struct Conn<T> {
                io: T,
                extensions: Extensions,
            }
        };
        let syn::Data::Struct(data) = &mut item.data else {
            unreachable!()
        };
        let field = data.fields.iter_mut().nth(1).expect("extensions field");
        let group = Group::new(Delimiter::None, field.ty.to_token_stream());
        field.ty = syn::parse2(TokenTree::Group(group).into()).expect("grouped type");
        assert!(matches!(field.ty, syn::Type::Group(_)));
        let out = expand_ok(&item);
        assert!(out.contains("& self . extensions"), "{out}");
    }

    #[test]
    fn generic_param_named_extensions_is_forwarded_with_bound() {
        let out = expand_ok(&parse_quote! {
            struct Wrap<Extensions> {
                other: u8,
                ext: Extensions,
            }
        });
        assert!(out.contains("where Extensions : "), "{out}");
        assert!(
            out.contains("ExtensionsRef :: extensions (& self . ext)"),
            "{out}"
        );
    }

    #[test]
    fn cfg_gated_field_is_rejected() {
        let err = expand_err(&parse_quote! {
            struct Posted<S> {
                #[cfg(windows)]
                inner: ManuallyDrop<S>,
                #[cfg(not(windows))]
                inner: S,
            }
        });
        assert!(err.contains("cfg`-gated field"), "{err}");
    }

    #[test]
    fn inner_wins_over_extensions_field() {
        let out = expand_ok(&parse_quote! {
            struct Svc<S> {
                extensions: Extensions,
                inner: S,
            }
        });
        assert!(out.contains("& self . inner"), "{out}");
    }

    #[test]
    fn two_extensions_fields_are_rejected() {
        let err = expand_err(&parse_quote! {
            struct Svc {
                a: Extensions,
                b: Extensions,
            }
        });
        assert!(err.contains("cannot pick a field"), "{err}");
    }

    #[test]
    fn marker_wins_over_inner() {
        let out = expand_ok(&parse_quote! {
            struct Svc<S, C> {
                inner: S,
                #[extensions_ref]
                conn: C,
            }
        });
        assert!(out.contains("& self . conn"), "{out}");
        assert!(!out.contains("S :"), "{out}");
    }

    #[test]
    fn ambiguous_fields_are_rejected() {
        let err = expand_err(&parse_quote! {
            struct Svc<A, B> {
                a: A,
                b: B,
            }
        });
        assert!(err.contains("cannot pick a field"), "{err}");

        let err = expand_err(&parse_quote! {
            struct Pair<A, B>(A, B);
        });
        assert!(err.contains("cannot pick a field"), "{err}");
    }

    #[test]
    fn unit_struct_is_rejected() {
        let err = expand_err(&parse_quote! {
            struct Svc;
        });
        assert!(err.contains("cannot pick a field"), "{err}");
    }

    #[test]
    fn two_markers_are_rejected() {
        let err = expand_err(&parse_quote! {
            struct Svc<A, B> {
                #[extensions_ref]
                a: A,
                #[extensions_ref]
                b: B,
            }
        });
        assert!(err.contains("only one field"), "{err}");
    }

    #[test]
    fn marker_with_arguments_is_rejected() {
        let err = expand_err(&parse_quote! {
            struct Svc<S> {
                #[extensions_ref(skip)]
                inner: S,
            }
        });
        assert!(err.contains("unexpected token"), "{err}");
    }

    #[test]
    fn enums_and_unions_are_rejected() {
        let err = expand_err(&parse_quote! {
            enum E<S> {
                A(#[extensions_ref] S),
            }
        });
        assert!(err.contains("only supports structs"), "{err}");

        let err = expand_err(&parse_quote! {
            union U {
                #[extensions_ref]
                a: u8,
            }
        });
        assert!(err.contains("only supports structs"), "{err}");
    }
}
