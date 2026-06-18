use proc_macro2::{Literal, Span, TokenStream};
use quote::quote;
use syn::{
    Data, DataEnum, DataStruct, DeriveInput, Fields, GenericArgument, Generics, Lifetime,
    LifetimeParam, PathArguments, Type,
};

use crate::utils::support_root_ts;

/// How a struct field is filled.
enum FieldShape<'a> {
    /// `Option<&'a T>`, `Option<Arc<T>>`, or `(_, usize)` variant
    Piece(FieldSpec<'a>),
    /// `Option<G>` where `G` is itself a `#[derive(FromExtensions)]` group
    Nested(&'a Type),
}

/// An extension piece and whether it's indexed
struct FieldSpec<'a> {
    kind: FieldKind,
    inner: &'a Type,
    indexed: bool,
}

enum FieldKind {
    /// `Option<&'a T>`, borrowed, gathered via `downcast_ref`.
    Ref,
    /// `Option<Arc<T>>`, owned Arc clone, gathered via `cloned_downcast`.
    Arc,
}

pub(crate) fn expand(input: DeriveInput) -> syn::Result<TokenStream> {
    let DeriveInput {
        ident,
        generics,
        data,
        ..
    } = input;

    if generics.type_params().next().is_some() {
        return Err(syn::Error::new_spanned(
            &generics,
            "`#[derive(FromExtensions)]` does not support type parameters",
        ));
    }
    if generics.const_params().next().is_some() {
        return Err(syn::Error::new_spanned(
            &generics,
            "`#[derive(FromExtensions)]` does not support const parameters",
        ));
    }
    let lifetimes: Vec<_> = generics.lifetimes().collect();
    if lifetimes.len() > 1 {
        return Err(syn::Error::new_spanned(
            &generics,
            "`#[derive(FromExtensions)]` supports at most one lifetime parameter",
        ));
    }
    let lifetime = lifetimes.first().map(|lt| lt.lifetime.clone());

    let root = support_root_ts("rama-core", None);

    match &data {
        Data::Struct(data) => expand_struct(&ident, &generics, lifetime.as_ref(), data, &root),
        Data::Enum(data) => expand_enum(&ident, &generics, lifetime.as_ref(), data, &root),
        Data::Union(_) => Err(syn::Error::new_spanned(
            &ident,
            "`#[derive(FromExtensions)]` can only be derived for structs and enums",
        )),
    }
}

/// `#[derive(FromExtensions)]` on a struct: gather one extension piece per named
/// field, plus any nested groups in a single run:
/// producing `fn from_extensions(&Extensions) -> Self`.
fn expand_struct(
    ident: &syn::Ident,
    generics: &Generics,
    lifetime: Option<&Lifetime>,
    data: &DataStruct,
    root: &TokenStream,
) -> syn::Result<TokenStream> {
    let Fields::Named(named) = &data.fields else {
        return Err(syn::Error::new_spanned(
            ident,
            "`#[derive(FromExtensions)]` only supports structs with named fields",
        ));
    };
    let fields = &named.named;
    if fields.is_empty() {
        return Err(syn::Error::new_spanned(
            ident,
            "`#[derive(FromExtensions)]` requires at least one field",
        ));
    }

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let (fn_generics, lt) = fn_lifetime(lifetime);

    // The shared buffers are filled and read by a running `__off` cursor, so each
    // field, whether a single piece (one slot) or a nested group (`TARGETS`
    // slots), advances the cursor by its own width. `__N` is the total width,
    // summed at compile time, nested widths are read from the group type via the
    // anonymous lifetime since `'a`/the method lifetime cannot appear in a const.
    let mut contribs = Vec::with_capacity(fields.len());
    let mut target_fills = Vec::with_capacity(fields.len());
    let mut field_lets = Vec::with_capacity(fields.len());
    let mut field_names = Vec::with_capacity(fields.len());

    for field in fields {
        let name = field
            .ident
            .as_ref()
            .expect("named field always has an ident");
        field_names.push(name);
        match classify_field(&field.ty)? {
            FieldShape::Piece(spec) => {
                let inner = spec.inner;
                let downcast = downcast_expr(&spec, root);
                let read = if spec.indexed {
                    quote!(__out[__off].and_then(|(__e, __rank)| #downcast.map(|__v| (__v, __rank))))
                } else {
                    quote!(__out[__off].and_then(|(__e, _)| #downcast))
                };
                contribs.push(quote!(1usize));
                target_fills.push(quote! {
                    __targets[__off] = ::core::any::TypeId::of::<#inner>();
                    __off += 1;
                });
                field_lets.push(quote! {
                    let #name = #read;
                    __off += 1;
                });
            }
            FieldShape::Nested(group) => {
                let anon = anon_lifetimes(group);
                let as_group = quote!(<#group as #root::extensions::FromExtensionsGroup<#lt>>);
                contribs
                    .push(quote!(<#anon as #root::extensions::FromExtensionsGroup<'_>>::TARGETS));
                target_fills.push(quote! {
                    #as_group::from_ext_targets(&mut __targets, __off);
                    __off += #as_group::TARGETS;
                });
                field_lets.push(quote! {
                    let #name = #as_group::from_ext_slots(&__out, __off);
                    __off += #as_group::TARGETS;
                });
            }
        }
    }

    Ok(quote! {
        impl #impl_generics #ident #ty_generics #where_clause {
            /// Gather these extension pieces from `ext` in a single pass.
            ///
            /// Generated by `#[derive(FromExtensions)]`. Each field uses the
            /// same lookup as `Extensions::get_ref` (newest-wins, walks wrappers
            /// and the parent chain), but the store is traversed only once, even
            /// for nested group fields, whose candidates are folded into
            /// the same pass. A field shaped `Option<(&'a T, usize)>` (or
            /// `Option<(Arc<T>, usize)>`) also captures the entry's traversal rank,
            /// `0` is the newest value seen, growing for older ones, so ranks
            /// order fields by recency.
            pub fn from_extensions #fn_generics (
                ext: & #lt #root::extensions::Extensions,
            ) -> Self {
                const __N: usize = #( #contribs )+*;
                let mut __targets = [::core::any::TypeId::of::<()>(); __N];
                let mut __off = 0usize;
                #( #target_fills )*
                let _ = __off;
                let mut __out: [
                    ::core::option::Option<(& #lt #root::extensions::TypeErasedExtension, usize)>; __N
                ] = [::core::option::Option::None; __N];
                ext.get_many_erased(&__targets, &mut __out);
                let mut __off = 0usize;
                #( #field_lets )*
                let _ = __off;
                Self { #( #field_names ),* }
            }
        }
    })
}

/// `#[derive(FromExtensions)]` on an enum: each variant names one candidate
/// extension type. Generates a [`FromExtensionsGroup`] impl (so the enum folds
/// into a parent struct's single pass) plus an inherent `fn
/// from_extensions(&Extensions) -> Option<Self>` returning the variant whose
/// value was inserted most recently (lowest traversal rank), newest-wins.
fn expand_enum(
    ident: &syn::Ident,
    generics: &Generics,
    lifetime: Option<&Lifetime>,
    data: &DataEnum,
    root: &TokenStream,
) -> syn::Result<TokenStream> {
    if data.variants.is_empty() {
        return Err(syn::Error::new_spanned(
            ident,
            "`#[derive(FromExtensions)]` requires at least one variant",
        ));
    }

    let mut target_writes = Vec::with_capacity(data.variants.len());
    let mut builders = Vec::with_capacity(data.variants.len());
    for (i, variant) in data.variants.iter().enumerate() {
        let Fields::Unnamed(unnamed) = &variant.fields else {
            return Err(syn::Error::new_spanned(
                variant,
                "every `#[derive(FromExtensions)]` enum variant must be a tuple variant \
                 holding exactly one `&'a T` or `Arc<T>`",
            ));
        };
        if unnamed.unnamed.len() != 1 {
            return Err(syn::Error::new_spanned(
                variant,
                "every `#[derive(FromExtensions)]` enum variant must hold exactly one value",
            ));
        }
        let vname = &variant.ident;
        let spec = classify_value(&unnamed.unnamed[0].ty)?;
        let inner = spec.inner;
        let idx = Literal::usize_unsuffixed(i);
        let downcast = downcast_expr(&spec, root);
        target_writes.push(quote! {
            __targets[__offset + #idx] = ::core::any::TypeId::of::<#inner>();
        });
        builders.push(if spec.indexed {
            quote!(__out[__offset + #idx].and_then(|(__e, __rank)| #downcast.map(|__v| (Self::#vname((__v, __rank)), __rank))))
        } else {
            quote!(__out[__offset + #idx].and_then(|(__e, __rank)| #downcast.map(|__v| (Self::#vname(__v), __rank))))
        });
    }

    let n = Literal::usize_unsuffixed(data.variants.len());
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let (fn_generics, lt) = fn_lifetime(lifetime);

    // Trait impl header: the group lifetime is the enum's own lifetime, or a
    // new one introduced on the impl if only `Arc`s are used
    let (group_impl_generics, group_lt, self_ty) = if let Some(lt) = lifetime {
        (quote!(<#lt>), quote!(#lt), quote!(#ident<#lt>))
    } else {
        let fresh = LifetimeParam::new(Lifetime::new("'__from_ext", Span::call_site()));
        (quote!(<#fresh>), quote!(#fresh), quote!(#ident))
    };

    Ok(quote! {
        impl #group_impl_generics #root::extensions::FromExtensionsGroup<#group_lt>
            for #self_ty #where_clause
        {
            const TARGETS: usize = #n;

            fn from_ext_targets(__targets: &mut [::core::any::TypeId], __offset: usize) {
                #( #target_writes )*
            }

            fn from_ext_slots(
                __out: &[::core::option::Option<(
                    & #group_lt #root::extensions::TypeErasedExtension, usize
                )>],
                __offset: usize,
            ) -> ::core::option::Option<Self> {
                let __candidates: [::core::option::Option<(Self, usize)>; #n] = [ #( #builders ),* ];
                // `min_by_key` keeps the first of equal keys, so on a rank tie
                // (only possible when two variants name the same type and thus
                // resolve to the same entry) the earlier-declared variant wins.
                ::core::iter::IntoIterator::into_iter(__candidates)
                    .flatten()
                    .min_by_key(|(_, __rank)| *__rank)
                    .map(|(__v, _)| __v)
            }
        }

        impl #impl_generics #ident #ty_generics #where_clause {
            /// Gather the candidate extension pieces from `ext` in a single pass
            /// and return the variant whose value was inserted most recently.
            ///
            /// Generated by `#[derive(FromExtensions)]`. Each variant names one
            /// candidate type, lookup uses the same rule as `Extensions::get_ref`
            /// (newest-wins, walks wrappers and the parent chain). When several
            /// candidates are present the one with the lowest traversal rank
            /// (newest) wins, returns `None` if none are present. If two variants
            /// name the same type they resolve to the same entry (equal rank), the
            /// tie is broken deterministically in favour of the earlier-declared
            /// variant.
            pub fn from_extensions #fn_generics (
                ext: & #lt #root::extensions::Extensions,
            ) -> ::core::option::Option<Self> {
                let mut __targets = [::core::any::TypeId::of::<()>(); #n];
                <Self as #root::extensions::FromExtensionsGroup<#lt>>::from_ext_targets(
                    &mut __targets, 0,
                );
                let mut __out: [
                    ::core::option::Option<(& #lt #root::extensions::TypeErasedExtension, usize)>; #n
                ] = [::core::option::Option::None; #n];
                ext.get_many_erased(&__targets, &mut __out);
                <Self as #root::extensions::FromExtensionsGroup<#lt>>::from_ext_slots(&__out, 0)
            }
        }
    })
}

/// The lifetime tying the borrowed slots to `ext`: reuse the type's lifetime if
/// it has one, otherwise introduce a fresh one on the method (a type with only
/// `Arc<T>` pieces needs no lifetime of its own).
fn fn_lifetime(lifetime: Option<&Lifetime>) -> (TokenStream, TokenStream) {
    if let Some(lt) = lifetime {
        (quote!(), quote!(#lt))
    } else {
        let fresh = LifetimeParam::new(Lifetime::new("'__from_ext", Span::call_site()));
        (quote!(<#fresh>), quote!(#fresh))
    }
}

/// Clone `ty` with every lifetime argument replaced by the anonymous `'_`, so it
/// can be named in a const context (where `'a`/method lifetimes are forbidden) to
/// read a nested group's `TARGETS`.
fn anon_lifetimes(ty: &Type) -> Type {
    let mut ty = ty.clone();
    anon_lifetimes_in(&mut ty);
    ty
}

fn anon_lifetimes_in(ty: &mut Type) {
    if let Type::Path(type_path) = ty {
        for segment in &mut type_path.path.segments {
            if let PathArguments::AngleBracketed(args) = &mut segment.arguments {
                for arg in &mut args.args {
                    match arg {
                        GenericArgument::Lifetime(lt) => {
                            *lt = Lifetime::new("'_", lt.apostrophe);
                        }
                        GenericArgument::Type(inner) => anon_lifetimes_in(inner),
                        _ => {}
                    }
                }
            }
        }
    }
}

/// Build the downcast expression for a classified piece, binding the slot's
/// erased entry as `__e`.
fn downcast_expr(spec: &FieldSpec<'_>, root: &TokenStream) -> TokenStream {
    let inner = spec.inner;
    let method = match spec.kind {
        FieldKind::Ref => quote!(downcast_ref),
        FieldKind::Arc => quote!(cloned_downcast),
    };
    quote!(#root::extensions::TypeErasedExtension::#method::<#inner>(__e))
}

/// Classify a struct field: strip the mandatory `Option<…>`, then decide whether
/// it is a gathered piece (`&'a T`, `Arc<T>`, or their `(_, usize)` indexed
/// forms) or a nested `FromExtensions` group (any other path, e.g. an any-of
/// enum) to delegate to.
fn classify_field(ty: &Type) -> syn::Result<FieldShape<'_>> {
    let inner = option_inner(ty).ok_or_else(|| unsupported_field(ty))?;
    if index_tuple(inner).is_some() || matches!(inner, Type::Reference(_)) || is_arc(inner) {
        return Ok(FieldShape::Piece(classify_value(inner)?));
    }
    if matches!(inner, Type::Path(_)) {
        return Ok(FieldShape::Nested(inner));
    }
    Err(unsupported_field(ty))
}

/// Whether `ty` is `Arc<…>` (matched by the last path segment, like the rest of
/// the classifier).
fn is_arc(ty: &Type) -> bool {
    matches!(ty, Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "Arc"))
}

/// Classify a value piece: `&'a T`, `Arc<T>`, or their `(value, usize)` indexed
/// tuple form. Returns the [`FieldKind`], the inner `T`, and whether the rank is
/// captured.
fn classify_value(ty: &Type) -> syn::Result<FieldSpec<'_>> {
    if let Some((value_ty, index_ty)) = index_tuple(ty) {
        if !is_usize(index_ty) {
            return Err(syn::Error::new_spanned(
                index_ty,
                "the second element of a `#[derive(FromExtensions)]` indexed piece must be `usize`",
            ));
        }
        let (kind, inner) = classify_inner(value_ty)?;
        return Ok(FieldSpec {
            kind,
            inner,
            indexed: true,
        });
    }
    let (kind, inner) = classify_inner(ty)?;
    Ok(FieldSpec {
        kind,
        inner,
        indexed: false,
    })
}

/// Classify `&'a T` (borrowed) or `Arc<T>` (owned Arc clone) and extract `T`.
fn classify_inner(ty: &Type) -> syn::Result<(FieldKind, &Type)> {
    match ty {
        Type::Reference(reference) if reference.mutability.is_some() => {
            Err(syn::Error::new_spanned(
                reference,
                "`#[derive(FromExtensions)]` can only hand out shared references; \
             use `&'a T`, not `&mut`",
            ))
        }
        Type::Reference(reference) => Ok((FieldKind::Ref, &reference.elem)),
        Type::Path(type_path) => {
            let segment = type_path
                .path
                .segments
                .last()
                .ok_or_else(|| unsupported_field(ty))?;
            if segment.ident != "Arc" {
                return Err(unsupported_field(ty));
            }
            let PathArguments::AngleBracketed(args) = &segment.arguments else {
                return Err(unsupported_field(ty));
            };
            if args.args.len() != 1 {
                return Err(syn::Error::new_spanned(
                    segment,
                    "`#[derive(FromExtensions)]` supports only `Arc<T>` (no custom allocator)",
                ));
            }
            let GenericArgument::Type(inner) = &args.args[0] else {
                return Err(unsupported_field(ty));
            };
            Ok((FieldKind::Arc, inner))
        }
        _ => Err(unsupported_field(ty)),
    }
}

fn unsupported_field(ty: &Type) -> syn::Error {
    syn::Error::new_spanned(
        ty,
        "every `#[derive(FromExtensions)]` piece must be `&'a T` / `Arc<T>` (struct fields \
         wrapped in `Option<…>`), optionally paired with the entry rank as `(_, usize)`",
    )
}

/// Extract `T` from `Option<T>`.
fn option_inner(ty: &Type) -> Option<&Type> {
    let Type::Path(type_path) = ty else {
        return None;
    };
    let segment = type_path.path.segments.last()?;
    if segment.ident != "Option" {
        return None;
    }
    let PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    let GenericArgument::Type(inner) = args.args.first()? else {
        return None;
    };
    Some(inner)
}

/// Match a 2-element tuple
fn index_tuple(ty: &Type) -> Option<(&Type, &Type)> {
    let Type::Tuple(tuple) = ty else {
        return None;
    };
    if tuple.elems.len() != 2 {
        return None;
    }
    Some((&tuple.elems[0], &tuple.elems[1]))
}

fn is_usize(ty: &Type) -> bool {
    matches!(ty, Type::Path(p) if p.path.is_ident("usize"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::{DeriveInput, parse_quote};

    fn expand_err(input: DeriveInput) -> String {
        expand(input)
            .expect_err("expected expansion to fail")
            .to_string()
    }

    fn expand_ok(input: DeriveInput) -> String {
        expand(input)
            .expect("expected expansion to succeed")
            .to_string()
    }

    #[test]
    fn rejects_type_parameters() {
        let e = expand_err(parse_quote! {
            struct Bad<T> { x: Option<T> }
        });
        assert!(e.contains("type parameters"), "{e}");
    }

    #[test]
    fn rejects_const_parameters() {
        let e = expand_err(parse_quote! {
            struct Bad<const N: usize> { x: Option<&'static u8> }
        });
        assert!(e.contains("const parameters"), "{e}");
    }

    #[test]
    fn rejects_multiple_lifetimes() {
        let e = expand_err(parse_quote! {
            struct Bad<'a, 'b> { x: Option<&'a u8>, y: Option<&'b u8> }
        });
        assert!(e.contains("at most one lifetime"), "{e}");
    }

    #[test]
    fn rejects_union() {
        let e = expand_err(parse_quote! {
            union Bad { x: u8 }
        });
        assert!(e.contains("structs and enums"), "{e}");
    }

    #[test]
    fn rejects_tuple_struct() {
        let e = expand_err(parse_quote! {
            struct Bad(u8);
        });
        assert!(e.contains("named fields"), "{e}");
    }

    #[test]
    fn rejects_empty_struct() {
        let e = expand_err(parse_quote! {
            struct Bad {}
        });
        assert!(e.contains("at least one field"), "{e}");
    }

    #[test]
    fn rejects_field_without_option() {
        let e = expand_err(parse_quote! {
            struct Bad<'a> { x: &'a u8 }
        });
        assert!(e.contains("piece must be"), "{e}");
    }

    #[test]
    fn rejects_mut_reference() {
        let e = expand_err(parse_quote! {
            struct Bad<'a> { x: Option<&'a mut u8> }
        });
        assert!(e.contains("shared references"), "{e}");
    }

    #[test]
    fn rejects_arc_with_allocator() {
        let e = expand_err(parse_quote! {
            struct Bad { x: Option<Arc<u8, MyAlloc>> }
        });
        assert!(e.contains("no custom allocator"), "{e}");
    }

    #[test]
    fn rejects_index_tuple_with_non_usize() {
        let e = expand_err(parse_quote! {
            struct Bad<'a> { x: Option<(&'a u8, u32)> }
        });
        assert!(e.contains("must be `usize`"), "{e}");
    }

    #[test]
    fn rejects_empty_enum() {
        let e = expand_err(parse_quote! {
            enum Bad {}
        });
        assert!(e.contains("at least one variant"), "{e}");
    }

    #[test]
    fn rejects_struct_variant() {
        let e = expand_err(parse_quote! {
            enum Bad<'a> { V { x: &'a u8 } }
        });
        assert!(e.contains("tuple variant"), "{e}");
    }

    #[test]
    fn rejects_unit_variant() {
        let e = expand_err(parse_quote! {
            enum Bad { V }
        });
        assert!(e.contains("tuple variant"), "{e}");
    }

    #[test]
    fn rejects_variant_with_two_fields() {
        let e = expand_err(parse_quote! {
            enum Bad<'a> { V(&'a u8, &'a u16) }
        });
        assert!(e.contains("exactly one value"), "{e}");
    }

    #[test]
    fn rejects_unsupported_struct_field_type() {
        let e = expand_err(parse_quote! {
            struct Bad { x: Option<[u8; 4]> }
        });
        assert!(e.contains("piece must be"), "{e}");
    }

    #[test]
    fn rejects_enum_variant_bare_value_type() {
        let e = expand_err(parse_quote! {
            enum Bad { V(u8) }
        });
        assert!(e.contains("piece must be"), "{e}");
    }

    #[test]
    fn rejects_enum_variant_array_value() {
        let e = expand_err(parse_quote! {
            enum Bad { V([u8; 2]) }
        });
        assert!(e.contains("piece must be"), "{e}");
    }

    #[test]
    fn struct_ref_arc_and_indexed_expand() {
        let out = expand_ok(parse_quote! {
            struct View<'a> {
                a: Option<&'a A>,
                b: Option<Arc<B>>,
                c: Option<(&'a C, usize)>,
            }
        });
        assert!(out.contains("fn from_extensions"), "{out}");
        assert!(out.contains("get_many_erased"), "{out}");
        assert!(out.contains("downcast_ref"), "{out}");
        assert!(out.contains("cloned_downcast"), "{out}");
    }

    #[test]
    fn all_arc_struct_needs_no_lifetime() {
        // No declared lifetime so we create one
        let out = expand_ok(parse_quote! {
            struct View { a: Option<Arc<A>> }
        });
        assert!(out.contains("'__from_ext"), "{out}");
    }

    #[test]
    fn enum_expands_group_impl_and_inherent() {
        let out = expand_ok(parse_quote! {
            enum Auth<'a> { A(&'a Server), B(&'a Verifier) }
        });
        assert!(out.contains("FromExtensionsGroup"), "{out}");
        assert!(out.contains("from_ext_targets"), "{out}");
        assert!(out.contains("from_ext_slots"), "{out}");
        assert!(out.contains("min_by_key"), "{out}");
        assert!(out.contains("fn from_extensions"), "{out}");
    }

    #[test]
    fn struct_nested_group_folds_into_single_pass() {
        let out = expand_ok(parse_quote! {
            struct Cfg<'a> {
                toggle: Option<&'a T>,
                either: Option<Either<'a>>,
            }
        });
        // the nested group is gathered through the trait (one shared pass),
        // not by calling its own `from_extensions`.
        assert!(out.contains("from_ext_targets"), "{out}");
        assert!(out.contains("from_ext_slots"), "{out}");
        assert!(out.contains("get_many_erased"), "{out}");
        // its width is read via the anonymous lifetime for the const buffer size.
        assert!(out.contains("'_"), "{out}");
    }
}
