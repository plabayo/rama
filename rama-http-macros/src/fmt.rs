use proc_macro2::{Span, TokenStream};
use quote::{ToTokens, format_ident, quote};
use syn::{Block, Expr, ExprBlock, ExprGroup, ExprLit, Ident, Lit, Token, parse_quote};

use crate::ast::{Attr, AttrValue, Element, Node};

/// Minimal copy of vy's escape-into helper used at compile time on string
/// literals. Kept private; the runtime equivalent lives in
/// `rama_http::html::escape`.
fn escape_into(buf: &mut String, input: &str) {
    for ch in input.chars() {
        match ch {
            '&' => buf.push_str("&amp;"),
            '<' => buf.push_str("&lt;"),
            '>' => buf.push_str("&gt;"),
            '"' => buf.push_str("&quot;"),
            _ => buf.push(ch),
        }
    }
}

pub(crate) struct Serializer<'s> {
    buf: &'s mut String,
    values: Vec<(usize, Expr)>,
    imports: Vec<Ident>,
    /// Path under which `rama-http`'s `html` module lives (e.g. `::rama::http`
    /// or `::rama_http`). Used to emit fully-qualified references to
    /// `PreEscaped`, the `Either*` variants, etc.
    root: TokenStream,
}

impl<'s> Serializer<'s> {
    pub(crate) fn new(buf: &'s mut String, root: TokenStream) -> Self {
        Self {
            buf,
            values: Vec::new(),
            imports: Vec::new(),
            root,
        }
    }

    pub(crate) fn write_expr(&mut self, mut expr: Expr) {
        match expr {
            Expr::Group(ExprGroup { attrs, expr, .. }) if attrs.is_empty() => {
                self.write_expr(*expr);
            }
            Expr::If(_) => {
                let mut count = 1;
                let mut current = Some(&expr);
                while let Some(Expr::If(node)) = current {
                    current = node.else_branch.as_ref().map(|(_, expr)| &**expr);
                    count += 1;
                }

                let either_name = if count > 2 {
                    format_ident!("Either{count}")
                } else {
                    format_ident!("Either")
                };

                let root = &self.root;
                transform_branches(root, &either_name, 0, &mut expr);

                self.values.push((self.buf.len(), expr));
            }
            Expr::Lit(ExprLit {
                attrs,
                lit: Lit::Str(lit_str),
            }) if attrs.is_empty() => {
                escape_into(self.buf, &lit_str.value());
            }
            Expr::Lit(ExprLit {
                attrs,
                lit: Lit::Char(lit_char),
            }) if attrs.is_empty() => {
                let mut tmp = [0u8; 4];
                escape_into(self.buf, lit_char.value().encode_utf8(&mut tmp));
            }
            Expr::Lit(ExprLit {
                attrs,
                lit: Lit::Int(lit_int),
            }) if attrs.is_empty() => {
                escape_into(self.buf, lit_int.base10_digits());
            }
            Expr::Lit(ExprLit {
                attrs,
                lit: Lit::Float(lit_float),
            }) if attrs.is_empty() => {
                escape_into(self.buf, lit_float.base10_digits());
            }
            Expr::Lit(ExprLit {
                attrs,
                lit: Lit::Bool(lit_bool),
            }) if attrs.is_empty() => {
                escape_into(self.buf, if lit_bool.value { "true" } else { "false" });
            }
            _ => {
                self.values.push((self.buf.len(), expr));
            }
        }
    }

    pub(crate) fn write_attr(&mut self, attr: Attr) {
        let name = attr.name.to_string();
        if attr.is_optional() {
            let sep_name = String::from(' ') + &name;
            let sep_name_eq = sep_name.clone() + "=\"";
            let root = &self.root;

            match attr.value {
                AttrValue::Expr(value) => self.write_expr(parse_quote! {
                    ::core::option::Option::map(
                        #value,
                        |val| (
                            #root::html::PreEscaped(#sep_name_eq),
                            val,
                            #root::html::PreEscaped('"'),
                        )
                    )
                }),
                AttrValue::Bool(value) => self.write_expr(parse_quote! {
                    <bool>::then_some(#value, #root::html::PreEscaped(#sep_name))
                }),
            }
        } else {
            self.buf.push(' ');
            self.buf.push_str(&name);
            self.buf.push('=');
            self.buf.push('"');
            self.write_expr(attr.value.into());
            self.buf.push('"');
        }
    }

    pub(crate) fn write_element(&mut self, Element { head, body }: Element) {
        let name = head.name().to_owned();
        let void = head.is_void();
        if let Some(ident) = head.import_ident() {
            self.imports.push(ident);
        }
        self.buf.push('<');
        self.buf.push_str(&name);
        for attr in body.attrs {
            self.write_attr(attr);
        }
        self.buf.push('>');
        if !void {
            for node in body.nodes {
                self.write_node(node);
            }
            self.buf.push('<');
            self.buf.push('/');
            self.buf.push_str(&name);
            self.buf.push('>');
        }
    }

    pub(crate) fn write_node(&mut self, node: Node) {
        match node {
            Node::Element(el) => self.write_element(el),
            Node::Expr(expr) => self.write_expr(expr),
        }
    }

    /// Emit a const block that references each of the per-element macros we
    /// touched. This forces a compile-time error if e.g. `body!` is used
    /// without being in scope, even though the rest of the expansion does
    /// not depend on the macro identifier directly.
    pub(crate) fn as_imports(&self) -> TokenStream {
        let imports = &self.imports;
        quote! {
            const _: () = {
                #(_ = #imports!(__rama_html_import_marker);)*
            }
        }
    }

    pub(crate) fn into_parts(self) -> Vec<Part<'s>> {
        let mut parts = Vec::new();
        let mut cursor = 0;

        for (i, val) in self.values {
            assert!(i >= cursor);
            let slice = &self.buf.as_str()[cursor..i];
            if !slice.is_empty() {
                parts.push(Part::Str(slice));
            }
            parts.push(Part::Expr(val));
            cursor = i;
        }

        let slice = &self.buf.as_str()[cursor..];
        if !slice.is_empty() {
            parts.push(Part::Str(slice));
        }

        parts
    }
}

pub(crate) enum Part<'s> {
    Str(&'s str),
    Expr(Expr),
}

fn wrap_branch(root: &TokenStream, either: &Ident, count: u8, tokens: impl ToTokens) -> Block {
    let variant_letter = match count {
        1..=9 => (b'A' + count - 1) as char,
        _ => panic!("exceeded number of supported branches"),
    };
    let variant = format_ident!("{}", variant_letter);

    parse_quote!({
        #root::html::#either::#variant(#tokens)
    })
}

fn transform_branches(root: &TokenStream, either: &Ident, mut count: u8, expr: &mut Expr) {
    count += 1;
    match expr {
        Expr::Block(ExprBlock { block, .. }) => {
            *block = wrap_branch(root, either, count, &block);
        }
        Expr::If(expr_if) => {
            expr_if.then_branch = wrap_branch(root, either, count, &expr_if.then_branch);

            if let Some((_, else_branch)) = &mut expr_if.else_branch {
                transform_branches(root, either, count, else_branch);
            } else {
                let unit: Expr = parse_quote!(());
                expr_if.else_branch = Some((
                    Token![else](Span::call_site()),
                    Box::new(Expr::Block(ExprBlock {
                        attrs: vec![],
                        label: None,
                        block: wrap_branch(root, either, count + 1, unit),
                    })),
                ))
            }
        }
        _ => {}
    }
}
