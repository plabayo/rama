#![allow(clippy::to_string_trait_impl)]

use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::{
    Error, Expr, ExprMacro, Ident, Lit, LitStr, Macro, Path, Result, Token,
    ext::IdentExt,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
};

use crate::known::{is_known_tag, is_void_tag};

/// A single ident `foo`, or a string literal `"bar"`.
pub(crate) enum AttrName {
    Ident(Ident),
    LitStr(LitStr),
}

impl Parse for AttrName {
    fn parse(input: ParseStream) -> Result<Self> {
        let lookahead = input.lookahead1();
        if lookahead.peek(Ident) {
            Ok(Self::Ident(input.parse()?))
        } else if lookahead.peek(LitStr) {
            Ok(Self::LitStr(input.parse()?))
        } else {
            Err(lookahead.error())
        }
    }
}

impl ToTokens for AttrName {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Self::Ident(ident) => ident.to_tokens(tokens),
            Self::LitStr(lit_str) => lit_str.to_tokens(tokens),
        }
    }
}

impl ToString for AttrName {
    fn to_string(&self) -> String {
        match self {
            // `unraw` strips the `r#` prefix from raw identifiers so that
            // e.g. `r#type = "x"` serializes as `type="x"` (the only
            // reasonable thing — `type` is a Rust keyword but a perfectly
            // legal HTML attribute name).
            Self::Ident(ident) => ident.unraw().to_string(),
            Self::LitStr(lit_str) => lit_str.value(),
        }
    }
}

pub(crate) enum AttrValue {
    Expr(Expr),
    Bool(bool),
}

impl Parse for AttrValue {
    fn parse(input: ParseStream) -> Result<Self> {
        if let Ok(Lit::Bool(b)) = input.fork().parse::<Lit>() {
            input.parse::<Lit>()?;
            return Ok(Self::Bool(b.value));
        }
        Ok(Self::Expr(input.parse()?))
    }
}

impl From<AttrValue> for Expr {
    fn from(value: AttrValue) -> Self {
        match value {
            AttrValue::Expr(expr) => expr,
            AttrValue::Bool(b) => Self::Lit(syn::ExprLit {
                attrs: Vec::new(),
                lit: Lit::Bool(syn::LitBool::new(b, proc_macro2::Span::call_site())),
            }),
        }
    }
}

impl ToTokens for AttrValue {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Self::Expr(expr) => expr.to_tokens(tokens),
            Self::Bool(b) => {
                let lit = Lit::Bool(syn::LitBool::new(*b, proc_macro2::Span::call_site()));
                lit.to_tokens(tokens);
            }
        }
    }
}

pub(crate) struct Attr {
    pub name: AttrName,
    pub question_token: Option<Token![?]>,
    pub eq_token: Token![=],
    pub value: AttrValue,
}

impl Attr {
    pub(crate) const fn is_optional(&self) -> bool {
        self.question_token.is_some()
    }
}

impl Parse for Attr {
    fn parse(input: ParseStream) -> Result<Self> {
        Ok(Self {
            name: input.parse()?,
            question_token: input.parse()?,
            eq_token: input.parse()?,
            value: input.parse()?,
        })
    }
}

impl ToTokens for Attr {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.name.to_tokens(tokens);
        self.eq_token.to_tokens(tokens);
        self.value.to_tokens(tokens);
    }
}

pub(crate) struct ElementBody {
    pub attrs: Vec<Attr>,
    pub nodes: Vec<Node>,
}

impl Parse for ElementBody {
    fn parse(input: ParseStream) -> Result<Self> {
        let mut parts = Punctuated::<AttrOrNode, Token![,]>::parse_terminated(input)?
            .into_iter()
            .peekable();

        let mut attrs = Vec::new();
        let mut nodes = Vec::new();

        while let Some(AttrOrNode::Attr(_)) = parts.peek() {
            let AttrOrNode::Attr(attr) = parts.next().unwrap() else {
                unreachable!();
            };
            attrs.push(attr);
        }

        for part in parts {
            match part {
                AttrOrNode::Attr(attr) => {
                    return Err(Error::new_spanned(
                        attr,
                        "attributes must be at the beginning",
                    ));
                }
                AttrOrNode::Node(node) => nodes.push(node),
            };
        }

        Ok(Self { attrs, nodes })
    }
}

impl ToTokens for ElementBody {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        for attr in &self.attrs {
            attr.to_tokens(tokens);
        }
        for node in &self.nodes {
            node.to_tokens(tokens);
        }
    }
}

/// The "head" of an element — i.e., its tag name.
///
/// `Known` elements are HTML5 elements declared in [`crate::known`]; they
/// are typo-checked at macro time and we know whether they are void.
///
/// `Custom` elements are introduced via the `custom!` proc-macro: their
/// tag name is a runtime string and (currently) they are always treated as
/// non-void containers.
pub(crate) enum ElementHead {
    Known {
        ident: Ident,
        name: String,
        void: bool,
    },
    Custom {
        tag: String,
    },
}

impl ElementHead {
    pub(crate) fn known(ident: Ident) -> Result<Self> {
        let name = ident.to_string();
        if !is_known_tag(&name) {
            return Err(Error::new_spanned(
                ident,
                format!(
                    "unknown HTML tag `{name}`; use the `custom!` macro \
                     to render arbitrary tag names (e.g. web components)"
                ),
            ));
        }
        let void = is_void_tag(&name);
        Ok(Self::Known { ident, name, void })
    }

    pub(crate) fn custom(tag: String) -> Self {
        Self::Custom { tag }
    }

    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Known { name, .. } => name,
            Self::Custom { tag } => tag,
        }
    }

    pub(crate) const fn is_void(&self) -> bool {
        match self {
            Self::Known { void, .. } => *void,
            Self::Custom { .. } => false,
        }
    }

    /// The Ident to push onto the import-marker list for hygiene checks.
    /// Custom elements skip this — they have no tag-named macro to import.
    pub(crate) fn import_ident(&self) -> Option<Ident> {
        match self {
            Self::Known { ident, .. } => Some(ident.clone()),
            Self::Custom { .. } => None,
        }
    }
}

pub(crate) struct Element {
    pub head: ElementHead,
    pub body: ElementBody,
}

impl Element {
    pub(crate) fn new(head: ElementHead, body: ElementBody) -> Result<Self> {
        if head.is_void() && !body.nodes.is_empty() {
            return Err(Error::new_spanned(
                body.nodes.first().unwrap(),
                "void tags cannot contain content",
            ));
        }
        Ok(Self { head, body })
    }

    /// Try to interpret a macro invocation as a known HTML element call —
    /// e.g. when `div!(...)` appears as a child of `body!(...)`. Custom
    /// (`custom!`) invocations cannot be reduced this way at parse time;
    /// they fall through to the generic-expression path (which is fine —
    /// the resulting [`crate::HtmlBuf`] still implements `IntoHtml`).
    pub(crate) fn from_known_macro(
        Macro {
            path: Path { mut segments, .. },
            tokens,
            ..
        }: Macro,
    ) -> Result<Self> {
        let ident = segments.pop().unwrap().into_value().ident;
        let head = ElementHead::known(ident)?;
        let body = syn::parse2(tokens)?;
        Self::new(head, body)
    }
}

impl ToTokens for Element {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        // Only used for diagnostics / error spans; emit something reasonable.
        match &self.head {
            ElementHead::Known { ident, .. } => ident.to_tokens(tokens),
            ElementHead::Custom { tag } => {
                LitStr::new(tag, proc_macro2::Span::call_site()).to_tokens(tokens);
            }
        }
        self.body.to_tokens(tokens);
    }
}

pub(crate) enum Node {
    Element(Element),
    Expr(Expr),
}

impl Parse for Node {
    fn parse(input: ParseStream) -> Result<Self> {
        let expr = input.parse()?;
        if let Expr::Macro(ExprMacro { mac, .. }) = &expr
            && let Ok(el) = Element::from_known_macro(mac.clone())
        {
            return Ok(Self::Element(el));
        }

        Ok(Self::Expr(expr))
    }
}

impl ToTokens for Node {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Self::Element(element) => element.to_tokens(tokens),
            Self::Expr(expr) => expr.to_tokens(tokens),
        }
    }
}

enum AttrOrNode {
    Attr(Attr),
    Node(Node),
}

impl Parse for AttrOrNode {
    fn parse(input: ParseStream) -> Result<Self> {
        if (input.peek(Ident) || input.peek(LitStr))
            && (input.peek2(Token![=]) || (input.peek2(Token![?]) && input.peek3(Token![=])))
        {
            Ok(Self::Attr(input.parse()?))
        } else {
            Ok(Self::Node(input.parse()?))
        }
    }
}
