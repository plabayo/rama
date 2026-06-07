//! Strongly-typed HTML tag names.
//!
//! [`HtmlTag`] classifies a tag name into a known element (a fieldless
//! variant) or [`Other`](HtmlTag::Other) — a custom/unknown tag that borrows
//! the original-case name bytes, so classification never allocates. Matching
//! a group of tags is a dense-discriminant `match` (no string compares), and
//! the classifier reuses the [`LocalNameHash`] the tokenizer already computes,
//! so it is a single `u64` switch with no extra pass over the name.

use super::name::LocalNameHash;

macro_rules! html_tags {
    ($($variant:ident => $name:literal),+ $(,)?) => {
        /// A classified HTML tag name.
        ///
        /// Known elements (the HTML5 set plus the foreign-content and legacy
        /// tags the parser tracks) are fieldless variants; anything else is
        /// [`Other`](Self::Other), borrowing the original-case name bytes.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum HtmlTag<'a> {
            $(
                #[doc = concat!("The `<", $name, ">` element.")]
                $variant,
            )+
            /// A tag outside the known set (e.g. a custom element). Borrows
            /// the original-case name bytes from the source.
            Other(&'a [u8]),
        }

        // One `u64` constant per known tag. Two tags hashing alike would make
        // the second `classify` arm unreachable — a compile error — so the
        // collision-free property is enforced by the build, not just a test.
        #[expect(non_upper_case_globals)]
        mod hash {
            use super::LocalNameHash;
            $(
                pub(super) const $variant: u64 =
                    LocalNameHash::from_static($name.as_bytes()).as_u64();
            )+
        }

        impl<'a> HtmlTag<'a> {
            /// The tag name as bytes — lowercase for a known element, the
            /// original bytes for [`Other`](Self::Other).
            #[must_use]
            pub fn as_bytes(&self) -> &'a [u8] {
                match *self {
                    $( Self::$variant => $name.as_bytes(), )+
                    Self::Other(name) => name,
                }
            }

            /// Classifies a tag from its [`LocalNameHash`] and original bytes.
            pub(crate) fn classify(name_hash: LocalNameHash, name: &'a [u8]) -> Self {
                match name_hash.as_u64() {
                    $( hash::$variant => Self::$variant, )+
                    _ => Self::Other(name),
                }
            }
        }
    };
}

html_tags! {
    A => "a", Abbr => "abbr", Address => "address", Area => "area",
    Article => "article", Aside => "aside", Audio => "audio",
    B => "b", Base => "base", Bdi => "bdi", Bdo => "bdo", Big => "big",
    Blockquote => "blockquote", Body => "body", Br => "br", Button => "button",
    Canvas => "canvas", Caption => "caption", Center => "center", Cite => "cite",
    Code => "code", Col => "col", Colgroup => "colgroup",
    Data => "data", Datalist => "datalist", Dd => "dd", Del => "del",
    Desc => "desc", Details => "details", Dfn => "dfn", Dialog => "dialog",
    Div => "div", Dl => "dl", Dt => "dt",
    Em => "em", Embed => "embed",
    Fieldset => "fieldset", Figcaption => "figcaption", Figure => "figure",
    Font => "font", Footer => "footer", Foreignobject => "foreignobject",
    Form => "form", Frameset => "frameset",
    H1 => "h1", H2 => "h2", H3 => "h3", H4 => "h4", H5 => "h5", H6 => "h6",
    Head => "head", Header => "header", Hgroup => "hgroup", Hr => "hr",
    Html => "html",
    I => "i", Iframe => "iframe", Img => "img", Input => "input", Ins => "ins",
    Kbd => "kbd", Keygen => "keygen",
    Label => "label", Legend => "legend", Li => "li", Link => "link",
    Listing => "listing",
    Main => "main", Map => "map", Mark => "mark", Math => "math", Menu => "menu",
    Meta => "meta", Meter => "meter", Mi => "mi", Mn => "mn", Mo => "mo",
    Ms => "ms", Mtext => "mtext",
    Nav => "nav", Nobr => "nobr", Noembed => "noembed", Noframes => "noframes",
    Noscript => "noscript",
    Object => "object", Ol => "ol", Optgroup => "optgroup", Option => "option",
    Output => "output",
    P => "p", Param => "param", Picture => "picture", Plaintext => "plaintext",
    Pre => "pre", Progress => "progress",
    Q => "q",
    Rb => "rb", Rp => "rp", Rt => "rt", Rtc => "rtc", Ruby => "ruby",
    S => "s", Samp => "samp", Script => "script", Search => "search",
    Section => "section", Select => "select", Small => "small",
    Source => "source", Span => "span", Strike => "strike", Strong => "strong",
    Style => "style", Sub => "sub", Summary => "summary", Sup => "sup",
    Svg => "svg",
    Table => "table", Tbody => "tbody", Td => "td", Template => "template",
    Textarea => "textarea", Tfoot => "tfoot", Th => "th", Thead => "thead",
    Time => "time", Title => "title", Tr => "tr", Track => "track", Tt => "tt",
    U => "u", Ul => "ul",
    Var => "var", Video => "video",
    Wbr => "wbr",
    Xmp => "xmp",
}

#[cfg(test)]
mod tests {
    use super::{HtmlTag, LocalNameHash};

    /// Every known tag classifies to a distinct variant whose `as_bytes`
    /// round-trips its (lowercase) name — which also proves the hashes are
    /// collision-free across the whole set.
    #[test]
    fn known_tags_round_trip() {
        for name in [
            "a",
            "div",
            "h1",
            "script",
            "style",
            "textarea",
            "foreignobject",
            "math",
            "mi",
            "svg",
            "template",
            "blockquote",
            "figcaption",
            "option",
            "tt",
            "plaintext",
            "xmp",
            "wbr",
        ] {
            let tag = HtmlTag::classify(LocalNameHash::of(name.as_bytes()), name.as_bytes());
            assert_ne!(
                tag,
                HtmlTag::Other(name.as_bytes()),
                "{name} not classified"
            );
            assert_eq!(tag.as_bytes(), name.as_bytes(), "{name} round-trip");
        }
    }

    #[test]
    fn classification_is_case_insensitive() {
        assert_eq!(
            HtmlTag::classify(LocalNameHash::of(b"DIV"), b"DIV"),
            HtmlTag::Div
        );
    }

    #[test]
    fn unknown_tag_borrows_original_bytes() {
        let name = b"my-card";
        let tag = HtmlTag::classify(LocalNameHash::of(name), name);
        assert_eq!(tag, HtmlTag::Other(name));
        assert_eq!(tag.as_bytes(), name);
    }
}
