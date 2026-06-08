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

impl HtmlTag<'_> {
    /// Returns `true` if this is an HTML5 [void element]: one that never has
    /// content or an end tag — `area`, `base`, `br`, `col`, `embed`, `hr`,
    /// `img`, `input`, `link`, `meta`, `source`, `track`, `wbr`.
    ///
    /// Note `param` is **not** void in the current spec (it is obsolete).
    ///
    /// [void element]: https://html.spec.whatwg.org/multipage/syntax.html#void-elements
    #[must_use]
    pub fn is_void(&self) -> bool {
        matches!(
            self,
            Self::Area
                | Self::Base
                | Self::Br
                | Self::Col
                | Self::Embed
                | Self::Hr
                | Self::Img
                | Self::Input
                | Self::Link
                | Self::Meta
                | Self::Source
                | Self::Track
                | Self::Wbr
        )
    }

    /// Returns `true` if this is a [raw text element] — `script` or `style`.
    /// Their content is tokenized verbatim: no markup, no character
    /// references, only the matching end tag closes them.
    ///
    /// This is the spec category, not rama's broader tokenizer raw-text set
    /// (which also covers legacy `xmp` / `iframe` / `noembed` / `noframes` /
    /// `noscript`).
    ///
    /// [raw text element]: https://html.spec.whatwg.org/multipage/syntax.html#raw-text-elements
    #[must_use]
    pub fn is_raw_text(&self) -> bool {
        matches!(self, Self::Script | Self::Style)
    }

    /// Returns `true` if this is an [escapable raw text element] — `textarea`
    /// or `title`. Like a raw text element, but character references are
    /// recognized in its content.
    ///
    /// [escapable raw text element]: https://html.spec.whatwg.org/multipage/syntax.html#escapable-raw-text-elements
    #[must_use]
    pub fn is_escapable_raw_text(&self) -> bool {
        matches!(self, Self::Textarea | Self::Title)
    }

    /// Returns `true` if this is [phrasing content] — the spec category for
    /// the text-level ("inline") elements: the runs of text in a document
    /// and the elements that mark them up (`a`, `span`, `em`, `strong`,
    /// `img`, `br`, `input`, `script`, …).
    ///
    /// Membership is the current WHATWG list of elements that are
    /// *inherently* phrasing content. Elements that qualify only in a
    /// specific context (`area` within a `map`, `link` / `meta` carrying an
    /// `itemprop`) are excluded — this is a name-only predicate. Obsolete
    /// presentational tags (`big`, `font`, `tt`, `strike`, `nobr`) are
    /// excluded too; they are not in the modern content model.
    ///
    /// [phrasing content]: https://html.spec.whatwg.org/multipage/dom.html#phrasing-content-2
    #[must_use]
    pub fn is_phrasing_content(&self) -> bool {
        matches!(
            self,
            Self::A
                | Self::Abbr
                | Self::Audio
                | Self::B
                | Self::Bdi
                | Self::Bdo
                | Self::Br
                | Self::Button
                | Self::Canvas
                | Self::Cite
                | Self::Code
                | Self::Data
                | Self::Datalist
                | Self::Del
                | Self::Dfn
                | Self::Em
                | Self::Embed
                | Self::I
                | Self::Iframe
                | Self::Img
                | Self::Input
                | Self::Ins
                | Self::Kbd
                | Self::Label
                | Self::Map
                | Self::Mark
                | Self::Math
                | Self::Meter
                | Self::Noscript
                | Self::Object
                | Self::Output
                | Self::Picture
                | Self::Progress
                | Self::Q
                | Self::Ruby
                | Self::S
                | Self::Samp
                | Self::Script
                | Self::Select
                | Self::Small
                | Self::Span
                | Self::Strong
                | Self::Sub
                | Self::Sup
                | Self::Svg
                | Self::Template
                | Self::Textarea
                | Self::Time
                | Self::U
                | Self::Var
                | Self::Video
                | Self::Wbr
        )
    }
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

    #[test]
    fn is_void_matches_the_spec_set() {
        for tag in [
            HtmlTag::Area,
            HtmlTag::Base,
            HtmlTag::Br,
            HtmlTag::Col,
            HtmlTag::Embed,
            HtmlTag::Hr,
            HtmlTag::Img,
            HtmlTag::Input,
            HtmlTag::Link,
            HtmlTag::Meta,
            HtmlTag::Source,
            HtmlTag::Track,
            HtmlTag::Wbr,
        ] {
            assert!(tag.is_void(), "{tag:?} should be void");
        }
        for tag in [
            HtmlTag::Div,
            HtmlTag::P,
            HtmlTag::Span,
            HtmlTag::Script,
            // Obsolete — not a void element in the current spec.
            HtmlTag::Param,
            HtmlTag::Other(b"my-card"),
        ] {
            assert!(!tag.is_void(), "{tag:?} should not be void");
        }
    }

    #[test]
    fn raw_text_is_script_and_style_only() {
        assert!(HtmlTag::Script.is_raw_text());
        assert!(HtmlTag::Style.is_raw_text());
        // Legacy tokenizer raw-text elements are *not* spec raw text elements.
        for tag in [
            HtmlTag::Xmp,
            HtmlTag::Iframe,
            HtmlTag::Noembed,
            HtmlTag::Noframes,
            HtmlTag::Noscript,
            HtmlTag::Textarea,
            HtmlTag::Title,
            HtmlTag::Div,
            HtmlTag::Other(b"my-card"),
        ] {
            assert!(!tag.is_raw_text(), "{tag:?} should not be raw text");
        }
    }

    #[test]
    fn escapable_raw_text_is_textarea_and_title_only() {
        assert!(HtmlTag::Textarea.is_escapable_raw_text());
        assert!(HtmlTag::Title.is_escapable_raw_text());
        for tag in [
            HtmlTag::Script,
            HtmlTag::Style,
            HtmlTag::Div,
            HtmlTag::Other(b"my-card"),
        ] {
            assert!(
                !tag.is_escapable_raw_text(),
                "{tag:?} should not be escapable raw text"
            );
        }
    }

    #[test]
    fn phrasing_content_covers_inline_elements() {
        // Representative text-level / replaced-inline / embedded elements.
        for tag in [
            HtmlTag::A,
            HtmlTag::Span,
            HtmlTag::Em,
            HtmlTag::Strong,
            HtmlTag::Img,
            HtmlTag::Br,
            HtmlTag::Wbr,
            HtmlTag::Input,
            HtmlTag::Label,
            HtmlTag::Script,
            HtmlTag::Textarea,
            HtmlTag::Svg,
            HtmlTag::Math,
            HtmlTag::Video,
        ] {
            assert!(tag.is_phrasing_content(), "{tag:?} should be phrasing");
        }
    }

    #[test]
    fn phrasing_content_excludes_flow_only_and_edge_cases() {
        for tag in [
            // Flow / block elements.
            HtmlTag::Div,
            HtmlTag::P,
            HtmlTag::Section,
            HtmlTag::Article,
            HtmlTag::Ul,
            HtmlTag::Li,
            HtmlTag::Table,
            HtmlTag::H1,
            HtmlTag::Blockquote,
            HtmlTag::Body,
            // Conditionally-phrasing — excluded from this name-only predicate.
            HtmlTag::Area,
            HtmlTag::Link,
            HtmlTag::Meta,
            // Obsolete presentational — not in the modern content model.
            HtmlTag::Big,
            HtmlTag::Font,
            HtmlTag::Tt,
            HtmlTag::Strike,
            HtmlTag::Nobr,
            HtmlTag::Other(b"my-card"),
        ] {
            assert!(!tag.is_phrasing_content(), "{tag:?} should not be phrasing");
        }
    }
}
