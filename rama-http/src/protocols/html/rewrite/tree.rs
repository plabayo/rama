//! The stack of open elements, kept the way browsers build it.
//!
//! A streaming rewrite needs three answers without building a DOM: which
//! elements are the ancestors of the tag being opened, which open elements an
//! end tag (or an implied end) closes, and how the tokenizer must read what
//! follows a start tag (raw text, CDATA). Browsers answer all three with the
//! WHATWG tree-construction rules (scopes, special elements, implied
//! elements, table and foreign-content handling); this module mirrors the
//! part of those rules that moves the stack, see [`ScopeMode::Browser`] for
//! what it deliberately leaves out.
//!
//! Stack maintenance costs O(1) amortised work per token, whatever the
//! nesting: each frame caches the index of the nearest frame below it for
//! every boundary kind (scopes, special elements, insertion-mode owners), and
//! every name links to its topmost open frame, so no rule walks the stack.
//! The only loops pop frames, and each pop is paid for by the push that
//! created the frame.

#[cfg(test)]
use std::cell::Cell;
use std::hash::{Hash, Hasher};
use std::mem;

use ahash::{HashMap, RandomState};
use rama_utils::macros::paste;

use crate::protocols::html::tokenizer::{
    EndTag, LocalNameHash, StartTag, TextMode, annotation_xml_is_html, attribute_value_is,
};

/// How the rewriter decides where elements end in markup that leaves end
/// tags out, misnests them, or adds stray ones.
///
/// The rewriter never rejects or stalls on such input; this only chooses whose
/// view of the document it follows. It is fixed once input has been written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ScopeMode {
    /// Parse the input as a full document with the WHATWG tree-construction
    /// rules established browsers apply: implied ends (`<li>`, `<p>`, table
    /// parts, `<option>`, ruby, headings, buttons) and end tags only reach
    /// elements in scope, `</x>` never crosses a special element, tables,
    /// templates and SVG/MathML integration points shield their contents,
    /// `</body>` and `</html>` leave everything open (their end-anchored edits
    /// still land before the tag), the self-closing flag is honoured only
    /// where browsers honour it (void and foreign elements), and raw-text
    /// bodies (`<style>`, `<textarea>`, …) and CDATA sections are recognised
    /// exactly where browsers recognise them.
    ///
    /// Elements browsers create without a tag (`html`, `head`, `body`,
    /// `tbody`, `tr`, `colgroup`) take part in selector ancestry and sibling
    /// positions, though only a tag can be matched: a late `<html>` or
    /// `<body>`, or a `<head>` for the head browsers created on their own, is
    /// matched as that element. Tags browsers drop (a `<tr>` outside a table,
    /// a second `<head>`, …) match nothing, so markup meant to be inserted
    /// into a table or another element is better rewritten with
    /// [`NearestMatch`](Self::NearestMatch).
    ///
    /// A streaming rewriter cannot restructure what it already emitted. This
    /// is not a full browser DOM or a sanitizer. In particular:
    ///
    /// * formatting elements (`a`, `b`, `i`, …) are not split or implicitly
    ///   closed by another formatting start tag. Their end tags close a
    ///   matching frame only when no special element needs restructuring;
    ///   reconstructed copies of formatting elements are not tracked, so a
    ///   `remove` does not reach content browsers move into such a copy;
    /// * a `</form>` that browsers apply to a form with still-open children
    ///   keeps the form open until its parent closes;
    /// * content browsers move out in front of a table (foster parenting)
    ///   stays part of the table for `remove` and `set_inner_content`: more
    ///   is removed, never less (selectors still see its real parent);
    /// * a tag matched as an element that is already open (a late `<html>` or
    ///   `<body>`) applies its edits from where it appears: content streamed
    ///   before it is not retracted, and its attributes reach selector
    ///   ancestry of later elements only;
    /// * frameset documents, iframe `srcdoc` quirks and scripting-disabled
    ///   `<noscript>` parsing are not modelled;
    /// * where established browsers disagree, the Chromium and WebKit
    ///   behaviour is followed: `<![CDATA[` in an SVG/MathML integration point
    ///   is a bogus comment, a `<form>` in a table inside a `<template>` is
    ///   kept, an empty doctype system identifier counts as missing, and
    ///   `search` and `dialog` do not stop end-tag and list-item walks. Inside
    ///   `<select>` the current (relaxed) select parsing of Chromium and Gecko
    ///   is followed, not the legacy one some WebKit releases still use.
    #[default]
    Browser,
    /// Close the nearest open element with a matching name, ignoring scope
    /// boundaries: the behaviour of simpler streaming rewriters, which also
    /// treats every tag as an element where it appears (fragments included).
    /// A hostile document can use it to end an element early, so prefer
    /// [`Browser`](Self::Browser) for markup you do not control.
    NearestMatch,
}

macro_rules! known_tags {
    ($($variant:ident = $name:literal,)*) => {
        paste! {
            /// Element names with dedicated tree-construction rules.
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub(super) enum Tag {
                Other,
                $($variant,)*
            }

            const TAG_COUNT: usize = [$(stringify!($variant)),*].len() + 1;

            $(const [<TAG_ $variant:snake:upper>]: LocalNameHash = LocalNameHash::from_static($name);)*

            /// Lowercase names, indexed by discriminant (`Other` has none).
            static TAG_NAMES: [&[u8]; TAG_COUNT] = [b"", $($name,)*];

            /// Name identities, indexed by discriminant.
            const TAG_IDS: [NameId; TAG_COUNT] = [
                NameId(NameId::KNOWN_LONG),
                $(NameId::of_known(Tag::$variant, [<TAG_ $variant:snake:upper>]),)*
            ];

            const TAG_SLOTS: usize = 512;
            /// Open-addressed by name identity: the identities, and in the
            /// same slot the tag (`Other` in empty slots).
            const CLASSIFY_TABLE: ([u64; TAG_SLOTS], [Tag; TAG_SLOTS]) = {
                let mut keys = [0; TAG_SLOTS];
                let mut tags = [Tag::Other; TAG_SLOTS];
                $(
                    let key = [<TAG_ $variant:snake:upper>].as_u64();
                    let mut index = tag_slot(key);
                    while keys[index] != 0 {
                        index = (index + 1) & (TAG_SLOTS - 1);
                    }
                    keys[index] = key;
                    tags[index] = Tag::$variant;
                )*
                (keys, tags)
            };
            static CLASSIFY_KEYS: [u64; TAG_SLOTS] = CLASSIFY_TABLE.0;
            static CLASSIFY_TAGS: [Tag; TAG_SLOTS] = CLASSIFY_TABLE.1;

            const fn tag_slot(key: u64) -> usize {
                (key.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> (64 - TAG_SLOTS.trailing_zeros())) as usize
            }

            /// Classifies a tag name. The fixed table bounds even adversarial
            /// lookups without allocating; a hit on a hashed (long) identity is
            /// confirmed on the name, since a crafted name can share its hash.
            #[inline]
            fn classify(hash: LocalNameHash, name: &[u8]) -> Tag {
                let key = hash.as_u64();
                let mut index = tag_slot(key);
                loop {
                    let candidate = CLASSIFY_KEYS[index];
                    if candidate == key {
                        let tag = CLASSIFY_TAGS[index];
                        return if hash.is_exact() || tag.name().eq_ignore_ascii_case(name) {
                            tag
                        } else {
                            Tag::Other
                        };
                    }
                    if candidate == 0 {
                        return Tag::Other;
                    }
                    index = (index + 1) & (TAG_SLOTS - 1);
                }
            }

            #[cfg(test)]
            #[test]
            fn known_tag_classifier_matches_every_name() {
                $(assert_eq!(classify([<TAG_ $variant:snake:upper>], $name), Tag::$variant);)*
                $(assert_eq!(classify(LocalNameHash::of(&$name.to_ascii_uppercase()), &$name.to_ascii_uppercase()), Tag::$variant);)*
                // A hashed (long) identity is confirmed on the name.
                $(assert!([<TAG_ $variant:snake:upper>].is_exact() || classify([<TAG_ $variant:snake:upper>], b"x-forged") == Tag::Other);)*
                assert_eq!(classify(LocalNameHash::from_static(b"x-unknown"), b"x-unknown"), Tag::Other);
                assert_eq!(classify(LocalNameHash::from_static(b"x"), b"x"), Tag::Other);
                // Bound the maximum collision chain independently of document size.
                for start in 0..TAG_SLOTS {
                    assert!((0..8).any(|offset| CLASSIFY_KEYS[(start + offset) & (TAG_SLOTS - 1)] == 0));
                }
                // Identities are unique per tag.
                for (i, a) in TAG_IDS.iter().enumerate() {
                    assert!(TAG_IDS.iter().skip(i + 1).all(|b| a != b));
                }
            }

        }
    };
}

known_tags! {
    A = b"a",
    Address = b"address",
    AnnotationXml = b"annotation-xml",
    Applet = b"applet",
    Area = b"area",
    Article = b"article",
    Aside = b"aside",
    B = b"b",
    Base = b"base",
    Basefont = b"basefont",
    Bgsound = b"bgsound",
    Big = b"big",
    Blockquote = b"blockquote",
    Body = b"body",
    Br = b"br",
    Button = b"button",
    Caption = b"caption",
    Center = b"center",
    Code = b"code",
    Col = b"col",
    Colgroup = b"colgroup",
    Dd = b"dd",
    Desc = b"desc",
    Details = b"details",
    Dialog = b"dialog",
    Dir = b"dir",
    Div = b"div",
    Dl = b"dl",
    Dt = b"dt",
    Em = b"em",
    Embed = b"embed",
    Fieldset = b"fieldset",
    Figcaption = b"figcaption",
    Figure = b"figure",
    Font = b"font",
    Footer = b"footer",
    ForeignObject = b"foreignobject",
    Form = b"form",
    Frame = b"frame",
    Frameset = b"frameset",
    H1 = b"h1",
    H2 = b"h2",
    H3 = b"h3",
    H4 = b"h4",
    H5 = b"h5",
    H6 = b"h6",
    Head = b"head",
    Header = b"header",
    Hgroup = b"hgroup",
    Hr = b"hr",
    Html = b"html",
    I = b"i",
    Iframe = b"iframe",
    Image = b"image",
    Img = b"img",
    Input = b"input",
    Keygen = b"keygen",
    Li = b"li",
    Link = b"link",
    Listing = b"listing",
    Main = b"main",
    Malignmark = b"malignmark",
    Marquee = b"marquee",
    Math = b"math",
    Menu = b"menu",
    Meta = b"meta",
    Mglyph = b"mglyph",
    Mi = b"mi",
    Mn = b"mn",
    Mo = b"mo",
    Ms = b"ms",
    Mtext = b"mtext",
    Nav = b"nav",
    Nobr = b"nobr",
    Noembed = b"noembed",
    Noframes = b"noframes",
    Noscript = b"noscript",
    Object = b"object",
    Ol = b"ol",
    Optgroup = b"optgroup",
    Option = b"option",
    P = b"p",
    Param = b"param",
    Plaintext = b"plaintext",
    Pre = b"pre",
    Rb = b"rb",
    Rp = b"rp",
    Rt = b"rt",
    Rtc = b"rtc",
    Ruby = b"ruby",
    S = b"s",
    Script = b"script",
    Search = b"search",
    Section = b"section",
    Select = b"select",
    Small = b"small",
    Source = b"source",
    Span = b"span",
    Strike = b"strike",
    Strong = b"strong",
    Style = b"style",
    Sub = b"sub",
    Summary = b"summary",
    Sup = b"sup",
    Svg = b"svg",
    Table = b"table",
    Tbody = b"tbody",
    Td = b"td",
    Template = b"template",
    Textarea = b"textarea",
    Tfoot = b"tfoot",
    Th = b"th",
    Thead = b"thead",
    Title = b"title",
    Tr = b"tr",
    Track = b"track",
    Tt = b"tt",
    U = b"u",
    Ul = b"ul",
    Var = b"var",
    Wbr = b"wbr",
    Xmp = b"xmp",
}

impl Tag {
    /// The lowercase tag name (empty for [`Tag::Other`]).
    pub(super) fn name(self) -> &'static [u8] {
        TAG_NAMES[self as usize]
    }
}

const HEADINGS: [Tag; 6] = [Tag::H1, Tag::H2, Tag::H3, Tag::H4, Tag::H5, Tag::H6];

/// An element name's identity in the stack bookkeeping: the exact
/// [`LocalNameHash`] of a short name, the variant of a long known tag, or a
/// per-document keyed hash of any other lowercased name, so a crafted name
/// cannot alias another one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct NameId(u64);

impl NameId {
    /// Long known tags carry this bit over their discriminant; exact
    /// identities never set it.
    const KNOWN_LONG: u64 = 1 << 63;
    /// Keyed hashes carry both top bits.
    const KEYED: u64 = 3 << 62;

    const fn of_known(tag: Tag, hash: LocalNameHash) -> Self {
        if hash.is_exact() {
            Self(hash.as_u64())
        } else {
            Self(Self::KNOWN_LONG | tag as u64)
        }
    }

    const fn known(tag: Tag) -> Self {
        TAG_IDS[tag as usize]
    }
}

/// A tag's name as the tokenizer saw it: its identity and its bytes.
#[derive(Debug, Clone, Copy)]
pub(super) struct TagName<'a> {
    hash: LocalNameHash,
    bytes: &'a [u8],
}

impl<'a> TagName<'a> {
    fn of_start(tag: &StartTag<'a>) -> Self {
        Self {
            hash: tag.name_hash(),
            bytes: tag.name(),
        }
    }

    fn of_end(tag: &EndTag<'a>) -> Self {
        Self {
            hash: tag.name_hash(),
            bytes: tag.name(),
        }
    }
}

/// Hashes a name ASCII-lowercased, without allocating.
struct Lowercase<'a>(&'a [u8]);

impl Hash for Lowercase<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut buf = [0u8; 32];
        for chunk in self.0.chunks(buf.len()) {
            let lower = &mut buf[..chunk.len()];
            lower.copy_from_slice(chunk);
            lower.make_ascii_lowercase();
            state.write(lower);
        }
        state.write_usize(self.0.len());
    }
}

/// The namespace an element lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ns {
    Html,
    Svg,
    MathMl,
}

// Per-frame category bits (namespace-aware, computed once at push).
const SPECIAL: u16 = 1;
/// `address`, `div` and `p`: special, yet passed over by the `li`/`dd`/`dt`
/// implied-close walk.
const ADDRESS_DIV_P: u16 = 1 << 1;
const SCOPE: u16 = 1 << 2;
const LIST_SCOPE: u16 = 1 << 3;
const BUTTON_SCOPE: u16 = 1 << 4;
const TABLE_SCOPE: u16 = 1 << 5;
/// Elements that decide the insertion mode ("reset the insertion mode").
const OWNER: u16 = 1 << 6;
const HTML_NS: u16 = 1 << 7;
const HTML_IP: u16 = 1 << 8;
const TEXT_IP: u16 = 1 << 9;
const IMPLIED_END: u16 = 1 << 10;

// Indices into `Frame::near`: the nearest frame (at or below) of each kind.
const NEAR_SCOPE: usize = 0;
const NEAR_LIST: usize = 1;
const NEAR_BUTTON: usize = 2;
const NEAR_TABLE: usize = 3;
const NEAR_SPECIAL: usize = 4;
/// Nearest special element other than `address`/`div`/`p`.
const NEAR_LI_STOP: usize = 5;
const NEAR_OWNER: usize = 6;
const NEAR_HTML: usize = 7;
const NEAR_KINDS: usize = 8;

fn html_flags(tag: Tag) -> u16 {
    let category = match tag {
        Tag::Address | Tag::Div => SPECIAL | ADDRESS_DIV_P,
        Tag::P => SPECIAL | ADDRESS_DIV_P | IMPLIED_END,
        Tag::Applet | Tag::Marquee | Tag::Object | Tag::Select => SPECIAL | SCOPE,
        Tag::Caption | Tag::Td | Tag::Th => SPECIAL | SCOPE | OWNER,
        Tag::Html | Tag::Table | Tag::Template => SPECIAL | SCOPE | TABLE_SCOPE | OWNER,
        Tag::Ol | Tag::Ul => SPECIAL | LIST_SCOPE,
        Tag::Button => SPECIAL | BUTTON_SCOPE,
        Tag::Body
        | Tag::Colgroup
        | Tag::Frameset
        | Tag::Head
        | Tag::Tbody
        | Tag::Tfoot
        | Tag::Thead
        | Tag::Tr => SPECIAL | OWNER,
        Tag::Dd | Tag::Dt | Tag::Li => SPECIAL | IMPLIED_END,
        Tag::Optgroup | Tag::Option | Tag::Rb | Tag::Rp | Tag::Rt | Tag::Rtc => IMPLIED_END,
        Tag::Area
        | Tag::Article
        | Tag::Aside
        | Tag::Base
        | Tag::Basefont
        | Tag::Bgsound
        | Tag::Blockquote
        | Tag::Br
        | Tag::Center
        | Tag::Col
        | Tag::Details
        | Tag::Dir
        | Tag::Dl
        | Tag::Embed
        | Tag::Fieldset
        | Tag::Figcaption
        | Tag::Figure
        | Tag::Footer
        | Tag::Form
        | Tag::Frame
        | Tag::H1
        | Tag::H2
        | Tag::H3
        | Tag::H4
        | Tag::H5
        | Tag::H6
        | Tag::Header
        | Tag::Hgroup
        | Tag::Hr
        | Tag::Iframe
        | Tag::Img
        | Tag::Input
        | Tag::Keygen
        | Tag::Link
        | Tag::Listing
        | Tag::Main
        | Tag::Menu
        | Tag::Meta
        | Tag::Nav
        | Tag::Noembed
        | Tag::Noframes
        | Tag::Noscript
        | Tag::Param
        | Tag::Plaintext
        | Tag::Pre
        | Tag::Script
        | Tag::Section
        | Tag::Source
        | Tag::Style
        | Tag::Summary
        | Tag::Textarea
        | Tag::Title
        | Tag::Track
        | Tag::Wbr
        | Tag::Xmp => SPECIAL,
        _ => 0,
    };
    category | HTML_NS
}

fn foreign_flags(ns: Ns, tag: Tag, start: &StartTag<'_>) -> u16 {
    match (ns, tag) {
        (Ns::Svg, Tag::ForeignObject | Tag::Desc | Tag::Title) => SPECIAL | SCOPE | HTML_IP,
        (Ns::MathMl, Tag::Mi | Tag::Mo | Tag::Mn | Tag::Ms | Tag::Mtext) => {
            SPECIAL | SCOPE | TEXT_IP
        }
        (Ns::MathMl, Tag::AnnotationXml) if annotation_xml_is_html(start) => {
            SPECIAL | SCOPE | HTML_IP
        }
        (Ns::MathMl, Tag::AnnotationXml) => SPECIAL | SCOPE,
        _ => 0,
    }
}

/// The tokenizer mode an HTML element with this name switches to.
fn text_mode_of(tag: Tag) -> Option<TextMode> {
    match tag {
        Tag::Script => Some(TextMode::ScriptData),
        Tag::Textarea | Tag::Title => Some(TextMode::RcData),
        Tag::Plaintext => Some(TextMode::PlainText),
        Tag::Style | Tag::Xmp | Tag::Iframe | Tag::Noembed | Tag::Noframes | Tag::Noscript => {
            Some(TextMode::RawText)
        }
        _ => None,
    }
}

/// Start tags that end foreign content (the HTML "breakout" list).
fn is_breakout(tag: Tag) -> bool {
    matches!(
        tag,
        Tag::B
            | Tag::Big
            | Tag::Blockquote
            | Tag::Body
            | Tag::Br
            | Tag::Center
            | Tag::Code
            | Tag::Dd
            | Tag::Div
            | Tag::Dl
            | Tag::Dt
            | Tag::Em
            | Tag::Embed
            | Tag::H1
            | Tag::H2
            | Tag::H3
            | Tag::H4
            | Tag::H5
            | Tag::H6
            | Tag::Head
            | Tag::Hr
            | Tag::I
            | Tag::Img
            | Tag::Li
            | Tag::Listing
            | Tag::Menu
            | Tag::Meta
            | Tag::Nobr
            | Tag::Ol
            | Tag::P
            | Tag::Pre
            | Tag::Ruby
            | Tag::S
            | Tag::Small
            | Tag::Span
            | Tag::Strong
            | Tag::Strike
            | Tag::Sub
            | Tag::Sup
            | Tag::Table
            | Tag::Tt
            | Tag::U
            | Tag::Ul
            | Tag::Var
    )
}

fn is_heading(tag: Tag) -> bool {
    matches!(
        tag,
        Tag::H1 | Tag::H2 | Tag::H3 | Tag::H4 | Tag::H5 | Tag::H6
    )
}

fn has_attribute(tag: &StartTag<'_>, names: &[&[u8]]) -> bool {
    tag.attributes()
        .any(|attr| names.iter().any(|n| attr.name().eq_ignore_ascii_case(n)))
}

/// Whether the first attribute named `name` has one of `values`, compared
/// as browsers compare enumerated attributes (decoded, ASCII case-insensitive).
fn attribute_is(tag: &StartTag<'_>, name: &[u8], values: &[&[u8]]) -> bool {
    tag.attributes()
        .find(|attr| attr.name().eq_ignore_ascii_case(name))
        .is_some_and(|attr| attribute_value_is(attr.value(), values))
}

/// The mode a template's contents are parsed in, fixed by its first tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TemplateMode {
    Undecided,
    Body,
    Table,
    TableBody,
    Row,
    ColumnGroup,
}

/// How a frame came to be on the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Origin {
    /// Opened by a start tag.
    Tag,
    /// Created by browsers without a tag; a later tag naming it is matched
    /// as this element.
    Implied,
    /// The closed head, pushed back for a tag browsers still insert into it.
    Reopened,
}

/// An open element.
#[derive(Debug)]
pub(super) struct Frame {
    name: NameId,
    /// Element children seen so far.
    child_count: u32,
    /// The element's own 1-based `:nth-child` position.
    pub(super) position: u32,
    /// The element's own 1-based `:nth-of-type` position (1 unless tracked).
    pub(super) type_position: u32,
    /// Whether the element sits outside every removed region.
    pub(super) visible: bool,
    pub(super) origin: Origin,
    /// Start of this frame's run of child type counts in
    /// [`OpenElements::types`] (filled only when a selector uses
    /// `:nth-of-type`).
    types_start: u32,
    /// Child type counts beyond the run: wide fan-out, or children placed
    /// while the frame is not current (foster parenting).
    types_spill: Option<Box<HashMap<NameId, u32>>>,
    near: [u32; NEAR_KINDS],
    /// The next open frame below with the same name and namespace class (0 =
    /// none), restoring the name's topmost index when this frame pops.
    prev_same: u32,
    flags: u16,
    pub(super) tag: Tag,
    ns: Ns,
    template: TemplateMode,
}

impl Frame {
    /// The sentinel below every element (the document): it bounds every
    /// scope, so no walk ever runs off the stack.
    fn root() -> Self {
        Self {
            name: NameId::known(Tag::Other),
            child_count: 0,
            position: 1,
            type_position: 1,
            visible: true,
            origin: Origin::Implied,
            types_start: 0,
            types_spill: None,
            near: [0; NEAR_KINDS],
            prev_same: 0,
            flags: SPECIAL | SCOPE | TABLE_SCOPE | OWNER | HTML_NS,
            tag: Tag::Other,
            ns: Ns::Html,
            template: TemplateMode::Undecided,
        }
    }

    fn is_html(&self) -> bool {
        self.flags & HTML_NS != 0
    }

    fn is_html_tag(&self, tag: Tag) -> bool {
        self.is_html() && self.tag == tag
    }
}

/// How many children of one type a frame has seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TypeCount {
    name: NameId,
    count: u32,
}

/// Child types a frame counts in its run before spilling into a map: the
/// run is scanned, the map hashed, so every count stays O(1).
const TYPE_RUN: usize = 8;

/// What the head kept when it closed, for tags browsers still insert into it.
#[derive(Debug)]
struct ClosedHead {
    child_count: u32,
    position: u32,
    type_position: u32,
    visible: bool,
    types: Vec<TypeCount>,
    types_spill: Option<Box<HashMap<NameId, u32>>>,
}

/// An element about to be pushed.
#[derive(Debug, Clone, Copy)]
pub(super) struct NewElement {
    tag: Tag,
    ns: Ns,
    flags: u16,
    /// The element becomes the form element pointer.
    sets_form: bool,
}

impl NewElement {
    fn html(tag: Tag) -> Self {
        Self {
            tag,
            ns: Ns::Html,
            flags: html_flags(tag),
            sets_form: false,
        }
    }

    fn foreign(ns: Ns, tag: Tag, start: &StartTag<'_>) -> Self {
        Self {
            tag,
            ns,
            flags: foreign_flags(ns, tag, start),
            sets_form: false,
        }
    }
}

/// Where an inserted element lands.
#[derive(Debug, Clone, Copy)]
pub(super) struct Slot {
    /// The frame selectors match against as the parent: the current node, or
    /// the foster parent for content misplaced in a table.
    pub(super) parent: usize,
    /// The table a foster-parented element goes in front of (0: appended).
    before: usize,
}

/// Where a start tag's element goes.
#[derive(Debug, Clone, Copy)]
pub(super) enum Placement {
    /// Browsers drop the tag: it creates no element.
    Dropped,
    /// The tag names an element that is already open (`html`, `body`, or a
    /// head browsers created without a tag). `claim` is set for the first
    /// tag to name an implied element: only that one is matched.
    Merged { frame: usize, claim: bool },
    /// An element without children (void, or self-closing foreign content).
    Leaf(Slot),
    /// An element that stays open; push it with [`OpenElements::push`].
    Open(Slot, NewElement),
}

#[derive(Debug, Clone, Copy)]
pub(super) struct StartPlan {
    pub(super) name: NameId,
    pub(super) placement: Placement,
}

/// What an end tag did beyond closing frames (which
/// [`OpenElements::take_low`] reports).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EndOutcome {
    /// Whether the deepest closed frame is the element the tag names (the tag
    /// then stands for that element's end).
    pub(crate) closes_named: bool,
    /// Frames (innermost first, 0 = none) whose end-anchored edits land at
    /// this tag although they stay open: `</body>` and `</html>`.
    pub(crate) anchors: [usize; 2],
}

impl EndOutcome {
    const IGNORED: Self = Self {
        closes_named: false,
        anchors: [0; 2],
    };

    fn closed(popped: usize) -> Self {
        Self {
            closes_named: popped > 0,
            anchors: [0; 2],
        }
    }
}

/// The insertion modes that affect the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// No `html` element yet (the "initial" and "before html" modes).
    Initial,
    BeforeHead,
    InHead,
    AfterHead,
    InBody,
    InTable,
    InTableBody,
    InRow,
    InCell,
    InCaption,
    InColumnGroup,
    InTemplate,
}

/// Document-level progress while the `html` element owns the insertion mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Initial,
    BeforeHead,
    AfterHead,
    InBody,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuirksMode {
    Undecided,
    Quirks,
    NoQuirks,
}

/// The form element pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormPointer {
    Null,
    /// Points at the open frame at this index.
    Open(u32),
    /// Points at a form no longer on the stack (still blocks nested forms).
    Closed,
}

/// The tree-construction view of the open elements.
#[derive(Debug)]
pub(super) struct OpenElements {
    frames: Vec<Frame>,
    /// Topmost open HTML frame per unknown name.
    html_top: HashMap<NameId, u32>,
    /// Topmost open HTML frame per known name, without hashing.
    known_top: [u32; TAG_COUNT],
    /// Topmost open SVG/MathML frame per name.
    foreign_top: HashMap<NameId, u32>,
    /// The frames' runs of child type counts, in stack order: a frame
    /// counts new types only while it is the current node, when its run is
    /// last.
    types: Vec<TypeCount>,
    /// Random per-document key for [`NameId`]s: names are untrusted.
    keys: RandomState,
    /// The last exact identity classified and its tag: a start tag is
    /// classified for its text mode, then again for its insertion.
    classified: (LocalNameHash, Tag),
    form: FormPointer,
    phase: Phase,
    quirks: QuirksMode,
    pub(super) mode: ScopeMode,
    /// Whether `:nth-of-type` positions are counted (some selector uses them).
    pub(super) tracks_type: bool,
    /// Lowest stack length since the last [`Self::take_low`].
    low: usize,
    /// Whether a frame closed or an implied one opened since then.
    changed: bool,
    closed_head: Option<ClosedHead>,
    /// Index the head frame had when it closed, until [`Self::take_closed_head`].
    head_closed_at: Option<usize>,
    /// Frames inspected, pops and rule iterations: the linearity tripwire
    /// tests bound this by the token count.
    #[cfg(test)]
    pub(super) work: Cell<usize>,
    /// A plain map per frame (and for the closed head) that every type
    /// count is checked against.
    #[cfg(any(test, fuzzing))]
    type_model: (Vec<HashMap<NameId, u32>>, Option<HashMap<NameId, u32>>),
}

impl OpenElements {
    pub(super) fn new() -> Self {
        let keys = RandomState::new();
        Self {
            frames: vec![Frame::root()],
            html_top: HashMap::with_hasher(keys.clone()),
            known_top: [0; TAG_COUNT],
            foreign_top: HashMap::with_hasher(keys.clone()),
            types: Vec::new(),
            keys,
            classified: (LocalNameHash::NONE, Tag::Other),
            form: FormPointer::Null,
            phase: Phase::Initial,
            quirks: QuirksMode::Undecided,
            mode: ScopeMode::default(),
            tracks_type: false,
            low: 1,
            changed: false,
            closed_head: None,
            head_closed_at: None,
            #[cfg(test)]
            work: Cell::new(0),
            #[cfg(any(test, fuzzing))]
            type_model: (vec![HashMap::default()], None),
        }
    }

    #[inline]
    #[cfg_attr(not(test), expect(clippy::unused_self, reason = "only tests count"))]
    fn count_work(&self) {
        #[cfg(test)]
        self.work.set(self.work.get() + 1);
    }

    /// The frame at `index` (counted by the linearity tripwire).
    #[inline]
    pub(super) fn at(&self, index: usize) -> &Frame {
        self.count_work();
        &self.frames[index]
    }

    #[inline]
    pub(super) fn at_mut(&mut self, index: usize) -> &mut Frame {
        self.count_work();
        &mut self.frames[index]
    }

    /// Number of frames, the root sentinel included.
    #[inline]
    pub(super) fn depth(&self) -> usize {
        self.frames.len()
    }

    /// The lowest stack length since the last call: frames from that index
    /// up closed (those above the current depth) or are new.
    #[inline]
    pub(super) fn take_low(&mut self) -> usize {
        self.changed = false;
        mem::replace(&mut self.low, self.frames.len())
    }

    /// The index the head frame had, if it closed since the last call.
    #[inline]
    pub(super) fn take_closed_head(&mut self) -> Option<usize> {
        self.head_closed_at.take()
    }

    #[inline]
    fn top(&self) -> usize {
        self.frames.len() - 1
    }

    #[inline]
    fn cur(&self) -> &Frame {
        self.at(self.top())
    }

    #[inline]
    fn near(&self, kind: usize) -> usize {
        self.cur().near[kind] as usize
    }

    /// The name identity of a tag classified as `tag`.
    #[inline]
    fn name_id(&self, tag: Tag, name: TagName<'_>) -> NameId {
        if name.hash.is_exact() {
            NameId(name.hash.as_u64())
        } else if tag != Tag::Other {
            NameId::known(tag)
        } else {
            NameId(self.keys.hash_one(Lowercase(name.bytes)) | NameId::KEYED)
        }
    }

    /// Topmost open HTML frame of a known tag (0 = none).
    #[inline]
    fn known(&self, tag: Tag) -> usize {
        self.known_top[tag as usize] as usize
    }

    /// Topmost open HTML frame named `name`, classified as `tag` (0 = none).
    fn html_named(&self, tag: Tag, name: TagName<'_>) -> usize {
        if tag == Tag::Other {
            self.html_top
                .get(&self.name_id(tag, name))
                .map_or(0, |&i| i as usize)
        } else {
            self.known(tag)
        }
    }

    fn foreign_top(&self, name: NameId) -> usize {
        self.foreign_top.get(&name).map_or(0, |&i| i as usize)
    }

    /// Whether the frame at `index` is in the scope whose boundaries are
    /// cached at `kind` (a boundary that is itself the target is in scope).
    #[inline]
    fn in_scope(&self, index: usize, kind: usize) -> bool {
        index > 0 && index >= self.near(kind)
    }

    fn template_open(&self) -> bool {
        self.known(Tag::Template) != 0
    }

    /// Whether `<![CDATA[` opens a CDATA section: only when the current node
    /// is foreign. Integration points count as HTML, as Chromium and WebKit
    /// treat them.
    pub(super) fn cdata_allowed(&self) -> bool {
        self.cur().flags & (HTML_NS | HTML_IP | TEXT_IP) == 0
    }

    /// The text mode a start tag switches the tokenizer to: only an HTML
    /// text element the tree actually inserts does. Decided without changing
    /// the stack, so the tokenizer can look ahead for a raw-text body.
    pub(super) fn text_mode(&mut self, hash: LocalNameHash, name: &[u8]) -> Option<TextMode> {
        let tag = self.classify(hash, name);
        self.text_switch(tag)
    }

    /// [`classify`], remembering the last exact identity (a pure function of
    /// it, so the remembered tag is never stale).
    #[inline]
    fn classify(&mut self, hash: LocalNameHash, name: &[u8]) -> Tag {
        if hash == self.classified.0 {
            return self.classified.1;
        }
        let tag = classify(hash, name);
        if hash.is_exact() {
            self.classified = (hash, tag);
        }
        tag
    }

    /// Whether the stack changed since the last [`Self::take_low`] (a frame
    /// closed, or one browsers create without a tag opened).
    #[inline]
    pub(super) fn changed(&self) -> bool {
        self.changed
    }

    fn text_switch(&self, tag: Tag) -> Option<TextMode> {
        let mode = text_mode_of(tag)?;
        // Of the modes, only a column group drops such tags (when the
        // template, not a colgroup, is current); everywhere else they insert.
        let inserted = self.html_rules(tag)
            && (self.insertion_mode() != Mode::InColumnGroup
                || self.cur().is_html_tag(Tag::Colgroup));
        inserted.then_some(mode)
    }

    /// Counts an element inserted at `slot` as a child, returning its
    /// `:nth-child` and `:nth-of-type` positions.
    #[inline]
    pub(super) fn place(&mut self, slot: Slot, name: NameId) -> (u32, u32) {
        self.count_work();
        let parent = &mut self.frames[slot.parent];
        parent.child_count = parent.child_count.saturating_add(1);
        let mut position = parent.child_count;
        let type_position = if self.tracks_type {
            self.count_type(slot.parent, name)
        } else {
            1
        };
        if slot.before > 0 {
            // Foster parenting inserts in front of the table.
            let table = &mut self.frames[slot.before];
            position = table.position;
            table.position = position.saturating_add(1);
        }
        (position, type_position)
    }

    /// Counts a child of type `name` of the frame at `parent`, returning its
    /// `:nth-of-type` position.
    fn count_type(&mut self, parent: usize, name: NameId) -> u32 {
        let count = self.count_type_in_runs(parent, name);
        #[cfg(any(test, fuzzing))]
        {
            let model = self.type_model.0[parent].entry(name).or_default();
            *model += 1;
            assert_eq!(count, *model, "type count of a child of frame {parent}");
        }
        count
    }

    fn count_type_in_runs(&mut self, parent: usize, name: NameId) -> u32 {
        let start = self.frames[parent].types_start as usize;
        let current = parent + 1 == self.frames.len();
        let end = if current {
            self.types.len()
        } else {
            self.frames[parent + 1].types_start as usize
        };
        if let Some(entry) = self.types[start..end].iter_mut().find(|e| e.name == name) {
            entry.count = entry.count.saturating_add(1);
            return entry.count;
        }
        let frame = &mut self.frames[parent];
        if let Some(count) = frame
            .types_spill
            .as_mut()
            .and_then(|spill| spill.get_mut(&name))
        {
            *count = count.saturating_add(1);
            return *count;
        }
        if current && end - start < TYPE_RUN {
            self.types.push(TypeCount { name, count: 1 });
        } else {
            frame
                .types_spill
                .get_or_insert_with(|| Box::new(HashMap::with_hasher(self.keys.clone())))
                .insert(name, 1);
        }
        1
    }

    /// Pushes an element planned by [`Self::start_tag`], placed by
    /// [`Self::place`].
    pub(super) fn push(&mut self, name: NameId, element: NewElement, positions: (u32, u32)) {
        // The caller tracks this frame itself: it is no change to report.
        let reported = self.low == self.frames.len();
        self.push_frame(name, element, positions, Origin::Tag);
        if reported {
            self.low = self.frames.len();
        }
    }

    fn push_frame(
        &mut self,
        name: NameId,
        element: NewElement,
        (position, type_position): (u32, u32),
        origin: Origin,
    ) {
        let index = self.frames.len();
        // Depths beyond `u32::MAX` would need terabytes of frames.
        let index32 = u32::try_from(index).unwrap_or(u32::MAX);
        let parent = self.cur().near;
        let flags = element.flags;
        let pick = |hit: bool, kind: usize| if hit { index32 } else { parent[kind] };
        let near = [
            pick(flags & SCOPE != 0, NEAR_SCOPE),
            pick(flags & (SCOPE | LIST_SCOPE) != 0, NEAR_LIST),
            pick(flags & (SCOPE | BUTTON_SCOPE) != 0, NEAR_BUTTON),
            pick(flags & TABLE_SCOPE != 0, NEAR_TABLE),
            pick(flags & SPECIAL != 0, NEAR_SPECIAL),
            pick(
                flags & SPECIAL != 0 && flags & ADDRESS_DIV_P == 0,
                NEAR_LI_STOP,
            ),
            pick(flags & OWNER != 0, NEAR_OWNER),
            pick(flags & HTML_NS != 0, NEAR_HTML),
        ];
        let prev_same = if flags & HTML_NS != 0 && element.tag != Tag::Other {
            mem::replace(&mut self.known_top[element.tag as usize], index32)
        } else {
            let names = if flags & HTML_NS != 0 {
                &mut self.html_top
            } else {
                &mut self.foreign_top
            };
            names.insert(name, index32).unwrap_or(0)
        };
        if element.sets_form {
            self.form = FormPointer::Open(index32);
        }
        self.frames.push(Frame {
            name,
            child_count: 0,
            position,
            type_position,
            visible: true,
            origin,
            types_start: u32::try_from(self.types.len()).unwrap_or(u32::MAX),
            types_spill: None,
            near,
            prev_same,
            flags,
            tag: element.tag,
            ns: element.ns,
            template: TemplateMode::Undecided,
        });
        #[cfg(any(test, fuzzing))]
        self.type_model.0.push(HashMap::default());
    }

    /// Pushes an element browsers create without a tag.
    fn push_implied(&mut self, tag: Tag) {
        self.changed = true;
        let name = NameId::known(tag);
        let positions = self.place(
            Slot {
                parent: self.top(),
                before: 0,
            },
            name,
        );
        self.push_frame(name, NewElement::html(tag), positions, Origin::Implied);
    }

    /// Pushes the closed head back, for a tag browsers insert into it.
    fn reopen_head(&mut self) {
        self.changed = true;
        let Some(head) = self.closed_head.take() else {
            self.push_implied(Tag::Head);
            return;
        };
        self.push_frame(
            NameId::known(Tag::Head),
            NewElement::html(Tag::Head),
            (head.position, head.type_position),
            Origin::Reopened,
        );
        if let Some(frame) = self.frames.last_mut() {
            frame.child_count = head.child_count;
            frame.types_spill = head.types_spill;
            frame.visible = head.visible;
        }
        self.types.extend_from_slice(&head.types);
        #[cfg(any(test, fuzzing))]
        if let (Some(model), Some(head)) = (self.type_model.1.take(), self.type_model.0.last_mut())
        {
            *head = model;
        }
    }

    fn pop(&mut self) {
        if self.frames.len() <= 1 {
            return;
        }
        let Some(frame) = self.frames.pop() else {
            return;
        };
        self.count_work();
        let index = self.frames.len();
        self.low = self.low.min(index);
        self.changed = true;
        let types_start = frame.types_start as usize;
        #[cfg(any(test, fuzzing))]
        let model = self.type_model.0.pop();
        if frame.is_html() && frame.tag != Tag::Other {
            self.known_top[frame.tag as usize] = frame.prev_same;
        } else {
            let names = if frame.is_html() {
                &mut self.html_top
            } else {
                &mut self.foreign_top
            };
            if frame.prev_same == 0 {
                names.remove(&frame.name);
            } else {
                names.insert(frame.name, frame.prev_same);
            }
        }
        if self.form == FormPointer::Open(u32::try_from(index).unwrap_or(u32::MAX)) {
            self.form = FormPointer::Closed;
        }
        if frame.is_html_tag(Tag::Head) && self.mode == ScopeMode::Browser {
            self.head_closed_at = Some(index);
            self.closed_head = Some(ClosedHead {
                child_count: frame.child_count,
                position: frame.position,
                type_position: frame.type_position,
                visible: frame.visible,
                types: self.types.get(types_start..).unwrap_or_default().to_vec(),
                types_spill: frame.types_spill,
            });
            #[cfg(any(test, fuzzing))]
            {
                self.type_model.1 = model;
            }
        }
        self.types.truncate(types_start);
    }

    /// Closes the frames at `index` and above, returning how many closed. The
    /// root sentinel (index 0) never closes.
    fn pop_to(&mut self, index: usize) -> usize {
        if index == 0 || index >= self.frames.len() {
            return 0;
        }
        let popped = self.frames.len() - index;
        for _ in 0..popped {
            self.pop();
        }
        popped
    }

    /// Closes every frame above `index`.
    fn pop_above(&mut self, index: usize) -> usize {
        self.pop_to(index + 1)
    }

    /// Closes the frames above the insertion-mode owner ("clear the stack
    /// back to a table / table body / table row context").
    fn clear_to_owner(&mut self) {
        self.pop_above(self.near(NEAR_OWNER));
    }

    /// Closes the head (and anything above it) when it owns the mode.
    fn pop_head(&mut self) -> usize {
        self.phase = Phase::AfterHead;
        let owner = self.near(NEAR_OWNER);
        if self.at(owner).is_html_tag(Tag::Head) {
            self.pop_to(owner)
        } else {
            0
        }
    }

    /// "Generate implied end tags", optionally sparing one name.
    fn generate_implied_end_tags(&mut self, except: Option<Tag>) {
        loop {
            let cur = self.cur();
            if cur.flags & IMPLIED_END == 0 || Some(cur.tag) == except {
                return;
            }
            self.pop();
        }
    }

    /// Pops foreign elements until an HTML element or integration point is
    /// the current node.
    fn pop_out_of_foreign(&mut self) {
        while self.cur().flags & (HTML_NS | HTML_IP | TEXT_IP) == 0 {
            self.pop();
        }
    }

    /// "Close a p element" when one is in button scope.
    fn close_p(&mut self) {
        let p = self.known(Tag::P);
        if self.in_scope(p, NEAR_BUTTON) {
            self.pop_to(p);
        }
    }

    fn close_in_scope(&mut self, tag: Tag, kind: usize) -> usize {
        let index = self.known(tag);
        if self.in_scope(index, kind) {
            self.pop_to(index)
        } else {
            0
        }
    }

    fn insertion_mode(&self) -> Mode {
        let owner_index = self.near(NEAR_OWNER);
        if owner_index == 0 {
            return Mode::Initial;
        }
        let owner = self.at(owner_index);
        match owner.tag {
            Tag::Td | Tag::Th => Mode::InCell,
            Tag::Tr => Mode::InRow,
            Tag::Tbody | Tag::Thead | Tag::Tfoot => Mode::InTableBody,
            Tag::Caption => Mode::InCaption,
            Tag::Colgroup => Mode::InColumnGroup,
            Tag::Table => Mode::InTable,
            Tag::Template => match owner.template {
                TemplateMode::Undecided => Mode::InTemplate,
                TemplateMode::Body => Mode::InBody,
                TemplateMode::Table => Mode::InTable,
                TemplateMode::TableBody => Mode::InTableBody,
                TemplateMode::Row => Mode::InRow,
                TemplateMode::ColumnGroup => Mode::InColumnGroup,
            },
            Tag::Head => Mode::InHead,
            Tag::Html => {
                if self.phase == Phase::BeforeHead {
                    Mode::BeforeHead
                } else {
                    Mode::AfterHead
                }
            }
            _ => Mode::InBody,
        }
    }

    /// Whether a start tag follows the HTML rules (rather than the foreign
    /// content ones) at the current node.
    fn html_rules(&self, tag: Tag) -> bool {
        let cur = self.cur();
        cur.is_html()
            || cur.flags & HTML_IP != 0
            || (cur.flags & TEXT_IP != 0 && !matches!(tag, Tag::Mglyph | Tag::Malignmark))
            || (cur.ns == Ns::MathMl && cur.tag == Tag::AnnotationXml && tag == Tag::Svg)
    }

    // --- placements -----------------------------------------------------

    /// Where an element inserted now lands: in front of the table when
    /// content lands directly in table structure, else in the current node.
    fn slot(&self, foster: bool) -> Slot {
        let top = self.top();
        let cur = self.at(top);
        if foster
            && cur.is_html()
            && matches!(
                cur.tag,
                Tag::Table | Tag::Tbody | Tag::Tfoot | Tag::Thead | Tag::Tr
            )
        {
            let template = self.known(Tag::Template);
            let table = self.known(Tag::Table);
            if template > table {
                return Slot {
                    parent: template,
                    before: 0,
                };
            }
            if table > 0 {
                return Slot {
                    parent: table - 1,
                    before: table,
                };
            }
        }
        Slot {
            parent: top,
            before: 0,
        }
    }

    fn leaf(&self, foster: bool) -> Placement {
        Placement::Leaf(self.slot(foster))
    }

    fn open(&self, element: NewElement, foster: bool) -> Placement {
        Placement::Open(self.slot(foster), element)
    }

    fn open_html(&self, tag: Tag, foster: bool) -> Placement {
        self.open(NewElement::html(tag), foster)
    }

    /// Matches a tag as the open element at `index`; only the first tag to
    /// name an implied element claims it.
    fn merge(&mut self, index: usize) -> Placement {
        let frame = self.at_mut(index);
        let claim = frame.origin == Origin::Implied;
        if claim {
            frame.origin = Origin::Tag;
        }
        Placement::Merged {
            frame: index,
            claim,
        }
    }

    /// A late `<html>`: browsers merge its attributes into the root element.
    fn merge_html(&mut self) -> Placement {
        if self.template_open() || !self.frames.get(1).is_some_and(|f| f.is_html_tag(Tag::Html)) {
            Placement::Dropped
        } else {
            self.merge(1)
        }
    }

    /// A late `<body>`: browsers merge its attributes into the body element.
    fn merge_body(&mut self) -> Placement {
        if self.template_open() || !self.frames.get(2).is_some_and(|f| f.is_html_tag(Tag::Body)) {
            Placement::Dropped
        } else {
            self.merge(2)
        }
    }

    /// A `<head>` in the head: browsers ignore it, yet a head they created
    /// on their own is still the element the tag names.
    fn merge_head(&mut self) -> Placement {
        let owner = self.near(NEAR_OWNER);
        let frame = self.at(owner);
        if frame.is_html_tag(Tag::Head) && frame.origin == Origin::Implied {
            self.merge(owner)
        } else {
            Placement::Dropped
        }
    }

    // --- start tags -----------------------------------------------------

    /// Applies a start tag's implied ends and decides where its element goes.
    pub(super) fn start_tag(&mut self, tag: &StartTag<'_>) -> StartPlan {
        let kind = self.classify(tag.name_hash(), tag.name());
        #[cfg(any(test, fuzzing))]
        let predicted = self.text_switch(kind);
        let placement = match self.mode {
            ScopeMode::Browser => self.browser_start(kind, tag),
            ScopeMode::NearestMatch => self.nearest_start(kind, tag.is_self_closing()),
        };
        #[cfg(any(test, fuzzing))]
        if self.mode == ScopeMode::Browser {
            let inserted = matches!(placement, Placement::Open(_, element)
                if element.ns == Ns::Html && text_mode_of(element.tag).is_some());
            assert_eq!(
                predicted.is_some(),
                inserted,
                "text-mode prediction disagrees with tree construction for {:?}",
                String::from_utf8_lossy(tag.raw())
            );
        }
        let name = match placement {
            Placement::Leaf(_) | Placement::Open(..) => self.name_id(kind, TagName::of_start(tag)),
            Placement::Dropped | Placement::Merged { .. } => NameId::known(kind),
        };
        StartPlan { name, placement }
    }

    fn leave_initial(&mut self) {
        if self.quirks == QuirksMode::Undecided {
            self.quirks = QuirksMode::Quirks;
        }
    }

    // Kept out of line: inlining every mode into one entry point slows both.
    #[inline(never)]
    fn browser_start(&mut self, kind: Tag, tag: &StartTag<'_>) -> Placement {
        self.leave_initial();
        if !self.html_rules(kind) {
            if is_breakout(kind)
                || (kind == Tag::Font && has_attribute(tag, &[b"color", b"face", b"size"]))
            {
                self.pop_out_of_foreign();
            } else {
                let ns = self.cur().ns;
                return if tag.is_self_closing() {
                    self.leaf(false)
                } else {
                    self.open(NewElement::foreign(ns, kind, tag), false)
                };
            }
        }
        loop {
            self.count_work();
            let placement = match self.insertion_mode() {
                Mode::Initial => self.start_initial(kind),
                Mode::BeforeHead => self.start_before_head(kind),
                Mode::InHead => self.start_in_head(kind),
                Mode::AfterHead => self.start_after_head(kind),
                Mode::InBody => Some(self.start_in_body(kind, tag, false)),
                Mode::InTable => self.start_in_table(kind, tag),
                Mode::InTableBody => self.start_in_table_body(kind, tag),
                Mode::InRow => self.start_in_row(kind, tag),
                // The same tags close a caption as a cell.
                Mode::InCell | Mode::InCaption => self.start_in_cell(kind, tag),
                Mode::InColumnGroup => self.start_in_column_group(kind),
                Mode::InTemplate => self.start_in_template(kind),
            };
            if let Some(placement) = placement {
                return placement;
            }
        }
    }

    fn start_initial(&mut self, kind: Tag) -> Option<Placement> {
        self.phase = Phase::BeforeHead;
        if kind == Tag::Html {
            Some(self.open_html(kind, false))
        } else {
            self.push_implied(Tag::Html);
            None
        }
    }

    fn start_before_head(&mut self, kind: Tag) -> Option<Placement> {
        match kind {
            Tag::Html => Some(self.merge_html()),
            Tag::Head => Some(self.open_html(kind, false)),
            _ => {
                self.push_implied(Tag::Head);
                None
            }
        }
    }

    fn start_in_head(&mut self, kind: Tag) -> Option<Placement> {
        match kind {
            Tag::Html => Some(self.merge_html()),
            Tag::Head => Some(self.merge_head()),
            Tag::Base | Tag::Basefont | Tag::Bgsound | Tag::Link | Tag::Meta => {
                Some(self.leaf(false))
            }
            Tag::Title
            | Tag::Noscript
            | Tag::Noframes
            | Tag::Style
            | Tag::Script
            | Tag::Template => Some(self.open_html(kind, false)),
            _ => {
                self.pop_head();
                None
            }
        }
    }

    fn start_after_head(&mut self, kind: Tag) -> Option<Placement> {
        match kind {
            Tag::Html => Some(self.merge_html()),
            Tag::Body | Tag::Frameset => {
                self.phase = Phase::InBody;
                Some(self.open_html(kind, false))
            }
            // Browsers insert these into the head element after all.
            Tag::Base
            | Tag::Basefont
            | Tag::Bgsound
            | Tag::Link
            | Tag::Meta
            | Tag::Noframes
            | Tag::Script
            | Tag::Style
            | Tag::Template
            | Tag::Title => {
                self.reopen_head();
                None
            }
            Tag::Head => Some(Placement::Dropped),
            _ => {
                self.push_implied(Tag::Body);
                self.phase = Phase::InBody;
                None
            }
        }
    }

    fn start_in_body(&mut self, kind: Tag, tag: &StartTag<'_>, foster: bool) -> Placement {
        match kind {
            Tag::Html => self.merge_html(),
            Tag::Body => self.merge_body(),
            Tag::Frameset
            | Tag::Head
            | Tag::Caption
            | Tag::Col
            | Tag::Colgroup
            | Tag::Frame
            | Tag::Tbody
            | Tag::Td
            | Tag::Tfoot
            | Tag::Th
            | Tag::Thead
            | Tag::Tr => Placement::Dropped,
            Tag::Base
            | Tag::Basefont
            | Tag::Bgsound
            | Tag::Link
            | Tag::Meta
            | Tag::Area
            | Tag::Br
            | Tag::Embed
            | Tag::Img
            | Tag::Image
            | Tag::Keygen
            | Tag::Wbr
            | Tag::Param
            | Tag::Source
            | Tag::Track => self.leaf(foster),
            Tag::Address
            | Tag::Article
            | Tag::Aside
            | Tag::Blockquote
            | Tag::Center
            | Tag::Details
            | Tag::Dialog
            | Tag::Dir
            | Tag::Div
            | Tag::Dl
            | Tag::Fieldset
            | Tag::Figcaption
            | Tag::Figure
            | Tag::Footer
            | Tag::Header
            | Tag::Hgroup
            | Tag::Main
            | Tag::Menu
            | Tag::Nav
            | Tag::Ol
            | Tag::P
            | Tag::Search
            | Tag::Section
            | Tag::Summary
            | Tag::Ul
            | Tag::Pre
            | Tag::Listing
            | Tag::Plaintext
            | Tag::Xmp => {
                self.close_p();
                self.open_html(kind, foster)
            }
            Tag::H1 | Tag::H2 | Tag::H3 | Tag::H4 | Tag::H5 | Tag::H6 => {
                self.close_p();
                if self.cur().is_html() && is_heading(self.cur().tag) {
                    self.pop();
                }
                self.open_html(kind, foster)
            }
            Tag::Form => {
                let in_template = self.template_open();
                if self.form != FormPointer::Null && !in_template {
                    Placement::Dropped
                } else {
                    self.close_p();
                    let mut element = NewElement::html(kind);
                    element.sets_form = !in_template;
                    self.open(element, foster)
                }
            }
            Tag::Li => {
                self.close_list_item(|t| t == Tag::Li);
                self.close_p();
                self.open_html(kind, foster)
            }
            Tag::Dd | Tag::Dt => {
                self.close_list_item(|t| matches!(t, Tag::Dd | Tag::Dt));
                self.close_p();
                self.open_html(kind, foster)
            }
            Tag::Button => {
                self.close_in_scope(Tag::Button, NEAR_SCOPE);
                self.open_html(kind, foster)
            }
            Tag::Table => {
                if self.quirks != QuirksMode::Quirks {
                    self.close_p();
                }
                self.open_html(kind, foster)
            }
            Tag::Input => {
                self.close_in_scope(Tag::Select, NEAR_SCOPE);
                self.leaf(foster)
            }
            Tag::Hr => {
                self.close_p();
                if self.in_scope(self.known(Tag::Select), NEAR_SCOPE) {
                    self.generate_implied_end_tags(None);
                }
                self.leaf(foster)
            }
            Tag::Select => {
                let select = self.known(Tag::Select);
                if self.in_scope(select, NEAR_SCOPE) {
                    self.pop_to(select);
                    Placement::Dropped
                } else {
                    self.open_html(kind, foster)
                }
            }
            Tag::Option | Tag::Optgroup => {
                if self.in_scope(self.known(Tag::Select), NEAR_SCOPE) {
                    let except = (kind == Tag::Option).then_some(Tag::Optgroup);
                    self.generate_implied_end_tags(except);
                } else if self.cur().is_html_tag(Tag::Option) {
                    self.pop();
                }
                self.open_html(kind, foster)
            }
            Tag::Rb | Tag::Rtc | Tag::Rp | Tag::Rt => {
                if self.in_scope(self.known(Tag::Ruby), NEAR_SCOPE) {
                    let except = matches!(kind, Tag::Rp | Tag::Rt).then_some(Tag::Rtc);
                    self.generate_implied_end_tags(except);
                }
                self.open_html(kind, foster)
            }
            Tag::Math | Tag::Svg => {
                if tag.is_self_closing() {
                    self.leaf(foster)
                } else {
                    let ns = if kind == Tag::Svg {
                        Ns::Svg
                    } else {
                        Ns::MathMl
                    };
                    self.open(NewElement::foreign(ns, kind, tag), foster)
                }
            }
            _ => self.open_html(kind, foster),
        }
    }

    /// The `li` / `dd` / `dt` walk: closes the nearest matching item unless a
    /// special element (other than `address`, `div`, `p`) comes first.
    fn close_list_item(&mut self, is_item: impl Fn(Tag) -> bool) {
        let stop = self.near(NEAR_LI_STOP);
        let frame = self.at(stop);
        if stop > 0 && frame.is_html() && is_item(frame.tag) {
            self.pop_to(stop);
        }
    }

    fn start_in_table(&mut self, kind: Tag, tag: &StartTag<'_>) -> Option<Placement> {
        Some(match kind {
            Tag::Caption | Tag::Colgroup | Tag::Tbody | Tag::Tfoot | Tag::Thead => {
                self.clear_to_owner();
                self.open_html(kind, false)
            }
            Tag::Col => {
                self.clear_to_owner();
                self.push_implied(Tag::Colgroup);
                return None;
            }
            Tag::Td | Tag::Th | Tag::Tr => {
                self.clear_to_owner();
                self.push_implied(Tag::Tbody);
                return None;
            }
            Tag::Table => {
                let table = self.known(Tag::Table);
                if !self.in_scope(table, NEAR_TABLE) {
                    return Some(Placement::Dropped);
                }
                // Reprocessed in whatever mode the outer context is in.
                self.pop_to(table);
                return None;
            }
            Tag::Style | Tag::Script | Tag::Template => self.open_html(kind, false),
            Tag::Input if attribute_is(tag, b"type", &[b"hidden"]) => self.leaf(false),
            Tag::Form => {
                // Inside a template, Chromium and WebKit keep the form.
                if !self.template_open() {
                    if self.form != FormPointer::Null {
                        return Some(Placement::Dropped);
                    }
                    self.form = FormPointer::Closed;
                }
                self.leaf(false)
            }
            _ => self.start_in_body(kind, tag, true),
        })
    }

    fn section_in_table_scope(&self) -> bool {
        let section = self
            .known(Tag::Tbody)
            .max(self.known(Tag::Thead))
            .max(self.known(Tag::Tfoot));
        self.in_scope(section, NEAR_TABLE)
    }

    fn start_in_table_body(&mut self, kind: Tag, tag: &StartTag<'_>) -> Option<Placement> {
        match kind {
            Tag::Tr => {
                self.clear_to_owner();
                Some(self.open_html(kind, false))
            }
            Tag::Td | Tag::Th => {
                self.clear_to_owner();
                self.push_implied(Tag::Tr);
                None
            }
            Tag::Caption | Tag::Col | Tag::Colgroup | Tag::Tbody | Tag::Tfoot | Tag::Thead => {
                if self.section_in_table_scope() {
                    self.clear_to_owner();
                    self.pop_to(self.near(NEAR_OWNER));
                    None
                } else {
                    Some(Placement::Dropped)
                }
            }
            _ => self.start_in_table(kind, tag),
        }
    }

    fn start_in_row(&mut self, kind: Tag, tag: &StartTag<'_>) -> Option<Placement> {
        match kind {
            Tag::Td | Tag::Th => {
                self.clear_to_owner();
                Some(self.open_html(kind, false))
            }
            Tag::Caption
            | Tag::Col
            | Tag::Colgroup
            | Tag::Tbody
            | Tag::Tfoot
            | Tag::Thead
            | Tag::Tr => {
                if self.in_scope(self.known(Tag::Tr), NEAR_TABLE) {
                    self.clear_to_owner();
                    self.pop_to(self.near(NEAR_OWNER));
                    None
                } else {
                    Some(Placement::Dropped)
                }
            }
            _ => self.start_in_table(kind, tag),
        }
    }

    fn start_in_cell(&mut self, kind: Tag, tag: &StartTag<'_>) -> Option<Placement> {
        match kind {
            Tag::Caption
            | Tag::Col
            | Tag::Colgroup
            | Tag::Tbody
            | Tag::Td
            | Tag::Tfoot
            | Tag::Th
            | Tag::Thead
            | Tag::Tr => {
                self.pop_to(self.near(NEAR_OWNER));
                None
            }
            _ => Some(self.start_in_body(kind, tag, false)),
        }
    }

    fn start_in_column_group(&mut self, kind: Tag) -> Option<Placement> {
        match kind {
            Tag::Html => Some(self.merge_html()),
            Tag::Col => Some(self.leaf(false)),
            Tag::Template => Some(self.open_html(kind, false)),
            _ if self.cur().is_html_tag(Tag::Colgroup) => {
                self.pop();
                None
            }
            _ => Some(Placement::Dropped),
        }
    }

    fn start_in_template(&mut self, kind: Tag) -> Option<Placement> {
        let mode = match kind {
            Tag::Base | Tag::Basefont | Tag::Bgsound | Tag::Link | Tag::Meta => {
                return Some(self.leaf(false));
            }
            Tag::Noframes | Tag::Script | Tag::Style | Tag::Template | Tag::Title => {
                return Some(self.open_html(kind, false));
            }
            Tag::Caption | Tag::Colgroup | Tag::Tbody | Tag::Tfoot | Tag::Thead => {
                TemplateMode::Table
            }
            Tag::Col => TemplateMode::ColumnGroup,
            Tag::Tr => TemplateMode::TableBody,
            Tag::Td | Tag::Th => TemplateMode::Row,
            _ => TemplateMode::Body,
        };
        let owner = self.near(NEAR_OWNER);
        self.at_mut(owner).template = mode;
        None
    }

    // --- end tags -------------------------------------------------------

    /// Applies an end tag.
    pub(super) fn end_tag(&mut self, tag: &EndTag<'_>) -> EndOutcome {
        let kind = self.classify(tag.name_hash(), tag.name());
        let name = TagName::of_end(tag);
        match self.mode {
            ScopeMode::Browser => self.browser_end(kind, name),
            ScopeMode::NearestMatch => EndOutcome::closed(self.pop_to(self.html_named(kind, name))),
        }
    }

    // Kept out of line: inlining every mode into one entry point slows both.
    #[inline(never)]
    fn browser_end(&mut self, kind: Tag, name: TagName<'_>) -> EndOutcome {
        self.leave_initial();
        let cur = self.cur();
        // The tokenizer emits only the matching end tag while in a text
        // element. Its close uses the text insertion mode, irrespective of
        // the enclosing head/table/template mode. No separate mode frame is
        // needed: popping restores the enclosing mode automatically.
        if cur.is_html() && cur.tag == kind && text_mode_of(kind).is_some() {
            self.pop();
            return EndOutcome::closed(1);
        }
        if !cur.is_html() {
            if matches!(kind, Tag::Br | Tag::P) {
                self.pop_out_of_foreign();
            } else {
                // Walk down the foreign elements for a same-name one; reaching
                // an HTML element hands the tag to the HTML rules.
                let foreign = self.foreign_top(self.name_id(kind, name));
                if foreign > self.near(NEAR_HTML) {
                    return EndOutcome::closed(self.pop_to(foreign));
                }
            }
        }
        self.html_end(kind, name)
    }

    fn html_end(&mut self, kind: Tag, name: TagName<'_>) -> EndOutcome {
        loop {
            self.count_work();
            let done = match self.insertion_mode() {
                Mode::Initial => {
                    if matches!(kind, Tag::Head | Tag::Body | Tag::Html | Tag::Br) {
                        self.phase = Phase::BeforeHead;
                        self.push_implied(Tag::Html);
                        None
                    } else {
                        Some(EndOutcome::IGNORED)
                    }
                }
                Mode::BeforeHead => {
                    if matches!(kind, Tag::Head | Tag::Body | Tag::Html | Tag::Br) {
                        self.push_implied(Tag::Head);
                        None
                    } else {
                        Some(EndOutcome::IGNORED)
                    }
                }
                Mode::InHead => self.end_in_head(kind),
                Mode::AfterHead => match kind {
                    Tag::Template => Some(self.end_template()),
                    Tag::Body | Tag::Html | Tag::Br => {
                        self.push_implied(Tag::Body);
                        self.phase = Phase::InBody;
                        None
                    }
                    _ => Some(EndOutcome::IGNORED),
                },
                Mode::InBody => Some(self.end_in_body(kind, name, false)),
                Mode::InTable => Some(self.end_in_table(kind, name)),
                Mode::InTableBody => self.end_in_table_body(kind, name),
                Mode::InRow => self.end_in_row(kind, name),
                Mode::InCell => self.end_in_cell(kind, name),
                Mode::InCaption => self.end_in_caption(kind, name),
                Mode::InColumnGroup => self.end_in_column_group(kind),
                Mode::InTemplate => Some(if kind == Tag::Template {
                    self.end_template()
                } else {
                    EndOutcome::IGNORED
                }),
            };
            if let Some(outcome) = done {
                return outcome;
            }
        }
    }

    fn end_in_head(&mut self, kind: Tag) -> Option<EndOutcome> {
        match kind {
            Tag::Head => Some(EndOutcome::closed(self.pop_head())),
            Tag::Body | Tag::Html | Tag::Br => {
                self.pop_head();
                None
            }
            Tag::Template => Some(self.end_template()),
            _ => Some(EndOutcome::IGNORED),
        }
    }

    fn end_template(&mut self) -> EndOutcome {
        EndOutcome::closed(self.pop_to(self.known(Tag::Template)))
    }

    fn close_named(&mut self, tag: Tag, kind: usize) -> EndOutcome {
        EndOutcome::closed(self.close_in_scope(tag, kind))
    }

    /// Counts an element browsers create for an end tag (`</p>` without an
    /// open p, `</br>`): it takes a sibling position.
    fn count_tagless_element(&mut self, tag: Tag, foster: bool) {
        let slot = self.slot(foster);
        self.place(slot, NameId::known(tag));
    }

    fn end_in_body(&mut self, kind: Tag, name: TagName<'_>, foster: bool) -> EndOutcome {
        match kind {
            Tag::Template => self.end_template(),
            Tag::Body | Tag::Html => {
                let body = self.known(Tag::Body);
                if !self.in_scope(body, NEAR_SCOPE) {
                    return EndOutcome::IGNORED;
                }
                let html = if kind == Tag::Html {
                    self.known(Tag::Html)
                } else {
                    0
                };
                EndOutcome {
                    closes_named: false,
                    anchors: [body, html],
                }
            }
            Tag::Address
            | Tag::Article
            | Tag::Aside
            | Tag::Blockquote
            | Tag::Button
            | Tag::Center
            | Tag::Details
            | Tag::Dialog
            | Tag::Dir
            | Tag::Div
            | Tag::Dl
            | Tag::Fieldset
            | Tag::Figcaption
            | Tag::Figure
            | Tag::Footer
            | Tag::Header
            | Tag::Hgroup
            | Tag::Listing
            | Tag::Main
            | Tag::Menu
            | Tag::Nav
            | Tag::Ol
            | Tag::Pre
            | Tag::Search
            | Tag::Section
            | Tag::Summary
            | Tag::Ul
            // Established browsers close a select in scope even across
            // special elements nested in it.
            | Tag::Select
            | Tag::Applet
            | Tag::Marquee
            | Tag::Object
            | Tag::Dd
            | Tag::Dt => self.close_named(kind, NEAR_SCOPE),
            Tag::P => {
                if !self.in_scope(self.known(Tag::P), NEAR_BUTTON) {
                    // Browsers insert an empty p to close.
                    self.count_tagless_element(Tag::P, foster);
                    return EndOutcome::IGNORED;
                }
                self.close_named(kind, NEAR_BUTTON)
            }
            Tag::Li => self.close_named(kind, NEAR_LIST),
            Tag::Form => self.end_form(),
            Tag::H1 | Tag::H2 | Tag::H3 | Tag::H4 | Tag::H5 | Tag::H6 => {
                let heading = HEADINGS
                    .iter()
                    .map(|&h| self.known(h))
                    .max()
                    .unwrap_or(0);
                if self.in_scope(heading, NEAR_SCOPE) {
                    EndOutcome::closed(self.pop_to(heading))
                } else {
                    EndOutcome::IGNORED
                }
            }
            Tag::Br => {
                // Browsers treat `</br>` as `<br>`.
                self.count_tagless_element(Tag::Br, foster);
                EndOutcome::IGNORED
            }
            // "Any other end tag", and formatting elements whose adoption
            // agency run needs no restructuring.
            _ => {
                let index = self.html_named(kind, name);
                if index > 0 && index >= self.near(NEAR_SPECIAL) {
                    EndOutcome::closed(self.pop_to(index))
                } else {
                    EndOutcome::IGNORED
                }
            }
        }
    }

    fn end_form(&mut self) -> EndOutcome {
        if self.template_open() {
            return self.close_named(Tag::Form, NEAR_SCOPE);
        }
        let pointer = mem::replace(&mut self.form, FormPointer::Null);
        let FormPointer::Open(form) = pointer else {
            return EndOutcome::IGNORED;
        };
        let form = form as usize;
        if !self.in_scope(form, NEAR_SCOPE) {
            return EndOutcome::IGNORED;
        }
        self.generate_implied_end_tags(None);
        if self.top() == form {
            self.pop();
            EndOutcome::closed(1)
        } else {
            // Browsers take the form out from under its open children; it stays
            // open here until its parent closes (see `ScopeMode::Browser`).
            EndOutcome::IGNORED
        }
    }

    fn end_in_table(&mut self, kind: Tag, name: TagName<'_>) -> EndOutcome {
        match kind {
            Tag::Table => self.close_named(kind, NEAR_TABLE),
            Tag::Body
            | Tag::Caption
            | Tag::Col
            | Tag::Colgroup
            | Tag::Html
            | Tag::Tbody
            | Tag::Td
            | Tag::Tfoot
            | Tag::Th
            | Tag::Thead
            | Tag::Tr => EndOutcome::IGNORED,
            Tag::Template => self.end_template(),
            _ => self.end_in_body(kind, name, true),
        }
    }

    fn end_in_table_body(&mut self, kind: Tag, name: TagName<'_>) -> Option<EndOutcome> {
        match kind {
            Tag::Tbody | Tag::Tfoot | Tag::Thead => {
                if !self.in_scope(self.known(kind), NEAR_TABLE) {
                    return Some(EndOutcome::IGNORED);
                }
                self.clear_to_owner();
                Some(EndOutcome::closed(self.pop_to(self.near(NEAR_OWNER))))
            }
            Tag::Table => {
                if !self.section_in_table_scope() {
                    return Some(EndOutcome::IGNORED);
                }
                self.clear_to_owner();
                self.pop_to(self.near(NEAR_OWNER));
                None
            }
            Tag::Body
            | Tag::Caption
            | Tag::Col
            | Tag::Colgroup
            | Tag::Html
            | Tag::Td
            | Tag::Th
            | Tag::Tr => Some(EndOutcome::IGNORED),
            _ => Some(self.end_in_table(kind, name)),
        }
    }

    fn end_in_row(&mut self, kind: Tag, name: TagName<'_>) -> Option<EndOutcome> {
        let tr_in_scope = self.in_scope(self.known(Tag::Tr), NEAR_TABLE);
        match kind {
            Tag::Tr => {
                if !tr_in_scope {
                    return Some(EndOutcome::IGNORED);
                }
                self.clear_to_owner();
                Some(EndOutcome::closed(self.pop_to(self.near(NEAR_OWNER))))
            }
            Tag::Table | Tag::Tbody | Tag::Tfoot | Tag::Thead => {
                if kind != Tag::Table && !self.in_scope(self.known(kind), NEAR_TABLE) {
                    return Some(EndOutcome::IGNORED);
                }
                if !tr_in_scope {
                    return Some(EndOutcome::IGNORED);
                }
                self.clear_to_owner();
                self.pop_to(self.near(NEAR_OWNER));
                None
            }
            Tag::Body | Tag::Caption | Tag::Col | Tag::Colgroup | Tag::Html | Tag::Td | Tag::Th => {
                Some(EndOutcome::IGNORED)
            }
            _ => Some(self.end_in_table(kind, name)),
        }
    }

    fn end_in_cell(&mut self, kind: Tag, name: TagName<'_>) -> Option<EndOutcome> {
        match kind {
            Tag::Td | Tag::Th => Some(self.close_named(kind, NEAR_TABLE)),
            Tag::Body | Tag::Caption | Tag::Col | Tag::Colgroup | Tag::Html => {
                Some(EndOutcome::IGNORED)
            }
            Tag::Table | Tag::Tbody | Tag::Tfoot | Tag::Thead | Tag::Tr => {
                if self.in_scope(self.known(kind), NEAR_TABLE) {
                    self.pop_to(self.near(NEAR_OWNER));
                    None
                } else {
                    Some(EndOutcome::IGNORED)
                }
            }
            _ => Some(self.end_in_body(kind, name, false)),
        }
    }

    fn end_in_caption(&mut self, kind: Tag, name: TagName<'_>) -> Option<EndOutcome> {
        match kind {
            Tag::Caption => Some(EndOutcome::closed(self.pop_to(self.near(NEAR_OWNER)))),
            Tag::Table => {
                self.pop_to(self.near(NEAR_OWNER));
                None
            }
            Tag::Body
            | Tag::Col
            | Tag::Colgroup
            | Tag::Html
            | Tag::Tbody
            | Tag::Td
            | Tag::Tfoot
            | Tag::Th
            | Tag::Thead
            | Tag::Tr => Some(EndOutcome::IGNORED),
            _ => Some(self.end_in_body(kind, name, false)),
        }
    }

    fn end_in_column_group(&mut self, kind: Tag) -> Option<EndOutcome> {
        let colgroup_current = self.cur().is_html_tag(Tag::Colgroup);
        match kind {
            Tag::Colgroup => Some(if colgroup_current {
                self.pop();
                EndOutcome::closed(1)
            } else {
                EndOutcome::IGNORED
            }),
            Tag::Col => Some(EndOutcome::IGNORED),
            Tag::Template => Some(self.end_template()),
            _ if colgroup_current => {
                self.pop();
                None
            }
            _ => Some(EndOutcome::IGNORED),
        }
    }

    // --- other tokens ---------------------------------------------------

    /// Applies a text run. Returns the offset of its first byte that lands
    /// past a stack change (the text's length if none): browsers keep leading
    /// whitespace where it is, then the first other byte ends an open head or
    /// column group and starts the body.
    pub(super) fn text(&mut self, text: &[u8]) -> usize {
        // Text inside an element that does not own the insertion mode (a
        // paragraph, a head `<title>`) changes nothing.
        if self.mode != ScopeMode::Browser || self.top() != self.near(NEAR_OWNER) {
            return text.len();
        }
        let mode = self.insertion_mode();
        let sensitive = match mode {
            Mode::Initial | Mode::BeforeHead | Mode::InHead | Mode::AfterHead => true,
            Mode::InColumnGroup => self.cur().is_html_tag(Tag::Colgroup),
            _ => false,
        };
        if !sensitive {
            return text.len();
        }
        let Some(at) = text.iter().position(|&b| !is_html_space(b)) else {
            return text.len();
        };
        self.leave_initial();
        match mode {
            Mode::Initial => {
                self.push_implied(Tag::Html);
                self.push_implied(Tag::Head);
                self.pop_head();
                self.push_implied(Tag::Body);
            }
            Mode::BeforeHead => {
                self.push_implied(Tag::Head);
                self.pop_head();
                self.push_implied(Tag::Body);
            }
            Mode::InHead => {
                self.pop_head();
                self.push_implied(Tag::Body);
            }
            Mode::AfterHead => self.push_implied(Tag::Body),
            _ => self.pop(),
        }
        if mode != Mode::InColumnGroup {
            self.phase = Phase::InBody;
        }
        at
    }

    /// Decides quirks mode from a doctype seen before any other content.
    pub(super) fn doctype(&mut self, raw: &[u8]) {
        if self.mode == ScopeMode::Browser
            && self.quirks == QuirksMode::Undecided
            && self.phase == Phase::Initial
        {
            self.quirks = if doctype_is_quirky(raw) {
                QuirksMode::Quirks
            } else {
                QuirksMode::NoQuirks
            };
        }
    }

    /// Whether class and id selectors match ASCII case-insensitively, as
    /// they do in a quirks-mode document.
    pub(super) fn quirks(&self) -> bool {
        self.quirks == QuirksMode::Quirks
    }

    /// Closes everything at end of input.
    pub(super) fn finish(&mut self) {
        self.pop_to(1);
    }

    // --- nearest-match rules --------------------------------------------

    // Kept out of line: inlining every mode into one entry point slows both.
    #[inline(never)]
    fn nearest_start(&mut self, kind: Tag, self_closing: bool) -> Placement {
        match kind {
            Tag::Li => self.pop_topmost(&[Tag::Li]),
            Tag::Dd | Tag::Dt => self.pop_topmost(&[Tag::Dd, Tag::Dt]),
            Tag::Option => self.pop_topmost(&[Tag::Option]),
            Tag::Optgroup => {
                self.pop_topmost(&[Tag::Option]);
                self.pop_topmost(&[Tag::Optgroup]);
            }
            Tag::Rb | Tag::Rt | Tag::Rtc | Tag::Rp => {
                self.pop_topmost(&[Tag::Rb, Tag::Rt, Tag::Rtc, Tag::Rp]);
            }
            Tag::Tr => {
                self.pop_topmost(&[Tag::Td, Tag::Th]);
                self.pop_topmost(&[Tag::Tr]);
            }
            Tag::Td | Tag::Th => self.pop_topmost(&[Tag::Td, Tag::Th]),
            Tag::Thead | Tag::Tbody | Tag::Tfoot => {
                self.pop_topmost(&[Tag::Td, Tag::Th]);
                self.pop_topmost(&[Tag::Tr]);
                self.pop_topmost(&[Tag::Thead, Tag::Tbody, Tag::Tfoot]);
            }
            _ if nearest_closes_p(kind) => self.pop_topmost(&[Tag::P]),
            _ => {}
        }
        let slot = Slot {
            parent: self.top(),
            before: 0,
        };
        if nearest_is_void(kind) || self_closing {
            Placement::Leaf(slot)
        } else {
            Placement::Open(slot, NewElement::html(kind))
        }
    }

    fn pop_topmost(&mut self, tags: &[Tag]) {
        let index = tags.iter().map(|&tag| self.known(tag)).max().unwrap_or(0);
        self.pop_to(index);
    }

    /// Recounts every cache from scratch and panics on any disagreement.
    #[cfg(any(test, fuzzing))]
    pub(super) fn assert_consistent(&self) {
        let mut html_top: HashMap<NameId, u32> = HashMap::default();
        let mut foreign_top: HashMap<NameId, u32> = HashMap::default();
        let mut known_top = [0; TAG_COUNT];
        for (index, frame) in self.frames.iter().enumerate().skip(1) {
            let index32 = u32::try_from(index).unwrap_or(u32::MAX);
            let prev = if frame.is_html() && frame.tag != Tag::Other {
                mem::replace(&mut known_top[frame.tag as usize], index32)
            } else if frame.is_html() {
                html_top.insert(frame.name, index32).unwrap_or(0)
            } else {
                foreign_top.insert(frame.name, index32).unwrap_or(0)
            };
            assert_eq!(frame.prev_same, prev, "prev_same link of frame {index}");
            assert_eq!(
                frame.name == NameId::known(frame.tag),
                frame.tag != Tag::Other,
                "name identity of frame {index}"
            );
            let below = &self.frames[..=index];
            let nearest = |hit: &dyn Fn(&Frame) -> bool| {
                below
                    .iter()
                    .rposition(hit)
                    .map_or(0, |i| u32::try_from(i).unwrap_or(u32::MAX))
            };
            let expected = [
                nearest(&|f| f.flags & SCOPE != 0),
                nearest(&|f| f.flags & (SCOPE | LIST_SCOPE) != 0),
                nearest(&|f| f.flags & (SCOPE | BUTTON_SCOPE) != 0),
                nearest(&|f| f.flags & TABLE_SCOPE != 0),
                nearest(&|f| f.flags & SPECIAL != 0),
                nearest(&|f| f.flags & SPECIAL != 0 && f.flags & ADDRESS_DIV_P == 0),
                nearest(&|f| f.flags & OWNER != 0),
                nearest(&|f| f.is_html()),
            ];
            assert_eq!(frame.near, expected, "cached boundaries of frame {index}");
        }
        assert_eq!(
            self.html_top.len(),
            html_top.len(),
            "topmost unknown HTML frames"
        );
        for (name, index) in &html_top {
            assert_eq!(
                self.html_top.get(name),
                Some(index),
                "topmost unknown HTML frame"
            );
        }
        assert_eq!(
            self.known_top, known_top,
            "topmost known HTML frame per name"
        );
        assert_eq!(
            self.foreign_top.len(),
            foreign_top.len(),
            "topmost foreign frames"
        );
        for (name, index) in &foreign_top {
            assert_eq!(
                self.foreign_top.get(name),
                Some(index),
                "topmost foreign frame"
            );
        }
        let mut run_start = 0;
        for (index, frame) in self.frames.iter().enumerate() {
            let start = frame.types_start as usize;
            let end = self
                .frames
                .get(index + 1)
                .map_or(self.types.len(), |f| f.types_start as usize);
            assert!(
                run_start <= start && start <= end && end <= self.types.len(),
                "type count runs of frame {index} are stacked"
            );
            run_start = start;
            let run = &self.types[start..end];
            assert!(run.len() <= TYPE_RUN, "type count run of frame {index}");
            for (i, entry) in run.iter().enumerate() {
                assert!(
                    run[i + 1..].iter().all(|other| other.name != entry.name)
                        && frame
                            .types_spill
                            .as_ref()
                            .is_none_or(|spill| !spill.contains_key(&entry.name)),
                    "one type count per child type of frame {index}"
                );
            }
            assert!(
                self.tracks_type || (run.is_empty() && frame.types_spill.is_none()),
                "type counts only when tracked"
            );
        }
        assert_eq!(
            self.type_model.0.len(),
            self.frames.len(),
            "type model frames"
        );
        if let FormPointer::Open(form) = self.form {
            assert!(
                self.frames
                    .get(form as usize)
                    .is_some_and(|f| f.is_html_tag(Tag::Form)),
                "form pointer targets an open form"
            );
        }
        if self.mode == ScopeMode::Browser && self.frames.len() > 1 {
            assert!(
                self.frames[1].is_html_tag(Tag::Html),
                "html is the root element"
            );
        }
    }
}

fn nearest_is_void(kind: Tag) -> bool {
    matches!(
        kind,
        Tag::Area
            | Tag::Base
            | Tag::Br
            | Tag::Col
            | Tag::Embed
            | Tag::Hr
            | Tag::Img
            | Tag::Input
            | Tag::Link
            | Tag::Meta
            | Tag::Source
            | Tag::Track
            | Tag::Wbr
    )
}

fn nearest_closes_p(kind: Tag) -> bool {
    matches!(
        kind,
        Tag::Address
            | Tag::Article
            | Tag::Aside
            | Tag::Blockquote
            | Tag::Details
            | Tag::Div
            | Tag::Dl
            | Tag::Fieldset
            | Tag::Figcaption
            | Tag::Figure
            | Tag::Footer
            | Tag::Form
            | Tag::H1
            | Tag::H2
            | Tag::H3
            | Tag::H4
            | Tag::H5
            | Tag::H6
            | Tag::Header
            | Tag::Hgroup
            | Tag::Hr
            | Tag::Main
            | Tag::Menu
            | Tag::Nav
            | Tag::Ol
            | Tag::P
            | Tag::Pre
            | Tag::Search
            | Tag::Section
            | Tag::Table
            | Tag::Ul
    )
}

fn is_html_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\x0c' | b'\r')
}

// --- doctype → quirks mode ------------------------------------------------

/// Public identifier prefixes that put a document in quirks mode (lowercase).
const QUIRKY_PUBLIC_PREFIXES: &[&[u8]] = &[
    b"+//silmaril//dtd html pro v0r11 19970101//",
    b"-//advasoft ltd//dtd html 3.0 aswedit + extensions//",
    b"-//as//dtd html 3.0 aswedit + extensions//",
    b"-//ietf//dtd html 2.0 level 1//",
    b"-//ietf//dtd html 2.0 level 2//",
    b"-//ietf//dtd html 2.0 strict level 1//",
    b"-//ietf//dtd html 2.0 strict level 2//",
    b"-//ietf//dtd html 2.0 strict//",
    b"-//ietf//dtd html 2.0//",
    b"-//ietf//dtd html 2.1e//",
    b"-//ietf//dtd html 3.0//",
    b"-//ietf//dtd html 3.2 final//",
    b"-//ietf//dtd html 3.2//",
    b"-//ietf//dtd html 3//",
    b"-//ietf//dtd html level 0//",
    b"-//ietf//dtd html level 1//",
    b"-//ietf//dtd html level 2//",
    b"-//ietf//dtd html level 3//",
    b"-//ietf//dtd html strict level 0//",
    b"-//ietf//dtd html strict level 1//",
    b"-//ietf//dtd html strict level 2//",
    b"-//ietf//dtd html strict level 3//",
    b"-//ietf//dtd html strict//",
    b"-//ietf//dtd html//",
    b"-//metrius//dtd metrius presentational//",
    b"-//microsoft//dtd internet explorer 2.0 html strict//",
    b"-//microsoft//dtd internet explorer 2.0 html//",
    b"-//microsoft//dtd internet explorer 2.0 tables//",
    b"-//microsoft//dtd internet explorer 3.0 html strict//",
    b"-//microsoft//dtd internet explorer 3.0 html//",
    b"-//microsoft//dtd internet explorer 3.0 tables//",
    b"-//netscape comm. corp.//dtd html//",
    b"-//netscape comm. corp.//dtd strict html//",
    b"-//o'reilly and associates//dtd html 2.0//",
    b"-//o'reilly and associates//dtd html extended 1.0//",
    b"-//o'reilly and associates//dtd html extended relaxed 1.0//",
    b"-//softquad software//dtd hotmetal pro 6.0::19990601::extensions to html 4.0//",
    b"-//softquad//dtd hotmetal pro 4.0::19971010::extensions to html 4.0//",
    b"-//spyglass//dtd html 2.0 extended//",
    b"-//sq//dtd html 2.0 hotmetal + extensions//",
    b"-//sun microsystems corp.//dtd hotjava html//",
    b"-//sun microsystems corp.//dtd hotjava strict html//",
    b"-//w3c//dtd html 3 1995-03-24//",
    b"-//w3c//dtd html 3.2 draft//",
    b"-//w3c//dtd html 3.2 final//",
    b"-//w3c//dtd html 3.2//",
    b"-//w3c//dtd html 3.2s draft//",
    b"-//w3c//dtd html 4.0 frameset//",
    b"-//w3c//dtd html 4.0 transitional//",
    b"-//w3c//dtd html experimental 19960712//",
    b"-//w3c//dtd html experimental 970421//",
    b"-//w3c//dtd w3 html//",
    b"-//w3o//dtd w3 html 3.0//",
    b"-//webtechs//dtd mozilla html 2.0//",
    b"-//webtechs//dtd mozilla html//",
];

const QUIRKY_PUBLIC_IDS: &[&[u8]] = &[
    b"-//w3o//dtd w3 html strict 3.0//en//",
    b"-/w3c/dtd html 4.0 transitional/en",
    b"html",
];

const QUIRKY_SYSTEM_ID: &[u8] = b"http://www.ibm.com/data/dtd/v11/ibmxhtml1-transitional.dtd";

/// HTML 4.01 frameset/transitional: quirks without a system identifier.
const HTML4_PUBLIC_PREFIXES: &[&[u8]] = &[
    b"-//w3c//dtd html 4.01 frameset//",
    b"-//w3c//dtd html 4.01 transitional//",
];

fn starts_with_ignore_case(haystack: &[u8], prefix: &[u8]) -> bool {
    haystack
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn trim_space(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&b| !is_html_space(b))
        .unwrap_or(bytes.len());
    &bytes[start..]
}

/// A quoted identifier at the start of `bytes`, and what follows it. `None`
/// when browsers would force quirks (no quote, or an unterminated one).
fn quoted_id(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&quote, rest) = bytes.split_first()?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let end = rest.iter().position(|&b| b == quote)?;
    Some((&rest[..end], &rest[end + 1..]))
}

/// The public and system identifiers after the doctype name, or `None` when
/// the doctype is malformed enough to force quirks mode.
#[expect(
    clippy::type_complexity,
    reason = "a pair of optional identifiers reads clearest inline"
)]
fn doctype_ids(rest: &[u8]) -> Option<(Option<&[u8]>, Option<&[u8]>)> {
    if rest.is_empty() {
        return Some((None, None));
    }
    if starts_with_ignore_case(rest, b"public") {
        let (public, after) = quoted_id(trim_space(&rest[6..]))?;
        let after = trim_space(after);
        if after.is_empty() {
            return Some((Some(public), None));
        }
        let (system, _) = quoted_id(after)?;
        Some((Some(public), Some(system)))
    } else if starts_with_ignore_case(rest, b"system") {
        let (system, _) = quoted_id(trim_space(&rest[6..]))?;
        Some((None, Some(system)))
    } else {
        None
    }
}

/// Whether browsers render a document with this doctype (the raw
/// `<!doctype …>` token) in quirks mode. Limited-quirks counts as no-quirks:
/// the two only differ in rules this module does not track.
fn doctype_is_quirky(raw: &[u8]) -> bool {
    // An unterminated doctype forces quirks.
    let Some(body) = raw.strip_suffix(b">") else {
        return true;
    };
    let rest = trim_space(body.get(b"<!doctype".len()..).unwrap_or_default());
    let name_end = rest
        .iter()
        .position(|&b| is_html_space(b))
        .unwrap_or(rest.len());
    let (name, rest) = rest.split_at(name_end);
    if !name.eq_ignore_ascii_case(b"html") {
        return true;
    }
    let Some((public, system)) = doctype_ids(trim_space(rest)) else {
        return true;
    };
    // Chromium and WebKit treat an empty system identifier as missing.
    let system = system.filter(|system| !system.is_empty());
    if let Some(system) = system
        && system.eq_ignore_ascii_case(QUIRKY_SYSTEM_ID)
    {
        return true;
    }
    let Some(public) = public else {
        return false;
    };
    QUIRKY_PUBLIC_IDS
        .iter()
        .any(|id| public.eq_ignore_ascii_case(id))
        || QUIRKY_PUBLIC_PREFIXES
            .iter()
            .any(|prefix| starts_with_ignore_case(public, prefix))
        || (system.is_none()
            && HTML4_PUBLIC_PREFIXES
                .iter()
                .any(|prefix| starts_with_ignore_case(public, prefix)))
}

#[cfg(test)]
mod tests {
    use quickcheck_macros::quickcheck;

    use super::*;
    use crate::protocols::html::tokenizer::{Doctype, Span, Text, TokenSink, tokenize};

    struct TreeSink {
        tree: OpenElements,
        ends: Vec<EndOutcome>,
        plans: Vec<Placement>,
    }

    impl TreeSink {
        fn tags(&self) -> Vec<Tag> {
            self.tree.frames.iter().skip(1).map(|f| f.tag).collect()
        }

        fn origins(&self) -> Vec<Origin> {
            self.tree.frames.iter().skip(1).map(|f| f.origin).collect()
        }
    }

    impl TokenSink for TreeSink {
        fn start_tag(&mut self, tag: &StartTag<'_>) {
            let plan = self.tree.start_tag(tag);
            match plan.placement {
                Placement::Open(slot, element) => {
                    let positions = self.tree.place(slot, plan.name);
                    self.tree.push(plan.name, element, positions);
                }
                Placement::Leaf(slot) => {
                    self.tree.place(slot, plan.name);
                }
                Placement::Dropped | Placement::Merged { .. } => {}
            }
            self.plans.push(plan.placement);
            self.tree.assert_consistent();
        }

        fn end_tag(&mut self, tag: &EndTag<'_>) {
            self.ends.push(self.tree.end_tag(tag));
            self.tree.assert_consistent();
        }

        fn text(&mut self, text: &Text<'_>) {
            self.tree.text(text.raw());
            self.tree.assert_consistent();
        }

        fn doctype(&mut self, tag: &Doctype<'_>) {
            self.tree.doctype(tag.raw());
        }
    }

    fn parse(html: &str) -> TreeSink {
        let mut sink = TreeSink {
            tree: OpenElements::new(),
            ends: Vec::new(),
            plans: Vec::new(),
        };
        sink.tree.tracks_type = true;
        tokenize(html.as_bytes(), &mut sink).unwrap();
        sink
    }

    #[test]
    fn text_element_end_tags_restore_the_enclosing_insertion_mode() {
        for tag in ["title", "style", "script", "noscript", "noframes"] {
            let sink = parse(&format!("<head><{tag}>text</{tag}><meta>"));
            assert_eq!(sink.ends, [EndOutcome::closed(1)], "{tag}");
            assert_eq!(sink.tree.cur().tag, Tag::Head, "{tag}");
        }
        for tag in ["title", "style", "script"] {
            let sink = parse(&format!("<template><{tag}>text</{tag}>"));
            assert_eq!(sink.ends, [EndOutcome::closed(1)], "{tag}");
            assert_eq!(sink.tree.cur().tag, Tag::Template, "{tag}");
        }
        for tag in ["style", "script"] {
            let sink = parse(&format!("<table><{tag}>text</{tag}>"));
            assert_eq!(sink.ends, [EndOutcome::closed(1)], "{tag}");
            assert_eq!(sink.tree.cur().tag, Tag::Table, "{tag}");
        }
    }

    #[test]
    fn implied_end_tags_include_paragraphs() {
        let sink = parse("<form><p>text</form>");
        assert_eq!(sink.ends, [EndOutcome::closed(1)]);
        assert_eq!(sink.tags(), [Tag::Html, Tag::Body]);

        let sink = parse("<ruby><p>text<rt>");
        assert_eq!(sink.tree.known(Tag::P), 0);
        assert_eq!(sink.tags(), [Tag::Html, Tag::Body, Tag::Ruby, Tag::Rt]);
    }

    #[test]
    fn namespace_integration_uses_first_decoded_encoding_attribute() {
        for (attrs, namespace) in [
            ("encoding='text&#47;html'", Ns::Html),
            ("encoding='text&#47html'", Ns::Html),
            ("encoding='text&sol;html'", Ns::Html),
            ("encoding='TEXT/HTML'", Ns::Html),
            ("encoding='application/xhtml&#x2b;xml'", Ns::Html),
            ("encoding='application/xhtml&plus;xml'", Ns::Html),
            ("encoding='x' encoding='text/html'", Ns::MathMl),
            ("encoding='text/html' encoding='x'", Ns::Html),
            ("encoding='text&sol html'", Ns::MathMl),
        ] {
            let sink = parse(&format!("<math><annotation-xml {attrs}><custom>"));
            assert_eq!(sink.tree.cur().ns, namespace, "{attrs}");
        }
    }

    /// Elements browsers create without a tag are frames, created where
    /// browsers create them.
    #[test]
    fn implied_elements_are_frames() {
        use Origin::{Implied as I, Tag as T};
        for (html, tags, origins) in [
            ("", vec![], vec![]),
            ("  \n", vec![], vec![]),
            ("<!--c-->", vec![], vec![]),
            ("x", vec![Tag::Html, Tag::Body], vec![I, I]),
            ("<title>t</title>", vec![Tag::Html, Tag::Head], vec![I, I]),
            ("<title>t</title>x", vec![Tag::Html, Tag::Body], vec![I, I]),
            ("<html><head></head>", vec![Tag::Html], vec![T]),
            ("<html> <head> </head> ", vec![Tag::Html], vec![T]),
            ("<p>", vec![Tag::Html, Tag::Body, Tag::P], vec![I, I, T]),
            ("</p>", vec![], vec![]),
            ("</br>", vec![Tag::Html, Tag::Body], vec![I, I]),
            ("</head>", vec![Tag::Html], vec![I]),
            ("</body>", vec![Tag::Html, Tag::Body], vec![I, I]),
            (
                "<table><tr><td>",
                vec![
                    Tag::Html,
                    Tag::Body,
                    Tag::Table,
                    Tag::Tbody,
                    Tag::Tr,
                    Tag::Td,
                ],
                vec![I, I, T, I, T, T],
            ),
            (
                "<table><td>",
                vec![
                    Tag::Html,
                    Tag::Body,
                    Tag::Table,
                    Tag::Tbody,
                    Tag::Tr,
                    Tag::Td,
                ],
                vec![I, I, T, I, I, T],
            ),
            (
                "<table><col>",
                vec![Tag::Html, Tag::Body, Tag::Table, Tag::Colgroup],
                vec![I, I, T, I],
            ),
            (
                "<template><td>",
                vec![Tag::Html, Tag::Head, Tag::Template, Tag::Td],
                vec![I, I, T, T],
            ),
            (
                "<template><caption></caption><tr>",
                vec![Tag::Html, Tag::Head, Tag::Template, Tag::Tbody, Tag::Tr],
                vec![I, I, T, I, T],
            ),
        ] {
            let sink = parse(html);
            assert_eq!(sink.tags(), tags, "{html:?}");
            assert_eq!(sink.origins(), origins, "{html:?}");
        }
    }

    /// A late `<html>` / `<body>` (or a `<head>` for the head browsers made)
    /// names the open element; only the first tag naming an implied one
    /// claims it, so handlers never run twice for one element.
    #[test]
    fn late_tags_merge_into_open_elements() {
        for (html, last) in [
            ("x<body class=b>", Some((2, true))),
            ("<body>x<body class=b>", Some((2, false))),
            ("<body class=a><p><body id=b>", Some((2, false))),
            ("<meta charset=utf-8><html lang=x>", Some((1, true))),
            ("<html><html lang=x>", Some((1, false))),
            ("x<html lang=x>", Some((1, true))),
            ("<meta><head class=h>", Some((2, true))),
            ("<head><head class=h>", None),
            ("<head></head><head class=h>", None),
            ("x<head>", None),
            ("<template><body>", None),
            ("<template><html>", None),
            ("<table><tr><td><body class=b>", Some((2, true))),
            ("<div><html lang=x>", Some((1, true))),
        ] {
            let sink = parse(html);
            let got = match sink.plans.last() {
                Some(&Placement::Merged { frame, claim }) => Some((frame, claim)),
                _ => None,
            };
            assert_eq!(got, last, "{html:?}");
        }
        // The browser case: a late body after head content still claims the
        // body browsers created.
        let sink = parse("<html><head></head><noscript>n</noscript><body class=b>t");
        assert!(matches!(
            sink.plans.last(),
            Some(Placement::Merged {
                frame: 2,
                claim: true
            })
        ));
    }

    /// Tags browsers still insert into the head after `</head>` land in it.
    #[test]
    fn head_tags_after_the_head_reopen_it() {
        let sink = parse("<head><meta></head><script>s</script><link>");
        assert_eq!(sink.tags(), [Tag::Html, Tag::Head]);
        assert_eq!(sink.origins(), [Origin::Implied, Origin::Reopened]);
        // meta, script, link: the head's child count carries over.
        assert_eq!(sink.tree.cur().child_count, 3);
        let sink = parse("<head></head><style>s</style><div>");
        assert_eq!(sink.tags(), [Tag::Html, Tag::Body, Tag::Div]);
        // The body is still the html element's second child.
        assert_eq!(sink.tree.frames[2].position, 2);
    }

    /// Whitespace before body content stays where it is; the first other
    /// byte is where the head (or a colgroup) ends.
    #[test]
    fn text_reports_where_the_stack_changes() {
        for (prefix, text, at, after) in [
            ("<head>", "  x", 2, vec![Tag::Html, Tag::Body]),
            ("<head>", "   ", 3, vec![Tag::Html, Tag::Head]),
            ("", "\n\t x", 3, vec![Tag::Html, Tag::Body]),
            ("<html>", " x", 1, vec![Tag::Html, Tag::Body]),
            ("<head></head>", " \n x", 3, vec![Tag::Html, Tag::Body]),
            (
                "<table><colgroup>",
                " x",
                1,
                vec![Tag::Html, Tag::Body, Tag::Table],
            ),
            (
                "<template><col>",
                " x",
                2,
                vec![Tag::Html, Tag::Head, Tag::Template],
            ),
            ("<body>", " x", 2, vec![Tag::Html, Tag::Body]),
            (
                "<head><title>",
                " x",
                2,
                vec![Tag::Html, Tag::Head, Tag::Title],
            ),
        ] {
            let mut sink = parse(prefix);
            assert_eq!(sink.tree.text(text.as_bytes()), at, "{prefix:?} + {text:?}");
            assert_eq!(sink.tags(), after, "{prefix:?} + {text:?}");
            sink.tree.assert_consistent();
        }
    }

    #[test]
    fn foster_parented_elements_take_the_tables_position() {
        // <span> and <b> go in front of the table, in order.
        let sink = parse("<div><a></a><table><span></span><b>");
        assert_eq!(sink.tree.cur().tag, Tag::B);
        assert_eq!(sink.tree.cur().position, 3);
        let table = sink.tree.known(Tag::Table);
        assert_eq!(sink.tree.at(table).position, 4);
    }

    #[test]
    fn tagless_elements_from_end_tags_take_sibling_positions() {
        // `</p>` with no open p, and `</br>`, each create an element.
        let sink = parse("<div></p></br><span>");
        assert_eq!(sink.tree.cur().tag, Tag::Span);
        assert_eq!(sink.tree.cur().position, 3);
    }

    #[test]
    fn cdata_follows_the_current_node() {
        for (html, allowed) in [
            ("", false),
            ("<div>", false),
            ("<svg>", true),
            ("<svg/>", false),
            ("<math><mi>", false),
            ("<math><mi><b>", false),
            ("<svg><foreignObject>", false),
            ("<svg><foreignObject><div><svg>", true),
            ("<math><annotation-xml>", true),
            ("<math><annotation-xml encoding=text/html>", false),
            ("<math><svg>", true),
            ("<math><svg><desc>", true),
            ("<svg><desc>", false),
            ("<svg><p>", false),
        ] {
            assert_eq!(parse(html).tree.cdata_allowed(), allowed, "{html:?}");
        }
    }

    #[test]
    fn text_modes_follow_the_tree() {
        let style = LocalNameHash::of(b"style");
        for (html, raw) in [
            ("", true),
            ("<svg>", false),
            ("<svg/>", true),
            ("<math/>", true),
            ("<svg><desc>", true),
            ("<svg><title>", true),
            ("<math><mi>", true),
            ("<math><svg>", false),
            ("<math><svg><desc>", false),
            ("<math><annotation-xml encoding=text/html>", true),
            ("<math><annotation-xml>", false),
            ("<p><span><svg></span>", true),
            ("<template><col>", false),
            ("<table><colgroup>", true),
            ("<table><col>", true),
            ("<select>", true),
            ("<head></head>", true),
            ("<frameset>", true),
        ] {
            let mut tree = parse(html).tree;
            assert_eq!(tree.text_mode(style, b"style").is_some(), raw, "{html:?}");
            // A crafted long name sharing a text-mode tag's hash never switches.
            let plaintext = LocalNameHash::of(b"plaintext");
            assert_eq!(tree.text_mode(plaintext, b"plaintexx"), None, "{html:?}");
        }
    }

    // --- crafted name hashes -------------------------------------------------

    /// Hands the tree every tag named `x-<known>` with the hash of `<known>`
    /// when that is a hashed (long) identity: a crafted 64-bit FNV collision
    /// (easy to find offline). Short names are their own identity.
    struct Forging(TreeSink);

    fn forged(tag_name: &[u8], hash: LocalNameHash) -> LocalNameHash {
        match tag_name.strip_prefix(b"x-") {
            Some(known) if !known.starts_with(b"x-") && !LocalNameHash::of(known).is_exact() => {
                LocalNameHash::of(known)
            }
            _ => hash,
        }
    }

    impl TokenSink for Forging {
        fn start_tag(&mut self, tag: &StartTag<'_>) {
            let forged = StartTag {
                name_hash: forged(tag.name(), tag.name_hash),
                ..*tag
            };
            self.0.start_tag(&forged);
        }

        fn end_tag(&mut self, tag: &EndTag<'_>) {
            let forged = EndTag {
                name_hash: forged(tag.name(), tag.name_hash),
                ..*tag
            };
            self.0.end_tag(&forged);
        }

        fn text(&mut self, text: &Text<'_>) {
            self.0.text(text);
        }
    }

    /// A name sharing a known tag's hash behaves as the unknown name it is,
    /// and an unknown name sharing another's hash never closes it.
    #[test]
    fn crafted_hash_collisions_change_nothing() {
        for html in [
            "<div class=x><x-plaintext></div>secret</x-plaintext>tail",
            "<p><x-blockquote><x-figcaption>a</x-figcaption></x-blockquote><p>b",
            "<svg><x-foreignobject><p>c</p></x-foreignobject><desc>d</svg>",
            "<math><x-annotation-xml encoding=text/html><p>e</x-annotation-xml></math>",
            "<math><mi><x-malignmark>f</x-malignmark><b>g</math>",
            "<table><x-figcaption><x-blockquote>h</table>",
            "<x-x-long-name-a><x-x-long-name-b>i</x-long-name-a>j",
        ] {
            let plain = parse(html);
            let mut forging = Forging(TreeSink {
                tree: OpenElements::new(),
                ends: Vec::new(),
                plans: Vec::new(),
            });
            forging.0.tree.tracks_type = true;
            tokenize(html.as_bytes(), &mut forging).unwrap();
            assert_eq!(forging.0.tags(), plain.tags(), "{html}");
            assert_eq!(forging.0.ends, plain.ends, "{html}");
            let positions = |sink: &TreeSink| -> Vec<_> {
                sink.tree
                    .frames
                    .iter()
                    .map(|f| (f.position, f.type_position, f.child_count))
                    .collect()
            };
            assert_eq!(positions(&forging.0), positions(&plain), "{html}");
        }
        // `</x-long-name-b>` hashing like the open `<x-long-name-a>` leaves it
        // open.
        let mut forging = Forging(TreeSink {
            tree: OpenElements::new(),
            ends: Vec::new(),
            plans: Vec::new(),
        });
        tokenize(b"<x-long-name-a>", &mut forging).unwrap();
        let alias = EndTag {
            input: b"</x-long-name-b>",
            raw: Span::new(0, 16),
            name: Span::new(2, 15),
            name_hash: LocalNameHash::of(b"x-long-name-a"),
        };
        forging.0.end_tag(&alias);
        assert_eq!(forging.0.tags(), [Tag::Html, Tag::Body, Tag::Other]);
    }

    fn tag_name(bytes: &[u8]) -> TagName<'_> {
        TagName {
            hash: LocalNameHash::of(bytes),
            bytes,
        }
    }

    /// Long unknown names are told apart by a hash keyed per document, so an
    /// attacker cannot precompute two names that alias.
    #[test]
    fn unknown_name_identity_is_keyed_per_document() {
        let (a, b) = (OpenElements::new(), OpenElements::new());
        let long = tag_name(b"x-long-name");
        assert_ne!(a.name_id(Tag::Other, long), b.name_id(Tag::Other, long));
        assert_eq!(
            a.name_id(Tag::Other, tag_name(b"X-LONG-NAME")),
            a.name_id(Tag::Other, long)
        );
        assert_ne!(
            a.name_id(Tag::Other, long),
            a.name_id(Tag::Other, tag_name(b"x-long-namf"))
        );
        // Short names are their own bytes: no two can alias.
        assert_eq!(
            a.name_id(Tag::Other, tag_name(b"x-a")),
            b.name_id(Tag::Other, tag_name(b"X-A"))
        );
        for (x, y) in [
            (&b"a"[..], &b"a\0"[..]),
            (b"ab", b"ba"),
            (b"abcdefgh", b"abcdefg"),
        ] {
            assert_ne!(
                a.name_id(Tag::Other, tag_name(x)),
                a.name_id(Tag::Other, tag_name(y))
            );
        }
        // Known tags have one identity, whatever the document.
        for (tag, name) in [
            (Tag::Div, &b"DIV"[..]),
            (Tag::Blockquote, b"BlockQuote"),
            (Tag::AnnotationXml, b"annotation-XML"),
        ] {
            assert_eq!(a.name_id(tag, tag_name(name)), NameId::known(tag));
            assert_eq!(b.name_id(tag, tag_name(name)), NameId::known(tag));
        }
        // The three spaces never meet.
        let ids = [
            a.name_id(Tag::Xmp, tag_name(b"xmp")),
            a.name_id(Tag::Other, tag_name(b"abcdefgh")),
            a.name_id(Tag::Figcaption, tag_name(b"figcaption")),
            a.name_id(Tag::Other, long),
        ];
        assert!(
            ids[0].0 >> 63 == 0
                && ids[1].0 >> 63 == 0
                && ids[2].0 >> 62 == 0b10
                && ids[3].0 >> 62 == 0b11
        );
    }

    // --- doctype → quirks ---------------------------------------------------

    #[test]
    fn doctypes_decide_quirks_like_chromium() {
        for (doctype, quirky) in [
            ("<!DOCTYPE html>", false),
            ("<!doctype html>", false),
            ("<!DOCTYPE>", true),
            ("<!DOCTYPE htmlx>", true),
            ("<!DOCTYPE html x>", true),
            ("<!DOCTYPE html PUBLIC>", true),
            ("<!DOCTYPE html SYSTEM>", true),
            ("<!DOCTYPE html PUBLIC \"\">", false),
            ("<!DOCTYPE html PUBLIC \"HTML\">", true),
            ("<!DOCTYPE html PUBLIC 'html'>", true),
            ("<!DOCTYPE html SYSTEM \"about:legacy-compat\">", false),
            (
                "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">",
                true,
            ),
            (
                "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">",
                false,
            ),
            (
                "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Frameset//EN\" \"\">",
                true,
            ),
            (
                "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01 Frameset//EN\" ''>",
                true,
            ),
            (
                "<!DOCTYPE html SYSTEM \"http://www.ibm.com/data/dtd/v11/ibmxhtml1-transitional.dtd\">",
                true,
            ),
            (
                "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">",
                true,
            ),
            (
                "<!DOCTYPE HTML PUBLIC \"-//W3O//DTD W3 HTML Strict 3.0//EN//\">",
                true,
            ),
            ("<!DOCTYPE html PUBLIC 'x>", true),
            ("<!DOCTYPE html", true),
        ] {
            assert_eq!(doctype_is_quirky(doctype.as_bytes()), quirky, "{doctype}");
        }
        // Only a doctype ahead of all other content counts.
        assert!(!parse("<!DOCTYPE html><p>").tree.quirks());
        assert!(parse("<!--c--><p>").tree.quirks());
        assert!(!parse("<!--c-->\n<!DOCTYPE html><p>").tree.quirks());
        assert!(parse("x<!DOCTYPE html><p>").tree.quirks());
    }

    // --- reference model ----------------------------------------------------

    // Independent, deliberately linear reference for the body rules exercised
    // below. It does not use flags, name maps, cached boundaries or production
    // close helpers; its element categories are the spec lists, written out.
    struct ScopeOracle {
        tree: OpenElements,
        /// The frames below the generated tokens (html, body, a table prefix).
        base: Vec<Tag>,
        stack: Vec<Tag>,
    }

    /// The "has an element in scope" boundaries.
    fn ref_scope(tag: Tag) -> bool {
        matches!(
            tag,
            Tag::Applet
                | Tag::Caption
                | Tag::Html
                | Tag::Table
                | Tag::Td
                | Tag::Th
                | Tag::Marquee
                | Tag::Object
                | Tag::Template
                | Tag::Select
        )
    }

    /// The special category (HTML elements; no foreign content here), as
    /// Chromium and WebKit apply it: `search` and `dialog` are not special.
    fn ref_special(tag: Tag) -> bool {
        matches!(
            tag,
            Tag::Address
                | Tag::Applet
                | Tag::Area
                | Tag::Article
                | Tag::Aside
                | Tag::Base
                | Tag::Basefont
                | Tag::Bgsound
                | Tag::Blockquote
                | Tag::Body
                | Tag::Br
                | Tag::Button
                | Tag::Caption
                | Tag::Center
                | Tag::Col
                | Tag::Colgroup
                | Tag::Dd
                | Tag::Details
                | Tag::Dir
                | Tag::Div
                | Tag::Dl
                | Tag::Dt
                | Tag::Embed
                | Tag::Fieldset
                | Tag::Figcaption
                | Tag::Figure
                | Tag::Footer
                | Tag::Form
                | Tag::Frame
                | Tag::Frameset
                | Tag::H1
                | Tag::H2
                | Tag::H3
                | Tag::H4
                | Tag::H5
                | Tag::H6
                | Tag::Head
                | Tag::Header
                | Tag::Hgroup
                | Tag::Hr
                | Tag::Html
                | Tag::Iframe
                | Tag::Img
                | Tag::Input
                | Tag::Keygen
                | Tag::Li
                | Tag::Link
                | Tag::Listing
                | Tag::Main
                | Tag::Marquee
                | Tag::Menu
                | Tag::Meta
                | Tag::Nav
                | Tag::Noembed
                | Tag::Noframes
                | Tag::Noscript
                | Tag::Object
                | Tag::Ol
                | Tag::P
                | Tag::Param
                | Tag::Plaintext
                | Tag::Pre
                | Tag::Script
                | Tag::Section
                | Tag::Select
                | Tag::Source
                | Tag::Style
                | Tag::Summary
                | Tag::Table
                | Tag::Tbody
                | Tag::Td
                | Tag::Template
                | Tag::Textarea
                | Tag::Tfoot
                | Tag::Th
                | Tag::Thead
                | Tag::Title
                | Tag::Tr
                | Tag::Track
                | Tag::Ul
                | Tag::Wbr
                | Tag::Xmp
        )
    }

    /// "Generate implied end tags" membership.
    fn ref_implied_end(tag: Tag) -> bool {
        matches!(
            tag,
            Tag::Dd
                | Tag::Dt
                | Tag::Li
                | Tag::Optgroup
                | Tag::Option
                | Tag::P
                | Tag::Rb
                | Tag::Rp
                | Tag::Rt
                | Tag::Rtc
        )
    }

    /// Block starts that close a p in button scope.
    fn ref_closes_p(tag: Tag) -> bool {
        matches!(
            tag,
            Tag::Address
                | Tag::Article
                | Tag::Aside
                | Tag::Blockquote
                | Tag::Center
                | Tag::Details
                | Tag::Dialog
                | Tag::Dir
                | Tag::Div
                | Tag::Dl
                | Tag::Fieldset
                | Tag::Figcaption
                | Tag::Figure
                | Tag::Footer
                | Tag::Header
                | Tag::Hgroup
                | Tag::Main
                | Tag::Menu
                | Tag::Nav
                | Tag::Ol
                | Tag::P
                | Tag::Search
                | Tag::Section
                | Tag::Summary
                | Tag::Ul
                | Tag::Pre
                | Tag::Listing
        )
    }

    impl ScopeOracle {
        /// Index of the topmost `wanted` element reachable before a
        /// `boundary` (a boundary that is itself wanted is reachable).
        fn find(
            &self,
            wanted: impl Fn(Tag) -> bool,
            boundary: impl Fn(Tag) -> bool,
        ) -> Option<usize> {
            for index in (0..self.stack.len()).rev() {
                let tag = self.stack[index];
                if wanted(tag) {
                    return Some(index);
                }
                if boundary(tag) {
                    return None;
                }
            }
            // The base frames (html, body, table parts) end every walk; only
            // the body rules' own boundaries matter.
            None
        }

        fn close(&mut self, wanted: impl Fn(Tag) -> bool, boundary: impl Fn(Tag) -> bool) {
            if let Some(index) = self.find(wanted, boundary) {
                self.stack.truncate(index);
            }
        }

        fn close_p(&mut self) {
            self.close(|t| t == Tag::P, |t| ref_scope(t) || t == Tag::Button);
        }

        fn in_scope(&self, wanted: impl Fn(Tag) -> bool) -> bool {
            self.find(wanted, ref_scope).is_some()
        }

        fn implied_ends(&mut self, except: Option<Tag>) {
            while let Some(&top) = self.stack.last() {
                if !ref_implied_end(top) || Some(top) == except {
                    break;
                }
                self.stack.pop();
            }
        }

        fn check(&self) {
            let actual: Vec<_> = self.tree.frames.iter().skip(1).map(|f| f.tag).collect();
            let mut expected = self.base.clone();
            expected.extend_from_slice(&self.stack);
            assert_eq!(actual, expected);
        }
    }

    impl TokenSink for ScopeOracle {
        fn start_tag(&mut self, tag: &StartTag<'_>) {
            let kind = classify(tag.name_hash(), tag.name());
            let mut push = true;
            match kind {
                Tag::Li => {
                    let stop =
                        |t: Tag| ref_special(t) && !matches!(t, Tag::Address | Tag::Div | Tag::P);
                    self.close(|t| t == Tag::Li, stop);
                    self.close_p();
                }
                Tag::Dd | Tag::Dt => {
                    let stop =
                        |t: Tag| ref_special(t) && !matches!(t, Tag::Address | Tag::Div | Tag::P);
                    self.close(|t| matches!(t, Tag::Dd | Tag::Dt), stop);
                    self.close_p();
                }
                Tag::Button => self.close(|t| t == Tag::Button, ref_scope),
                Tag::H1 | Tag::H2 | Tag::H3 | Tag::H4 | Tag::H5 | Tag::H6 => {
                    self.close_p();
                    if self.stack.last().is_some_and(|&t| is_heading(t)) {
                        self.stack.pop();
                    }
                }
                Tag::Select => {
                    if let Some(index) = self.find(|t| t == Tag::Select, ref_scope) {
                        self.stack.truncate(index);
                        push = false;
                    }
                }
                Tag::Option | Tag::Optgroup => {
                    if self.in_scope(|t| t == Tag::Select) {
                        let except = (kind == Tag::Option).then_some(Tag::Optgroup);
                        self.implied_ends(except);
                    } else if self.stack.last() == Some(&Tag::Option) {
                        self.stack.pop();
                    }
                }
                Tag::Rb | Tag::Rtc | Tag::Rp | Tag::Rt => {
                    if self.in_scope(|t| t == Tag::Ruby) {
                        let except = matches!(kind, Tag::Rp | Tag::Rt).then_some(Tag::Rtc);
                        self.implied_ends(except);
                    }
                }
                Tag::Hr => {
                    self.close_p();
                    if self.in_scope(|t| t == Tag::Select) {
                        self.implied_ends(None);
                    }
                    push = false;
                }
                Tag::Br | Tag::Img => push = false,
                _ if ref_closes_p(kind) => self.close_p(),
                _ => {}
            }
            if push {
                self.stack.push(kind);
            }
            let plan = self.tree.start_tag(tag);
            match plan.placement {
                Placement::Open(slot, element) => {
                    let positions = self.tree.place(slot, plan.name);
                    self.tree.push(plan.name, element, positions);
                }
                Placement::Leaf(slot) => {
                    self.tree.place(slot, plan.name);
                }
                Placement::Dropped | Placement::Merged { .. } => {}
            }
            self.check();
        }

        fn end_tag(&mut self, tag: &EndTag<'_>) {
            let kind = classify(tag.name_hash(), tag.name());
            match kind {
                Tag::P => self.close(|t| t == Tag::P, |t| ref_scope(t) || t == Tag::Button),
                Tag::Li => self.close(
                    |t| t == Tag::Li,
                    |t| ref_scope(t) || matches!(t, Tag::Ul | Tag::Ol),
                ),
                Tag::H1 | Tag::H2 | Tag::H3 | Tag::H4 | Tag::H5 | Tag::H6 => {
                    self.close(is_heading, ref_scope);
                }
                Tag::Br | Tag::Body | Tag::Html => {}
                _ if ref_closes_p(kind)
                    || matches!(
                        kind,
                        Tag::Button
                            | Tag::Select
                            | Tag::Applet
                            | Tag::Marquee
                            | Tag::Object
                            | Tag::Dd
                            | Tag::Dt
                    ) =>
                {
                    self.close(|t| t == kind, ref_scope);
                }
                // "Any other end tag": formatting, ruby, option and unknown
                // elements.
                _ => self.close(|t| t == kind, ref_special),
            }
            self.tree.end_tag(tag);
            self.check();
        }
    }

    #[quickcheck]
    fn cached_scope_decisions_match_linear_reference(tokens: Vec<u8>, prefix: u8) -> bool {
        let mut oracle = ScopeOracle {
            tree: OpenElements::new(),
            base: Vec::new(),
            stack: Vec::new(),
        };
        // Establish the body (and a table cell, or a template in body mode)
        // the generated tokens run in.
        let (prefix, base): (&[u8], &[Tag]) = match prefix % 3 {
            0 => (b"<body>", &[Tag::Html, Tag::Body]),
            1 => (
                b"<body><table><tr><td>",
                &[
                    Tag::Html,
                    Tag::Body,
                    Tag::Table,
                    Tag::Tbody,
                    Tag::Tr,
                    Tag::Td,
                ],
            ),
            _ => (
                b"<body><template><div></div>",
                &[Tag::Html, Tag::Body, Tag::Template],
            ),
        };
        {
            let mut sink = TreeSink {
                tree: OpenElements::new(),
                ends: Vec::new(),
                plans: Vec::new(),
            };
            tokenize(prefix, &mut sink).unwrap();
            oracle.tree = sink.tree;
        }
        oracle.base = base.to_vec();
        oracle.check();
        let names = [
            "p", "button", "li", "dd", "dt", "div", "span", "ul", "ol", "dl", "h1", "h2",
            "section", "b", "i", "x-custom", "select", "option", "optgroup", "ruby", "rt", "rp",
            "rtc", "rb", "pre", "hr", "br", "em", "address", "object",
        ];
        let mut input = String::new();
        for byte in tokens.into_iter().take(512) {
            let name = names[usize::from(byte & 127) % names.len()];
            input.push('<');
            if byte & 128 != 0 {
                input.push('/');
            }
            input.push_str(name);
            input.push('>');
        }
        tokenize(input.as_bytes(), &mut oracle).unwrap();
        true
    }
}
