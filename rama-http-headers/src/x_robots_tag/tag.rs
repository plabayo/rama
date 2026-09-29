use crate::util::HeaderValueString;
use crate::x_robots_tag::{CustomRule, DirectiveDateTime, MaxImagePreviewSetting};
use rama_core::error::BoxErrorExt as _;
use rama_core::error::{BoxError, ErrorContext as _, ErrorExt as _};
use rama_core::telemetry::tracing;
use rama_utils::macros::generate_set_and_with;
use std::fmt::{self, Display, Formatter};

macro_rules! directive_type {
    (
        #[kind(optional)]
        $property_type:ty
    ) => {
       Option<$property_type>
    };

    (
        #[kind(bool)]
        $property_type:ty
    ) => {
        bool
    };
}

macro_rules! pair_key_if_branch_for_optional {
    (
        $key_buffer:ident =>
        #[as_str($property_name_str:literal)]
        #[kind(optional)]
        $property_name:ident
    ) => {
        if $key_buffer.eq_ignore_ascii_case($property_name_str.as_bytes()) {
            return Some($property_name_str);
        }
    };

    (
        $key_buffer:ident =>
        #[as_str($property_name_str:literal)]
        #[kind(bool)]
        $property_name:ident
    ) => {};
}

macro_rules! make_pair_key_find_fn {
    (
        $(
            #[as_str($property_name_str:literal)]
            #[kind($kind:tt)]
            $property_name:ident
        )+
    ) => {
        fn find_pair_key_fn(key_buffer: &[u8]) -> Option<&'static str> {
            $(
                pair_key_if_branch_for_optional!{
                    key_buffer =>
                    #[as_str($property_name_str)]
                    #[kind($kind)]
                    $property_name
                }
            )+
            None
        }
    };
}

macro_rules! parse_value_optional {
    (
        $pair_key:ident, $tag:ident, $value:ident =>
        #[as_str($property_name_str:literal)]
        #[kind(optional)]
        $property_name:ident
    ) => {
        if $pair_key == $property_name_str {
            $tag.$property_name = Some(
                $value
                    .parse()
                    .context("parse robots tag value")
                    .context_str_field("value", $value)
                    .context_field("property", $property_name_str)?,
            );
            return Ok(());
        }
    };

    (
        $pair_key:ident, $tag:ident, $value:ident =>
        #[as_str($property_name_str:literal)]
        #[kind(bool)]
        $property_name:ident
    ) => {};
}

macro_rules! parse_value_bool {
    (
        $tag:ident, $value:ident =>
        #[as_str($property_name_str:literal)]
        #[kind(optional)]
        $property_name:ident
    ) => {};

    (
        $tag:ident, $value:ident =>
        #[as_str($property_name_str:literal)]
        #[kind(bool)]
        $property_name:ident
    ) => {
        if $value.eq_ignore_ascii_case($property_name_str) {
            $tag.$property_name = true;
            return Ok(());
        }
    };
}

macro_rules! make_parse_value_fn {
    (
        $(
            #[as_str($property_name_str:literal)]
            #[kind($kind:tt)]
            $property_name:ident
        )+
    ) => {
        fn parse_value(value: &str, pair_key: &str, tag: &mut RobotsTag) -> Result<(), BoxError> {
            tracing::debug!("parse value: {value} (key={pair_key}");

            $(
                parse_value_optional!{
                    pair_key, tag, value =>
                    #[as_str($property_name_str)]
                    #[kind($kind)]
                    $property_name
                }
            )+

            if !pair_key.is_empty() {
                return Err(BoxError::from_static_str("unknown robots tag pair key")
                    .context_str_field("key", pair_key));
            }

            $(
                parse_value_bool!{
                    tag, value =>
                    #[as_str($property_name_str)]
                    #[kind($kind)]
                    $property_name
                }
            )+

            if value.is_empty() {
                return Err(BoxError::from_static_str("empty robots tag directive"));
            }
            tag.custom_rules.push(CustomRule::new_boolean_directive(value.parse().context("create custom boolean directive")?));
            Ok(())
        }
    };
}

macro_rules! directive_setter {
    (
        #[kind(optional)]
        $(#[$property_doc:meta])+
        $property_name:ident: $property_type:ty
    ) => {
        generate_set_and_with! {
            $(#[$property_doc])+
            pub fn $property_name(
                mut self,
                value: Option<$property_type>,
            ) -> Self {
                self.$property_name = value;
                self
            }
        }
    };

    (
        #[kind(bool)]
        $(#[$property_doc:meta])+
        $property_name:ident: $property_type:ty
    ) => {
        generate_set_and_with! {
            $(#[$property_doc])+
            pub fn $property_name(
                mut self,
                value: $property_type,
            ) -> Self {
                self.$property_name = value;
                self
            }
        }
    };
}

macro_rules! directive_constructor {
    (
        #[kind(optional)]
        $(#[$property_doc:meta])+
        $property_name:ident: $property_type:ty
    ) => {
        rama_utils::macros::paste! {
            $(#[$property_doc])+
            #[must_use]
            pub fn [<new_ $property_name>](value: $property_type) -> Self {
                Self {
                    $property_name: Some(value),
                    ..Self::new_default_inner()
                }
            }

            $(#[$property_doc])+
            #[must_use]
            pub fn [<new_ $property_name _for_bot>](value: $property_type, name: HeaderValueString) -> Self {
                Self {
                    bot_name: Some(name),
                    $property_name: Some(value),
                    ..Self::new_default_inner()
                }
            }
        }
    };

    (
        #[kind(bool)]
        $(#[$property_doc:meta])+
        $property_name:ident: $property_type:ty
    ) => {
        rama_utils::macros::paste! {
            $(#[$property_doc])+
            #[must_use]
            pub fn [<new_ $property_name>]() -> Self {
                Self {
                    $property_name: true,
                    ..Self::new_default_inner()
                }
            }

            $(#[$property_doc])+
            #[must_use]
            pub fn [<new_ $property_name _for_bot>](name: HeaderValueString) -> Self {
                Self {
                    bot_name: Some(name),
                    $property_name: true,
                    ..Self::new_default_inner()
                }
            }
        }
    };
}

macro_rules! directive_getter {
    (
        #[kind(optional)]
        $(#[$property_doc:meta])+
        $property_name:ident: $property_type:ty
    ) => {
        $(#[$property_doc])+
        pub fn $property_name(&self) -> Option<&$property_type> {
            self.$property_name.as_ref()
        }
    };

    (
        #[kind(bool)]
        $(#[$property_doc:meta])+
        $property_name:ident: $property_type:ty
    ) => {
        $(#[$property_doc])+
        pub fn $property_name(&self) -> bool {
            self.$property_name
        }
    };
}

trait DirectiveCondWrite {
    fn cond_write(
        &self,
        key: &str,
        separator: &mut &'static str,
        f: &mut Formatter<'_>,
    ) -> std::fmt::Result;
}

impl DirectiveCondWrite for bool {
    fn cond_write(
        &self,
        key: &str,
        separator: &mut &'static str,
        f: &mut Formatter<'_>,
    ) -> std::fmt::Result {
        if *self {
            write!(f, "{separator}{key}")?;
            *separator = ", ";
        }
        Ok(())
    }
}

impl<T: fmt::Display> DirectiveCondWrite for Option<T> {
    fn cond_write(
        &self,
        key: &str,
        separator: &mut &'static str,
        f: &mut Formatter<'_>,
    ) -> std::fmt::Result {
        if let Some(val) = self.as_ref() {
            write!(f, "{separator}{key}: {val}")?;
            *separator = ", ";
        }
        Ok(())
    }
}

macro_rules! create_robots_tag {
    (
      $(
          #[as_str($property_name_str:literal)]
          #[kind($kind:tt)]
          $(#[$property_doc:meta])+
          $property_name:ident: $property_type:ty,
      )+
    ) => {
        /// A single element of [`X-Robots-Tag`] corresponding to the valid values for one `bot name`
        ///
        /// More Information:
        ///
        /// * [List of std directives](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Robots-Tag#directives)
        /// * SPC: <https://www.ietf.org/slides/slides-aicontrolws-server-privacy-control-a-server-to-client-privacy-opt-out-preference-signal-00.pdf>
        /// * No-AI / No-Image-AI: no source that we aware of, if you know of any please open a PR
        ///
        /// [`X-Robots-Tag`]: super::XRobotsTag
        #[derive(Debug, Clone)]
        #[cfg_attr(test, derive(PartialEq, Eq))]
        pub struct RobotsTag {
            bot_name: Option<HeaderValueString>,
            custom_rules: Vec<CustomRule>,

            $(
                $property_name: directive_type! {
                    #[kind($kind)]
                    $property_type
                },
            )+
        }

        rama_utils::macros::paste! {
            impl RobotsTag {
                fn new_default_inner() -> Self {
                    Self {
                        bot_name: Default::default(),
                        custom_rules: Default::default(),
                        $(
                            $property_name: Default::default(),
                        )+
                    }
                }

                /// Custom rules defined for this tag.
                pub fn custom_rules(&self) -> &[CustomRule] {
                    &self.custom_rules
                }

                /// Custom rules defined for this tag.
                pub fn new_custom_rule(rule: CustomRule) -> Self {
                    Self {
                        custom_rules: vec![rule],
                        ..Self::new_default_inner()
                    }
                }

                /// Custom rules defined for this tag.
                pub fn new_custom_rule_for_bot(rule: CustomRule, name: HeaderValueString) -> Self {
                    Self {
                        bot_name: Some(name),
                        custom_rules: vec![rule],
                        ..Self::new_default_inner()
                    }
                }

                generate_set_and_with! {
                    /// Set an additional rule to this tag.
                    pub fn additional_custom_rule(
                        mut self,
                        rule: CustomRule,
                    ) -> Self {
                        self.custom_rules.push(rule);
                        self
                    }
                }

                generate_set_and_with! {
                    /// Set zero, one or multiple additional rules to this tag.
                    pub fn additional_custom_rules(
                        mut self,
                        rules: impl IntoIterator<Item = CustomRule>,
                    ) -> Self {
                        self.custom_rules.extend(rules);
                        self
                    }
                }

                /// Get a reference the robot name that is set.
                pub fn bot_name(&self) -> Option<&HeaderValueString> {
                    self.bot_name.as_ref()
                }

                generate_set_and_with! {
                    /// Set or overwrite the robot name.
                    pub fn bot_name(
                        mut self,
                        name: Option<HeaderValueString>,
                    ) -> Self {
                        self.bot_name = name;
                        self
                    }
                }

                $(
                    directive_constructor! {
                        #[kind($kind)]
                        $(#[$property_doc])+
                        $property_name: $property_type
                    }

                    directive_getter! {
                        #[kind($kind)]
                        $(#[$property_doc])+
                        $property_name: $property_type
                    }

                    directive_setter! {
                        #[kind($kind)]
                        $(#[$property_doc])+
                        $property_name: $property_type
                    }
                )+
            }
        }

        rama_utils::macros::paste! {
            impl Display for RobotsTag {
                fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                    if let Some(bot_name) = self.bot_name.as_ref() {
                        write!(f, "{bot_name}: ")?;
                    }

                    let mut separator = "";

                    $(
                        self.$property_name.cond_write($property_name_str, &mut separator, f)?;
                    )+

                    for rule in self.custom_rules.iter() {
                        match rule.as_tuple() {
                            (key, Some(value)) => {
                                write!(f, "{separator}{key}: {value}")?;
                                separator = ", ";
                            },
                            (key, None) => {
                                write!(f, "{separator}{key}")?;
                                separator = ", ";
                            },
                        }
                    }

                    Ok(())
                }
            }
        }

        make_pair_key_find_fn! {
            $(
                #[as_str($property_name_str)]
                #[kind($kind)]
                $property_name
            )+
        }

        make_parse_value_fn! {
            $(
                #[as_str($property_name_str)]
                #[kind($kind)]
                $property_name
            )+
        }
    };
}

create_robots_tag! {
    #[as_str("all")]
    #[kind(bool)]
    /// No restrictions for indexing or serving in search results.
    /// This rule is the default value and has no effect if explicitly listed.
    all: bool,
    #[as_str("noindex")]
    #[kind(bool)]
    /// Do not show this page, media, or resource in search results.
    /// If omitted, the page, media, or resource may be indexed and shown in search results.
    no_index: bool,
    #[as_str("nofollow")]
    #[kind(bool)]
    /// Do not follow the links on this page. If omitted,
    /// search engines may use the links on the page to discover those linked pages.
    no_follow: bool,
    #[as_str("none")]
    #[kind(bool)]
    /// Equivalent to `noindex`, `nofollow`.
    none: bool,
    #[as_str("nosnippet")]
    #[kind(bool)]
    /// Do not show a text snippet or video preview in the search results for this page.
    /// A static image thumbnail (if available) may still be visible.
    /// If omitted, search engines may generate a text snippet
    /// and video preview based on information found on the page.
    ///
    /// To exclude certain sections of your content from appearing in search result snippets,
    /// use [the data-nosnippet HTML attribute](https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag#data-nosnippet-attr).
    no_snippet: bool,
    #[as_str("indexifembedded")]
    #[kind(bool)]
    /// A search engine is allowed to index the content of a page
    /// if it's embedded in another page through iframes or similar HTML elements,
    /// in spite of a `noindex` rule. `indexifembedded` only has an effect if it's accompanied by `noindex`.
    index_if_embedded: bool,
    #[as_str("max-snippet")]
    #[kind(optional)]
    /// Use a maximum of `<number>` characters as a textual snippet for this search result.
    ///
    /// Ignored if no valid `<number>` is specified.
    max_snippet: u32,
    #[as_str("max-image-preview")]
    #[kind(optional)]
    /// The maximum size of an image preview for this page in a search results.
    ///
    /// If omitted, search engines may show an image preview of the default size.
    /// If you don't want search engines to use larger thumbnail images,
    /// specify a `max-image-preview` value of [`standard`] or [`none`].
    ///
    /// [`standard`]: MaxImagePreviewSetting::Standard
    /// [`none`]: MaxImagePreviewSetting::None
    max_image_preview: MaxImagePreviewSetting,
    #[as_str("max-video-preview")]
    #[kind(optional)]
    /// Use a maximum of `<number>` seconds as a video snippet
    /// for videos on this page in search results.
    ///
    /// If omitted, search engines may show a video snippet in search results,
    /// and the search engine decides how long a preview may be.
    ///
    /// Ignored if no valid `<number>` is specified.
    ///
    /// Special values are as follows:
    /// - `0`:  At most, a static image may be used, in accordance to the max-image-preview setting.
    /// - `-1`: No video length limit.
    max_video_preview: i32,
    #[as_str("notranslate")]
    #[kind(bool)]
    /// Don't offer translation of this page in search results.
    ///
    /// If omitted, search engines may translate the search result title and snippet
    /// into the language of the search query.
    no_translate: bool,
    #[as_str("noimageindex")]
    #[kind(bool)]
    /// Do not index images on this page.
    ///
    /// If omitted, images on the page may be indexed and shown in search results.
    no_image_index: bool,
    #[as_str("unavailable_after")]
    #[kind(optional)]
    /// Requests not to show this page in search results after the specified <date/time>.
    ///
    /// Ignored if no valid <date/time> is specified.
    /// A date must be specified in a format such as RFC 822, RFC 850, or ISO 8601.
    ///
    /// By default there is no expiration date for content.
    /// If omitted, this page may be shown in search results indefinitely.
    /// Crawlers are expected to considerably decrease
    unavailable_after: DirectiveDateTime,
    #[as_str("noai")]
    #[kind(bool)]
    /// No AI (e.g. LLM) allowed.
    no_ai: bool,
    #[as_str("noimageai")]
    #[kind(bool)]
    /// No Image AI (e.g. LLM) allowed.
    no_image_ai: bool,
    #[as_str("spc")]
    #[kind(bool)]
    /// Server Privacy Control
    ///
    /// A do-not-sell-or-share preference is when a person requests that their data "not be sold
    /// or shared" for instance by activating a Server Privacy Control setting with their web
    /// server software or by using web server software that defaults to such a setting
    /// (possibly because this setting matches the most common expectations of that tool's
    /// users). When set, this preference indicates that the person expects to create content
    /// for the Web with do-not-sell-or-share interactions.
    spc: bool,
}

/// Create an iterator to try to parse a byte slice
/// as one or multiple [`RobotsTag`]s.
pub fn robots_tag_parse_iter(buffer: &[u8]) -> impl Iterator<Item = Result<RobotsTag, BoxError>> {
    Parser::new(buffer)
}

#[derive(Debug)]
struct Parser<'a> {
    buffer: &'a [u8],
}

impl<'a> Parser<'a> {
    fn new(buffer: &'a [u8]) -> Self {
        Self { buffer }
    }

    /// Bytes before the delimiter found at `index`.
    fn head(&self, index: usize) -> &'a [u8] {
        self.buffer.get(..index).unwrap_or_default()
    }

    /// Consume up to and including the delimiter found at `index`.
    fn advance_past(&mut self, index: usize) {
        self.buffer = self
            .buffer
            .get(index.saturating_add(1)..)
            .unwrap_or_default();
    }
}

/// Retrying each comma re-parses the value so far, so bound it to keep parsing linear.
const MAX_COMMAS_PER_VALUE: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Delimiter {
    Colon,
    Comma,
}

fn find_delimiter(buffer: &[u8], from: usize) -> Option<(usize, Delimiter)> {
    buffer
        .iter()
        .enumerate()
        .skip(from)
        .find_map(|(index, b)| match b {
            b':' => Some((index, Delimiter::Colon)),
            b',' => Some((index, Delimiter::Comma)),
            _ => None,
        })
}

/// Trim OWS (SP and HTAB).
fn trim_space(mut buffer: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = buffer {
        buffer = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = buffer {
        buffer = rest;
    }
    buffer
}

impl Iterator for Parser<'_> {
    type Item = Result<RobotsTag, BoxError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.is_empty() {
            return None;
        }

        let mut has_directive = false;
        let mut tag = RobotsTag::new_default_inner();
        let mut pair_key = "";
        let mut delimiter_offset = 0;
        let mut value_commas = 0;

        // every iteration consumes or skips a delimiter, so the input length bounds the loop
        for _ in 0..=self.buffer.len() {
            match find_delimiter(self.buffer, delimiter_offset) {
                Some((index, Delimiter::Colon)) => {
                    if !pair_key.is_empty() {
                        tracing::trace!(
                            "unexpected colon in value for key {pair_key} (try to continue search)"
                        );
                        // colon could be part of value
                        delimiter_offset = index.saturating_add(1);
                        continue;
                    }

                    let key_buffer = trim_space(self.head(index));
                    if let Some(key) = find_pair_key_fn(key_buffer) {
                        pair_key = key
                    } else {
                        if has_directive {
                            return Some(Ok(tag));
                        }

                        if tag.bot_name.is_some() {
                            self.buffer = &[];
                            return Some(Err(BoxError::from_static_str(
                                "unexpected bot name: one is already defined without any directives",
                            )));
                        } else {
                            let s = match std::str::from_utf8(key_buffer) {
                                Ok(value) => value,
                                Err(err) => {
                                    self.buffer = &[];
                                    return Some(Err(
                                        err.context("interpret key buffer bot name as utf-8")
                                    ));
                                }
                            };
                            tag.bot_name = Some(match s.parse() {
                                Ok(value) => value,
                                Err(err) => {
                                    self.buffer = &[];
                                    return Some(Err(err.context(
                                        "interpret key buffer utf-8 string as bot-name",
                                    )));
                                }
                            });
                        }
                    }
                    self.advance_past(index);
                    delimiter_offset = 0;
                    value_commas = 0;
                }
                Some((index, Delimiter::Comma)) => {
                    let raw_value = trim_space(self.head(index));
                    // an empty list element is ignored (RFC 9110 §5.6.1)
                    if pair_key.is_empty() && raw_value.is_empty() {
                        self.advance_past(index);
                        delimiter_offset = 0;
                        continue;
                    }
                    let value = match std::str::from_utf8(raw_value) {
                        Ok(value) => value,
                        Err(err) => {
                            self.buffer = &[];
                            return Some(Err(err.context("interpret value as utf-8")));
                        }
                    };
                    if let Err(e) = parse_value(value, pair_key, &mut tag) {
                        if value_commas >= MAX_COMMAS_PER_VALUE {
                            self.buffer = &[];
                            return Some(Err(e.context("too many commas in robots tag value")));
                        }
                        tracing::trace!("parse value error (try to continue search): {e}");
                        // comma could be part of value
                        value_commas = value_commas.saturating_add(1);
                        delimiter_offset = index.saturating_add(1);
                        continue;
                    }
                    has_directive = true;
                    pair_key = "";
                    self.advance_past(index);
                    delimiter_offset = 0;
                    value_commas = 0;
                }
                None => {
                    let value = match std::str::from_utf8(trim_space(self.buffer)) {
                        Ok(value) => value,
                        Err(err) => {
                            self.buffer = &[];
                            return Some(Err(err.context("interpret remainder value as utf-8")));
                        }
                    };
                    // an empty remainder ends the tag like the end of input does
                    if !(value.is_empty() && pair_key.is_empty()) {
                        if let Err(e) = parse_value(value, pair_key, &mut tag) {
                            self.buffer = &[];
                            return Some(Err(e));
                        }
                        has_directive = true;
                    }
                    pair_key = "";
                    self.buffer = &[];
                    delimiter_offset = 0;
                }
            }

            if self.buffer.is_empty() {
                if !has_directive {
                    if let Some(bot_name) = tag.bot_name {
                        return Some(Err(BoxError::from_static_str(
                            "tag with only a bot name is not allowed",
                        )
                        .context_field("bot_name", bot_name)));
                    }
                    return None;
                } else {
                    return Some(Ok(tag));
                }
            }
        }

        self.buffer = &[];
        Some(Err(BoxError::from_static_str("delimiter search overflow")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[::tracing_test::traced_test]
    fn test_parse_invalid_input() {
        for test_value in ["", "\n"] {
            _ = robots_tag_parse_iter(test_value.as_bytes()).collect::<Vec<_>>();
        }
    }

    #[test]
    fn test_parse_adversarial_input_no_panic() {
        for test_value in [
            ":",
            ",",
            ":,",
            ",:",
            "::::",
            ",,,,",
            " : , : ",
            "ü",
            "ü:ü",
            "ü: ü, ü: noindex",
            "é,é:é",
            "bot: é: é, noindex",
            "max-snippet: ü, é, noindex",
            "unavailable_after: ü:ü, é:é",
            "unavailable_after:",
            "unavailable_after: ,",
            "max-snippet:",
            "max-snippet: 99999999999999999999",
            "max-video-preview: -99999999999999999999",
            "bot:",
            "bot: bot:",
            "a\n, b: noindex",
            "a\n: noindex",
            "noindex, a\u{7f}: nofollow",
            "unavailable_after: 1 Jan 0000 00:00:00 +0100",
            "unavailable_after: 0000-01-01T00:00:00+23:59",
            "unavailable_after: -009999-01-01",
        ] {
            for tag in robots_tag_parse_iter(test_value.as_bytes()).flatten() {
                _ = tag.to_string();
                _ = tag.bot_name();
                _ = tag.custom_rules();
                _ = tag.unavailable_after().map(ToString::to_string);
                _ = tag.max_image_preview().map(ToString::to_string);
            }
        }
    }

    #[test]
    fn test_parse_many_delimiters_bounded() {
        for unit in [",", ":", "a,", "a:", "ü,", ", noindex", ": noindex"] {
            for prefix in ["", "max-snippet: ", "unavailable_after: ", "bot: "] {
                let input = format!("{prefix}{}", unit.repeat(10_000));
                let results = robots_tag_parse_iter(input.as_bytes()).collect::<Vec<_>>();
                assert!(results.len() <= input.len());
            }
        }
    }

    #[test]
    #[::tracing_test::traced_test]
    fn test_single_robots_tag_display_mirror() {
        for test_value in [
            "noindex",
            "noimageindex",
            "unavailable_after: Wed, 3 Dec 2025 13:09:53 +0000",
            "noimageindex, unavailable_after: Wed, 3 Dec 2025 13:09:53 +0000",
            "BadBot: noindex, nofollow",
            "BadBot: noindex, nofollow", // + custom key-value rule
            "googlebot: nofollow",
            "duckduckbot: quack", // custom boolean rule
        ] {
            let mut iter = robots_tag_parse_iter(test_value.as_bytes());
            let tag = iter.next().unwrap().unwrap();
            let output = tag.to_string();
            assert_eq!(test_value, output);
        }
    }

    #[test]
    #[::tracing_test::traced_test]
    fn test_multiple_robots_tag_display_mirror() {
        for test_value in [
            "noindex, googlebot: nofollow",
            "BadBot: noindex, nofollow, googlebot: nofollow, unavailable_after: Wed, 3 Dec 2025 13:09:53 +0000",
            "google_bot: unavailable_after: 2025-02-18T08:25:15+00:00, BadBot: max-image-preview: large",
        ] {
            let tags = robots_tag_parse_iter(test_value.as_bytes())
                .map(|result| result.unwrap().to_string())
                .collect::<Vec<_>>();
            assert_eq!(2, tags.len());
            let output = tags.join(", ");
            assert_eq!(test_value, output);
        }
    }

    #[test]
    fn test_parse_value_with_many_commas_errors() {
        for prefix in ["max-snippet: ", "unavailable_after: ", "bot: max-snippet: "] {
            let input = format!("{prefix}{}", "a,".repeat(4000));
            let results = robots_tag_parse_iter(input.as_bytes()).collect::<Vec<_>>();
            assert!(matches!(results.as_slice(), [Err(_)]), "{prefix}");
        }
    }

    #[test]
    fn test_parse_date_value_with_commas() {
        let tag = robots_tag_parse_iter(
            b"unavailable_after: Wed, 3 Dec 2025 13:09:53 +0000 (a, b, c), noindex",
        )
        .next()
        .unwrap()
        .unwrap();
        assert!(tag.unavailable_after().is_some());
        assert!(tag.no_index());
    }

    #[test]
    fn test_parse_many_directives_in_one_tag() {
        let input = vec!["a"; 5000].join(",");
        let tags = robots_tag_parse_iter(input.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].custom_rules().len(), 5000);
    }

    #[test]
    fn test_parse_empty_list_elements_are_ignored() {
        for input in [
            "noindex,,nofollow",
            "noindex, , nofollow",
            ", noindex, nofollow,",
            "noindex, nofollow, ",
        ] {
            let tags = robots_tag_parse_iter(input.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(tags.len(), 1, "{input}");
            assert!(tags[0].no_index(), "{input}");
            assert!(tags[0].no_follow(), "{input}");
            assert!(tags[0].custom_rules().is_empty(), "{input}");
        }
    }

    #[test]
    fn test_parse_only_empty_elements_yields_no_tag() {
        for input in [",", ", ,", " , "] {
            let tags = robots_tag_parse_iter(input.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert!(tags.is_empty(), "{input:?}");
        }
    }

    #[test]
    fn test_parse_blank_directive_is_rejected() {
        for input in [" ", "  ", "\t"] {
            let results = robots_tag_parse_iter(input.as_bytes()).collect::<Vec<_>>();
            assert!(results.iter().all(Result::is_err), "{input:?}: {results:?}");
        }
    }

    #[test]
    fn test_parse_date_value_comma_bound() {
        let date = |commas: usize| {
            let comment = vec!["a"; commas.saturating_add(1)].join(",");
            format!("unavailable_after: Wed, 3 Dec 2025 13:09:53 +0000 ({comment}), noindex")
        };
        let accepted = date(15);
        let tag = robots_tag_parse_iter(accepted.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        assert!(tag.unavailable_after().is_some());

        let rejected = date(17);
        let results = robots_tag_parse_iter(rejected.as_bytes()).collect::<Vec<_>>();
        assert!(matches!(results.as_slice(), [Err(_)]), "{results:?}");
    }
}
