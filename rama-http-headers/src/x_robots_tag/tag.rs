use crate::util::HeaderValueString;
use crate::x_robots_tag::{CustomRule, DirectiveDateTime, MaxImagePreviewSetting};
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
            $tag.$property_name = Some($value.parse().context(format!(
                "parse '{}' value as {}",
                $value, $property_name_str
            ))?);
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

            debug_assert!(pair_key.is_empty());

            $(
                parse_value_bool!{
                    tag, value =>
                    #[as_str($property_name_str)]
                    #[kind($kind)]
                    $property_name
                }
            )+

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Delimiter {
    Colon,
    Comma,
}

fn find_delimiter(buffer: &[u8]) -> Option<(usize, Delimiter)> {
    for (index, &b) in buffer.iter().enumerate() {
        match b {
            b':' => return Some((index, Delimiter::Colon)),
            b',' => return Some((index, Delimiter::Comma)),
            _ => {}
        }
    }
    None
}

fn trim_space(buffer: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = buffer.len();
    while start < end && buffer[start] == b' ' {
        start += 1;
    }
    while start < end && buffer[end - 1] == b' ' {
        end -= 1;
    }
    &buffer[start..end]
}

impl Iterator for Parser<'_> {
    type Item = Result<RobotsTag, BoxError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.is_empty() {
            return None;
        }

        let mut directive_count = 0;
        let mut tag = RobotsTag::new_default_inner();
        let mut pair_key = "";
        let mut delimiter_offset = 0;

        for _ in 0..4096 {
            match find_delimiter(&self.buffer[delimiter_offset..]) {
                Some((index, Delimiter::Colon)) => {
                    if !pair_key.is_empty() {
                        tracing::trace!(
                            "unexpected colon in value for key {pair_key} (try to continue search)"
                        );
                        // colon could be part of value
                        delimiter_offset += index + 1;
                        continue;
                    }

                    let key_buffer = trim_space(&self.buffer[..delimiter_offset + index]);
                    if let Some(key) = find_pair_key_fn(key_buffer) {
                        pair_key = key
                    } else {
                        if directive_count != 0 {
                            return Some(Ok(tag));
                        }

                        if tag.bot_name.is_some() {
                            self.buffer = &self.buffer[self.buffer.len()..];
                            return Some(Err(BoxError::from(
                                "unexpected bot name: one is already defined without any directives",
                            )));
                        } else {
                            let s = match std::str::from_utf8(key_buffer) {
                                Ok(value) => value,
                                Err(err) => {
                                    self.buffer = &self.buffer[self.buffer.len()..];
                                    return Some(Err(
                                        err.context("interpret key buffer bot name as utf-8")
                                    ));
                                }
                            };
                            tag.bot_name = Some(match s.parse() {
                                Ok(value) => value,
                                Err(err) => {
                                    self.buffer = &self.buffer[self.buffer.len()..];
                                    return Some(Err(err.context(
                                        "interpret key buffer utf-8 string as bot-name",
                                    )));
                                }
                            });
                        }
                    }
                    self.buffer = &self.buffer[delimiter_offset + index + 1..];
                    delimiter_offset = 0;
                }
                Some((index, Delimiter::Comma)) => {
                    let value = match std::str::from_utf8(trim_space(
                        &self.buffer[..delimiter_offset + index],
                    )) {
                        Ok(value) => value,
                        Err(err) => {
                            self.buffer = &self.buffer[self.buffer.len()..];
                            return Some(Err(err.context("interpret value as utf-8")));
                        }
                    };
                    if let Err(e) = parse_value(value, pair_key, &mut tag) {
                        tracing::trace!("parse value error (try to continue search): {e}");
                        // comma could be part of value
                        delimiter_offset += index + 1;
                        continue;
                    }
                    directive_count += 1;
                    pair_key = "";
                    self.buffer = &self.buffer[delimiter_offset + index + 1..];
                    delimiter_offset = 0;
                }
                None => {
                    let value = match std::str::from_utf8(trim_space(self.buffer)) {
                        Ok(value) => value,
                        Err(err) => {
                            self.buffer = &self.buffer[self.buffer.len()..];
                            return Some(Err(err.context("interpret remainder value as utf-8")));
                        }
                    };
                    if let Err(e) = parse_value(value, pair_key, &mut tag) {
                        self.buffer = &self.buffer[self.buffer.len()..];
                        return Some(Err(e));
                    }
                    directive_count += 1;
                    pair_key = "";
                    self.buffer = &self.buffer[self.buffer.len()..];
                    delimiter_offset = 0;
                }
            }

            if self.buffer.is_empty() {
                if directive_count == 0 {
                    if let Some(bot_name) = tag.bot_name {
                        self.buffer = &self.buffer[self.buffer.len()..];
                        return Some(Err(BoxError::from(
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

        self.buffer = &self.buffer[self.buffer.len()..];
        Some(Err(BoxError::from("delimiter search overflow")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[::tracing_test::traced_test]
    fn test_parse_invalid_input() {
        for test_value in ["", "\n"] {
            let _: Vec<_> = robots_tag_parse_iter(test_value.as_bytes()).collect();
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
}
