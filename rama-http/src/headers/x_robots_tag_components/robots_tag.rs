use crate::headers::util::value_string::HeaderValueString;
use crate::headers::x_robots_tag_components::robots_tag_components::Builder;
use crate::headers::x_robots_tag_components::{CustomRule, MaxImagePreviewSetting, ValidDate};
use chrono::{DateTime, Utc};
use std::fmt::{Display, Formatter};

macro_rules! getter_setter {
    ($field:ident, $type:ty) => {
        paste::paste! {
            pub fn [<$field>](&self) -> $type {
                self.[<$field>]
            }

            pub fn [<set_ $field>](&mut self, [<$field>]: $type) -> &mut Self {
                self.[<$field>] = [<$field>];
                self
            }

            pub fn [<with_ $field>](mut self, [<$field>]: $type) -> Self {
                self.[<$field>] = [<$field>];
                self
            }
        }
    };

    ($field:ident, $type:ty, optional) => {
        paste::paste! {
            pub fn [<$field>](&self) -> Option<&$type> {
                self.[<$field>].as_ref()
            }

            pub fn [<set_ $field>](&mut self, [<$field>]: $type) -> &mut Self {
                self.[<$field>] = Some([<$field>]);
                self
            }

            pub fn [<with_ $field>](mut self, [<$field>]: $type) -> Self {
                self.[<$field>] = Some([<$field>]);
                self
            }
        }
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RobotsTag {
    bot_name: Option<HeaderValueString>,
    all: bool,
    no_index: bool,
    no_follow: bool,
    none: bool,
    no_snippet: bool,
    index_if_embedded: bool,
    max_snippet: u32,
    max_image_preview: Option<MaxImagePreviewSetting>,
    max_video_preview: Option<u32>,
    no_translate: bool,
    no_image_index: bool,
    unavailable_after: Option<ValidDate>,
    no_ai: bool,
    no_image_ai: bool,
    spc: bool,
    custom_rules: Vec<CustomRule>,
}

impl RobotsTag {
    pub(super) fn new_with_bot_name(bot_name: Option<HeaderValueString>) -> Self {
        Self {
            bot_name,
            all: false,
            no_index: false,
            no_follow: false,
            none: false,
            no_snippet: false,
            index_if_embedded: false,
            max_snippet: 0,
            max_image_preview: None,
            max_video_preview: None,
            no_translate: false,
            no_image_index: false,
            unavailable_after: None,
            no_ai: false,
            no_image_ai: false,
            spc: false,
            custom_rules: vec![],
        }
    }

    pub fn add_custom_rule_simple(&mut self, key: HeaderValueString) -> &mut Self {
        self.custom_rules.push(key.into());
        self
    }

    pub fn add_custom_rule_composite(
        &mut self,
        key: HeaderValueString,
        value: HeaderValueString,
    ) -> &mut Self {
        self.custom_rules.push((key, value).into());
        self
    }

    pub fn custom_rules(
        &self,
    ) -> impl Iterator<Item = (&HeaderValueString, &Option<HeaderValueString>)> {
        self.custom_rules.iter().map(|x| x.as_tuple())
    }

    pub fn builder() -> Builder {
        Builder::new()
    }

    getter_setter!(bot_name, HeaderValueString, optional);
    getter_setter!(all, bool);
    getter_setter!(no_index, bool);
    getter_setter!(no_follow, bool);
    getter_setter!(none, bool);
    getter_setter!(no_snippet, bool);
    getter_setter!(index_if_embedded, bool);
    getter_setter!(max_snippet, u32);
    getter_setter!(max_image_preview, MaxImagePreviewSetting, optional);
    getter_setter!(max_video_preview, u32, optional);
    getter_setter!(no_translate, bool);
    getter_setter!(no_image_index, bool);
    getter_setter!(no_ai, bool);
    getter_setter!(no_image_ai, bool);
    getter_setter!(spc, bool);

    pub(super) fn is_valid_field_name(field_name: &str) -> bool {
        field_name.trim().eq_ignore_ascii_case("all")
            || field_name.eq_ignore_ascii_case("noindex")
            || field_name.eq_ignore_ascii_case("nofollow")
            || field_name.eq_ignore_ascii_case("none")
            || field_name.eq_ignore_ascii_case("nosnippet")
            || field_name.eq_ignore_ascii_case("indexifembedded")
            || field_name.eq_ignore_ascii_case("max-snippet")
            || field_name.eq_ignore_ascii_case("max-image-preview")
            || field_name.eq_ignore_ascii_case("max-video-preview")
            || field_name.eq_ignore_ascii_case("notranslate")
            || field_name.eq_ignore_ascii_case("noimageindex")
            || field_name.eq_ignore_ascii_case("unavailable_after")
            || field_name.eq_ignore_ascii_case("noai")
            || field_name.eq_ignore_ascii_case("noimageai")
            || field_name.eq_ignore_ascii_case("spc")
    }

    pub fn unavailable_after(&self) -> Option<&DateTime<Utc>> {
        self.unavailable_after.as_deref()
    }

    pub fn set_unavailable_after(&mut self, unavailable_after: DateTime<Utc>) -> &mut Self {
        self.unavailable_after = Some(unavailable_after.into());
        self
    }

    pub fn with_unavailable_after(mut self, unavailable_after: DateTime<Utc>) -> Self {
        self.unavailable_after = Some(unavailable_after.into());
        self
    }
}

impl Display for RobotsTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(bot_name) = self.bot_name() {
            write!(f, "{bot_name}: ")?;
        }

        let mut _first = true;

        macro_rules! write_field {
            ($cond:expr, $fmt:expr) => {
                if $cond {
                    if !_first {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", $fmt)?;
                    _first = false;
                }
            };
            ($cond:expr, $fmt:expr, optional) => {
                if let Some(value) = $cond {
                    if !_first {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", $fmt, value)?;
                    _first = false;
                }
            };
        }

        write_field!(self.all(), "all");
        write_field!(self.no_index(), "noindex");
        write_field!(self.no_follow(), "nofollow");
        write_field!(self.none(), "none");
        write_field!(self.no_snippet(), "nosnippet");
        write_field!(self.index_if_embedded(), "indexifembedded");
        write_field!(
            self.max_snippet() != 0,
            format!("max-snippet: {}", self.max_snippet())
        );
        write_field!(self.max_image_preview(), "max-image-preview", optional);
        write_field!(self.max_video_preview(), "max-video-preview", optional);
        write_field!(self.no_translate(), "notranslate");
        write_field!(self.no_image_index(), "noimageindex");
        write_field!(self.unavailable_after(), "unavailable_after", optional);
        write_field!(self.no_ai(), "noai");
        write_field!(self.no_image_ai(), "noimageai");
        write_field!(self.spc(), "spc");

        Ok(())
    }
}
