use crate::headers::util::value_string::HeaderValueString;
use crate::headers::x_robots_tag::custom_rule::CustomRule;
use crate::headers::x_robots_tag::max_image_preview_setting::MaxImagePreviewSetting;
use crate::headers::x_robots_tag::robots_tag_builder::RobotsTagBuilder;

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
        }
    };

    ($field:ident, $type:ty, vec) => {
        paste::paste! {
            pub fn [<$field>](&self) -> &Vec<$type> {
                &self.[<$field>]
            }

            pub fn [<add_ $field>](&mut self, [<$field>]: $type) -> &mut Self {
                self.[<$field>].push([<$field>]);
                self
            }
        }
    };
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
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
    unavailable_after: Option<chrono::DateTime<chrono::Utc>>, // "A date must be specified in a format such as RFC 822, RFC 850, or ISO 8601."
    // custom rules
    no_ai: bool,
    no_image_ai: bool,
    spc: bool,
    custom_rules: Vec<CustomRule>,
}

impl RobotsTag {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn with_bot_name(bot_name: Option<HeaderValueString>) -> Self {
        Self {
            bot_name,
            ..Default::default()
        }
    }

    pub fn builder() -> RobotsTagBuilder {
        RobotsTagBuilder::new()
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
    getter_setter!(unavailable_after, chrono::DateTime<chrono::Utc>, optional);
    getter_setter!(no_ai, bool);
    getter_setter!(no_image_ai, bool);
    getter_setter!(spc, bool);
    getter_setter!(custom_rules, CustomRule, vec);
}
