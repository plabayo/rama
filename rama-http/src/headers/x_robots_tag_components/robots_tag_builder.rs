use rama_core::error::OpaqueError;
use crate::headers::util::value_string::HeaderValueString;
use crate::headers::x_robots_tag_components::custom_rule::CustomRule;
use crate::headers::x_robots_tag_components::max_image_preview_setting::MaxImagePreviewSetting;
use crate::headers::x_robots_tag_components::robots_tag::RobotsTag;
use crate::headers::x_robots_tag_components::valid_date::ValidDate;

macro_rules! builder_field {
    ($field:ident, $type:ty) => {
        paste::paste! {
            pub(super) fn [<$field>](mut self, [<$field>]: $type) -> Self {
                self.content.[<set_ $field>]([<$field>]);
                self
            }

            pub(super) fn [<set_ $field>](&mut self, [<$field>]: $type) -> &mut Self {
                self.content.[<set_ $field>]([<$field>]);
                self
            }

            pub(super) fn [<with_ $field>](mut self, [<$field>]: $type) -> Self {
                self.content.[<set_ $field>]([<$field>]);
                self
            }
        }
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RobotsTagBuilder<T = ()> {
    content: T,
    valid: bool
}

impl RobotsTagBuilder<()> {
    pub(super) fn new() -> Self {
        RobotsTagBuilder{content: (), valid: false }
    }

    pub(super) fn bot_name(
        self,
        bot_name: Option<HeaderValueString>,
    ) -> RobotsTagBuilder<RobotsTag> {
        RobotsTagBuilder{ content: RobotsTag::new_with_bot_name(bot_name), valid: false }
    }
}

impl RobotsTagBuilder<RobotsTag> {
    pub(super) fn build(self) -> Result<RobotsTag, OpaqueError> {
        if self.valid {
            Ok(self.content)
        } else {
            Err(OpaqueError::from_display("not a valid robots tag"))
        }
    }

    pub(super) fn add_custom_rule(&mut self, rule: CustomRule) -> &mut Self {
        self.content.add_custom_rule(rule);
        self
    }

    builder_field!(bot_name, HeaderValueString);
    builder_field!(all, bool);
    builder_field!(no_index, bool);
    builder_field!(no_follow, bool);
    builder_field!(none, bool);
    builder_field!(no_snippet, bool);
    builder_field!(index_if_embedded, bool);
    builder_field!(max_snippet, u32);
    builder_field!(max_image_preview, MaxImagePreviewSetting);
    builder_field!(max_video_preview, u32);
    builder_field!(no_translate, bool);
    builder_field!(no_image_index, bool);
    builder_field!(unavailable_after, ValidDate);
    builder_field!(no_ai, bool);
    builder_field!(no_image_ai, bool);
    builder_field!(spc, bool);
}
