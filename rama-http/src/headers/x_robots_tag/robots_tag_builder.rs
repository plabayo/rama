use crate::headers::util::value_string::HeaderValueString;
use crate::headers::x_robots_tag::custom_rule::CustomRule;
use crate::headers::x_robots_tag::max_image_preview_setting::MaxImagePreviewSetting;
use crate::headers::x_robots_tag::robots_tag::RobotsTag;

macro_rules! builder_field {
    ($field:ident, $type:ty) => {
        paste::paste! {
            pub fn [<$field>](mut self, [<$field>]: $type) -> Self {
                self.0.[<set_ $field>]([<$field>]);
                self
            }

            pub fn [<set_ $field>](&mut self, [<$field>]: $type) -> &mut Self {
                self.0.[<set_ $field>]([<$field>]);
                self
            }
        }
    };
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct RobotsTagBuilder<T = ()>(T);

impl RobotsTagBuilder<()> {
    pub fn new() -> Self {
        RobotsTagBuilder(())
    }

    pub fn bot_name(self, bot_name: Option<HeaderValueString>) -> RobotsTagBuilder<RobotsTag> {
        RobotsTagBuilder(RobotsTag::with_bot_name(bot_name))
    }
}

impl RobotsTagBuilder<RobotsTag> {
    pub fn add_custom_rule(&mut self, rule: CustomRule) -> &mut Self {
        self.0.add_custom_rules(rule);
        self
    }

    pub fn build(self) -> RobotsTag {
        self.0
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
    builder_field!(unavailable_after, chrono::DateTime<chrono::Utc>);
    builder_field!(no_ai, bool);
    builder_field!(no_image_ai, bool);
    builder_field!(spc, bool);
}
