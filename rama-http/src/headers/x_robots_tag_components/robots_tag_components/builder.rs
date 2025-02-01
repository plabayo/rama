use crate::headers::util::value_string::HeaderValueString;
use crate::headers::x_robots_tag_components::custom_rule::CustomRule;
use crate::headers::x_robots_tag_components::max_image_preview_setting::MaxImagePreviewSetting;
use crate::headers::x_robots_tag_components::robots_tag::RobotsTag;
use crate::headers::x_robots_tag_components::valid_date::ValidDate;
use rama_core::error::OpaqueError;

macro_rules! builder_field {
    ($field:ident, $type:ty) => {
        paste::paste! {
            pub(in crate::headers::x_robots_tag_components) fn [<$field>](mut self, [<$field>]: $type) -> Self {
                self.content.[<set_ $field>]([<$field>]);
                self.valid = true;
                self
            }

            pub(in crate::headers::x_robots_tag_components) fn [<set_ $field>](&mut self, [<$field>]: $type) -> &mut Self {
                self.content.[<set_ $field>]([<$field>]);
                self.valid = true;
                self
            }
        }
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::headers::x_robots_tag_components) struct Builder<T = ()> {
    content: T,
    valid: bool,
}

impl Builder<()> {
    pub(in crate::headers::x_robots_tag_components) fn new() -> Self {
        Builder {
            content: (),
            valid: false,
        }
    }

    pub(in crate::headers::x_robots_tag_components) fn bot_name(
        &self,
        bot_name: Option<HeaderValueString>,
    ) -> Builder<RobotsTag> {
        Builder {
            content: RobotsTag::new_with_bot_name(bot_name),
            valid: false,
        }
    }
}

impl Builder<RobotsTag> {
    pub(in crate::headers::x_robots_tag_components) fn build(
        self,
    ) -> Result<RobotsTag, OpaqueError> {
        if self.valid {
            Ok(self.content)
        } else {
            Err(OpaqueError::from_display("not a valid robots tag"))
        }
    }

    pub(in crate::headers::x_robots_tag_components) fn add_custom_rule(
        &mut self,
        rule: CustomRule,
    ) -> &mut Self {
        self.content.add_custom_rule(rule);
        self.valid = true;
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

    pub(in crate::headers::x_robots_tag_components) fn add_field(
        &mut self,
        s: &str,
    ) -> Result<&mut Self, OpaqueError> {
        if let Some((key, value)) = s.split_once(':') {
            Ok(if key.eq_ignore_ascii_case("max-snippet") {
                self.set_max_snippet(value.parse().map_err(OpaqueError::from_std)?)
            } else if key.eq_ignore_ascii_case("max-image-preview") {
                self.set_max_image_preview(value.parse()?)
            } else if key.eq_ignore_ascii_case("max-video-preview") {
                self.set_max_video_preview(value.parse().map_err(OpaqueError::from_std)?)
            } else if key.eq_ignore_ascii_case("unavailable_after: <date/time>") {
                self.set_unavailable_after(value.parse()?)
            } else {
                return Err(OpaqueError::from_display("not a valid robots tag field"));
            })
        } else {
            self.add_simple_field(s)
        }
    }

    fn add_simple_field(&mut self, s: &str) -> Result<&mut Self, OpaqueError> {
        Ok(if s.eq_ignore_ascii_case("all") {
            self.set_all(true)
        } else if s.eq_ignore_ascii_case("noindex") {
            self.set_no_index(true)
        } else if s.eq_ignore_ascii_case("nofollow") {
            self.set_no_follow(true)
        } else if s.eq_ignore_ascii_case("none") {
            self.set_none(true)
        } else if s.eq_ignore_ascii_case("nosnippet") {
            self.set_no_snippet(true)
        } else if s.eq_ignore_ascii_case("indexifembedded") {
            self.set_index_if_embedded(true)
        } else if s.eq_ignore_ascii_case("notranslate") {
            self.set_no_translate(true)
        } else if s.eq_ignore_ascii_case("noimageindex") {
            self.set_no_image_index(true)
        } else if s.eq_ignore_ascii_case("noai") {
            self.set_no_ai(true)
        } else if s.eq_ignore_ascii_case("noimageai") {
            self.set_no_image_ai(true)
        } else if s.eq_ignore_ascii_case("spc") {
            self.set_spc(true)
        } else {
            return Err(OpaqueError::from_display("not a valid robots tag field"));
        })
    }
}
