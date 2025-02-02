use crate::headers::util::value_string::HeaderValueString;
use crate::headers::x_robots_tag_components::custom_rule::CustomRule;
use crate::headers::x_robots_tag_components::max_image_preview_setting::MaxImagePreviewSetting;
use crate::headers::x_robots_tag_components::robots_tag::RobotsTag;
use crate::headers::x_robots_tag_components::valid_date::ValidDate;
use headers::Error;
use rama_core::error::OpaqueError;

macro_rules! robots_tag_builder_field {
    ($field:ident, $type:ty) => {
        paste::paste! {
            pub(in crate::headers::x_robots_tag_components) fn [<$field>](mut self, [<$field>]: $type) -> Self {
                self.0.[<set_ $field>]([<$field>]);
                self
            }

            pub(in crate::headers::x_robots_tag_components) fn [<set_ $field>](&mut self, [<$field>]: $type) -> &mut Self {
                self.0.[<set_ $field>]([<$field>]);
                self
            }
        }
    };
}

macro_rules! no_tag_builder_field {
    ($field:ident, $type:ty) => {
        paste::paste! {
            pub(in crate::headers::x_robots_tag_components) fn [<$field>](self, [<$field>]: $type) -> Builder<RobotsTag> {
                Builder(RobotsTag::new_with_bot_name(self.0.bot_name)).[<$field>]([<$field>])
            }
        }
    };
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::headers::x_robots_tag_components) struct Builder<T = ()>(T);

impl Builder<()> {
    pub(in crate::headers::x_robots_tag_components) fn new() -> Self {
        Builder(())
    }

    pub(in crate::headers::x_robots_tag_components) fn bot_name(
        &self,
        bot_name: Option<HeaderValueString>,
    ) -> Builder<NoTag> {
        Builder(NoTag { bot_name })
    }
}

pub(in crate::headers::x_robots_tag_components) struct NoTag {
    bot_name: Option<HeaderValueString>,
}

impl Builder<NoTag> {
    pub(in crate::headers::x_robots_tag_components) fn bot_name(
        mut self,
        bot_name: HeaderValueString,
    ) -> Self {
        self.0.bot_name = Some(bot_name);
        self
    }

    pub(in crate::headers::x_robots_tag_components) fn set_bot_name(
        &mut self,
        bot_name: HeaderValueString,
    ) -> &mut Self {
        self.0.bot_name = Some(bot_name);
        self
    }
    
    no_tag_builder_field!(all, bool);
    no_tag_builder_field!(no_index, bool);
    no_tag_builder_field!(no_follow, bool);
    no_tag_builder_field!(none, bool);
    no_tag_builder_field!(no_snippet, bool);
    no_tag_builder_field!(index_if_embedded, bool);
    no_tag_builder_field!(max_snippet, u32);
    no_tag_builder_field!(max_image_preview, MaxImagePreviewSetting);
    no_tag_builder_field!(max_video_preview, u32);
    no_tag_builder_field!(no_translate, bool);
    no_tag_builder_field!(no_image_index, bool);
    no_tag_builder_field!(unavailable_after, ValidDate);
    no_tag_builder_field!(no_ai, bool);
    no_tag_builder_field!(no_image_ai, bool);
    no_tag_builder_field!(spc, bool);

    pub(in crate::headers::x_robots_tag_components) fn add_field(
        self,
        s: &str,
    ) -> Result<Builder<RobotsTag>, OpaqueError> {
        let mut builder = Builder(RobotsTag::new_with_bot_name(self.0.bot_name));
        builder.add_field(s)?;
        Ok(builder)
    }
}

impl Builder<RobotsTag> {
    pub(in crate::headers::x_robots_tag_components) fn build(self) -> RobotsTag {
        self.0
    }

    pub(in crate::headers::x_robots_tag_components) fn add_custom_rule(
        &mut self,
        rule: CustomRule,
    ) -> &mut Self {
        self.0.add_custom_rule(rule);
        self
    }

    robots_tag_builder_field!(bot_name, HeaderValueString);
    robots_tag_builder_field!(all, bool);
    robots_tag_builder_field!(no_index, bool);
    robots_tag_builder_field!(no_follow, bool);
    robots_tag_builder_field!(none, bool);
    robots_tag_builder_field!(no_snippet, bool);
    robots_tag_builder_field!(index_if_embedded, bool);
    robots_tag_builder_field!(max_snippet, u32);
    robots_tag_builder_field!(max_image_preview, MaxImagePreviewSetting);
    robots_tag_builder_field!(max_video_preview, u32);
    robots_tag_builder_field!(no_translate, bool);
    robots_tag_builder_field!(no_image_index, bool);
    robots_tag_builder_field!(unavailable_after, ValidDate);
    robots_tag_builder_field!(no_ai, bool);
    robots_tag_builder_field!(no_image_ai, bool);
    robots_tag_builder_field!(spc, bool);

    pub(in crate::headers::x_robots_tag_components) fn add_field(
        &mut self,
        s: &str,
    ) -> Result<&mut Self, OpaqueError> {
        if let Some((key, value)) = s.trim().split_once(':') {
            Ok(if key.eq_ignore_ascii_case("max-snippet") {
                self.set_max_snippet(value.parse().map_err(OpaqueError::from_std)?)
            } else if key.eq_ignore_ascii_case("max-image-preview") {
                self.set_max_image_preview(value.parse()?)
            } else if key.eq_ignore_ascii_case("max-video-preview") {
                self.set_max_video_preview(value.parse().map_err(OpaqueError::from_std)?)
            } else if key.eq_ignore_ascii_case("unavailable_after: <date/time>") {
                self.set_unavailable_after(value.parse()?)
            } else {
                return Err(OpaqueError::from_std(Error::invalid()));
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
            return Err(OpaqueError::from_std(Error::invalid()));
        })
    }
}
