use crate::headers::util::value_string::HeaderValueString;
use crate::headers::x_robots_tag_components::{MaxImagePreviewSetting, RobotsTag, ValidDate};
use chrono::{DateTime, Utc};
use headers::Error;
use rama_core::error::OpaqueError;

macro_rules! robots_tag_builder_field {
    ($field:ident, bool) => {
        paste::paste! {
            pub fn [<$field>](mut self) -> Self {
                self.0.[<$field>] = true;
                self
            }

            pub fn [<set_ $field>](&mut self) -> &mut Self {
                self.0.[<$field>] = true;
                self
            }
        }
    };

    ($field:ident, $type:ty) => {
        paste::paste! {
            pub fn [<$field>](mut self, [<$field>]: $type) -> Self {
                self.0.[<$field>] = [<$field>];
                self
            }

            pub fn [<set_ $field>](&mut self, [<$field>]: $type) -> &mut Self {
                self.0.[<$field>] = [<$field>];
                self
            }
        }
    };

    ($field:ident, $type:ty, optional) => {
        paste::paste! {
            pub fn [<$field>](mut self, [<$field>]: $type) -> Self {
                self.0.[<$field>] = Some([<$field>]);
                self
            }

            pub fn [<set_ $field>](&mut self, [<$field>]: $type) -> &mut Self {
                self.0.[<$field>] = Some([<$field>]);
                self
            }
        }
    };
}

macro_rules! no_tag_builder_field {
    ($field:ident, bool) => {
        paste::paste! {
            pub fn [<$field>](self) -> Builder<RobotsTag> {
                Builder(RobotsTag::new_with_bot_name(self.0.bot_name)).[<$field>]()
            }
        }
    };

    ($field:ident, $type:ty) => {
        paste::paste! {
            pub fn [<$field>](self, [<$field>]: $type) -> Builder<RobotsTag> {
                Builder(RobotsTag::new_with_bot_name(self.0.bot_name)).[<$field>]([<$field>])
            }
        }
    };
}

/// Generic structure used for building a [`RobotsTag`] with compile-time validation
///
/// # States
///
/// - `Builder<()>`
///     - a new builder without any values
///     - can transform to `Builder<NoTag>` using the [`Builder::bot_name()`] function
/// - `Builder<NoTag>`
///     - holds a `bot_name` field, but still isn't a valid [`RobotsTag`]
///     - can transform to `Builder<RobotsTag>` by specifying a valid [`RobotsTag`] field
/// - `Builder<RobotsTag>`
///     - holds a valid [`RobotsTag`] struct, which can be further modified
///     - can be built into a [`RobotsTag`] using the [`Builder::<RobotsTag>::build()`] function
///
/// # Examples
///
/// ```
/// # use rama_http::headers::x_robots_tag_components::RobotsTag;
/// let robots_tag = RobotsTag::builder()
///                     .no_follow()
///                     .build();
/// assert_eq!(robots_tag.no_follow(), true);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Builder<T = ()>(T);

impl Builder<()> {}

pub struct NoTag {
    bot_name: Option<HeaderValueString>,
}

impl Builder<NoTag> {
    pub fn new() -> Self {
        Self(NoTag { bot_name: None })
    }

    pub fn bot_name(mut self, bot_name: HeaderValueString) -> Self {
        self.0.bot_name = Some(bot_name);
        self
    }

    pub fn set_bot_name(&mut self, bot_name: HeaderValueString) -> &mut Self {
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
    no_tag_builder_field!(max_video_preview, Option<u32>);
    no_tag_builder_field!(no_translate, bool);
    no_tag_builder_field!(no_image_index, bool);
    no_tag_builder_field!(unavailable_after, DateTime<Utc>);
    no_tag_builder_field!(no_ai, bool);
    no_tag_builder_field!(no_image_ai, bool);
    no_tag_builder_field!(spc, bool);

    /// Transforms the `Builder<NoTag>` into a `Builder<RobotsTag>` by calling the
    /// [`Builder<RobotsTag>::add_field()`] function (see for more detailed documentation)
    pub fn add_field(self, s: &str) -> Result<Builder<RobotsTag>, OpaqueError> {
        let mut builder = Builder(RobotsTag::new_with_bot_name(self.0.bot_name));
        builder.add_field(s)?;
        Ok(builder)
    }
}

impl Builder<RobotsTag> {
    pub fn build(self) -> RobotsTag {
        self.0
    }

    pub fn add_custom_rule_simple(&mut self, key: HeaderValueString) -> &mut Self {
        self.0.custom_rules.push(key.into());
        self
    }

    pub fn add_custom_rule_composite(
        &mut self,
        key: HeaderValueString,
        value: HeaderValueString,
    ) -> &mut Self {
        self.0.custom_rules.push((key, value).into());
        self
    }

    pub fn set_unavailable_after(&mut self, unavailable_after: DateTime<Utc>) -> &mut Self {
        self.0.unavailable_after = Some(unavailable_after.into());
        self
    }

    pub fn unavailable_after(mut self, unavailable_after: DateTime<Utc>) -> Self {
        self.0.unavailable_after = Some(unavailable_after.into());
        self
    }

    robots_tag_builder_field!(bot_name, HeaderValueString, optional);
    robots_tag_builder_field!(all, bool);
    robots_tag_builder_field!(no_index, bool);
    robots_tag_builder_field!(no_follow, bool);
    robots_tag_builder_field!(none, bool);
    robots_tag_builder_field!(no_snippet, bool);
    robots_tag_builder_field!(index_if_embedded, bool);
    robots_tag_builder_field!(max_snippet, u32);
    robots_tag_builder_field!(max_image_preview, MaxImagePreviewSetting, optional);
    robots_tag_builder_field!(max_video_preview, Option<u32>);
    robots_tag_builder_field!(no_translate, bool);
    robots_tag_builder_field!(no_image_index, bool);
    robots_tag_builder_field!(no_ai, bool);
    robots_tag_builder_field!(no_image_ai, bool);
    robots_tag_builder_field!(spc, bool);

    /// Adds a field based on its `&str` representation (also handles whitespace by trimming)
    ///
    /// # Returns and Errors
    ///
    /// - `Result<&mut Self, OpaqueError>`
    ///     - `Ok(&mut Self)`
    ///         - when the field was valid and successfully added
    ///         - returns `&mut Self` wrapped inside for easier chaining of functions
    ///     - `Err(OpaqueError)`
    ///         - is of type [`headers::Error`] when the field name is not valid
    ///         - for composite rules (key + value), wraps the conversion error for the value
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::num::ParseIntError;
    /// # use rama_http::headers::x_robots_tag_components::RobotsTag;
    /// let mut builder = RobotsTag::builder().no_follow();
    ///
    /// assert!(builder.add_field("nosnippet").is_ok());
    /// assert!(builder.add_field("max-snippet: 8").is_ok());
    /// assert!(builder.add_field("nonexistent").is_err_and(|e| e.is::<headers::Error>()));
    /// assert!(builder.add_field("max-video-preview: not_a_number").is_err_and(|e| e.is::<ParseIntError>()));
    ///
    /// let robots_tag = builder.build();
    ///
    /// assert_eq!(robots_tag.no_snippet(), true);
    /// assert_eq!(robots_tag.max_snippet(), 8);
    /// ```
    pub fn add_field(&mut self, s: &str) -> Result<&mut Self, OpaqueError> {
        if let Some((key, value)) = s.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            Ok(if key.eq_ignore_ascii_case("max-snippet") {
                self.set_max_snippet(value.parse().map_err(OpaqueError::from_std)?)
            } else if key.eq_ignore_ascii_case("max-image-preview") {
                self.set_max_image_preview(value.parse()?)
            } else if key.eq_ignore_ascii_case("max-video-preview") {
                self.set_max_video_preview(match value {
                    "-1" => None,
                    _ => Some(value.parse().map_err(OpaqueError::from_std)?),
                })
            } else if key.eq_ignore_ascii_case("unavailable_after") {
                self.set_unavailable_after(value.parse::<ValidDate>()?.into())
            } else {
                return Err(OpaqueError::from_std(Error::invalid()));
            })
        } else {
            self.add_simple_field(s.trim())
        }
    }

    /// # Contracts
    ///
    /// - expects `s` to be trimmed in advance
    fn add_simple_field(&mut self, s: &str) -> Result<&mut Self, OpaqueError> {
        Ok(if s.eq_ignore_ascii_case("all") {
            self.set_all()
        } else if s.eq_ignore_ascii_case("noindex") {
            self.set_no_index()
        } else if s.eq_ignore_ascii_case("nofollow") {
            self.set_no_follow()
        } else if s.eq_ignore_ascii_case("none") {
            self.set_none()
        } else if s.eq_ignore_ascii_case("nosnippet") {
            self.set_no_snippet()
        } else if s.eq_ignore_ascii_case("indexifembedded") {
            self.set_index_if_embedded()
        } else if s.eq_ignore_ascii_case("notranslate") {
            self.set_no_translate()
        } else if s.eq_ignore_ascii_case("noimageindex") {
            self.set_no_image_index()
        } else if s.eq_ignore_ascii_case("noai") {
            self.set_no_ai()
        } else if s.eq_ignore_ascii_case("noimageai") {
            self.set_no_image_ai()
        } else if s.eq_ignore_ascii_case("spc") {
            self.set_spc()
        } else {
            return Err(OpaqueError::from_std(Error::invalid()));
        })
    }
}
