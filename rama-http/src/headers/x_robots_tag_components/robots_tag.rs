use crate::headers::util::value_string::HeaderValueString;
use crate::headers::x_robots_tag_components::robots_tag_components::{Builder, NoTag};
use crate::headers::x_robots_tag_components::{CustomRule, MaxImagePreviewSetting, ValidDate};
use chrono::{DateTime, Utc};
use std::fmt::{Display, Formatter};

macro_rules! getter {
    ($field:ident, $type:ty) => {
        paste::paste! {
            pub fn [<$field>](&self) -> $type {
                self.[<$field>]
            }
        }
    };

    ($field:ident, $type:ty, optional) => {
        paste::paste! {
            pub fn [<$field>](&self) -> Option<&$type> {
                self.[<$field>].as_ref()
            }
        }
    };
}

/// A single element of [`XRobotsTag`] corresponding to the valid values for one `bot_name`
///
/// [List of directives](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Robots-Tag#directives)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RobotsTag {
    pub(super) bot_name: Option<HeaderValueString>,
    pub(super) all: bool,
    pub(super) no_index: bool,
    pub(super) no_follow: bool,
    pub(super) none: bool,
    pub(super) no_snippet: bool,
    pub(super) index_if_embedded: bool,
    pub(super) max_snippet: u32,
    pub(super) max_image_preview: Option<MaxImagePreviewSetting>,
    pub(super) max_video_preview: Option<u32>,
    pub(super) no_translate: bool,
    pub(super) no_image_index: bool,
    pub(super) unavailable_after: Option<ValidDate>,
    pub(super) no_ai: bool,
    pub(super) no_image_ai: bool,
    pub(super) spc: bool,
    pub(super) custom_rules: Vec<CustomRule>,
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

    pub fn builder() -> Builder<NoTag> {
        Builder::new()
    }

    pub fn custom_rules(
        &self,
    ) -> impl Iterator<Item = (&HeaderValueString, &Option<HeaderValueString>)> {
        self.custom_rules.iter().map(|x| x.as_tuple())
    }

    getter!(bot_name, HeaderValueString, optional);
    getter!(all, bool);
    getter!(no_index, bool);
    getter!(no_follow, bool);
    getter!(none, bool);
    getter!(no_snippet, bool);
    getter!(index_if_embedded, bool);
    getter!(max_snippet, u32);
    getter!(max_image_preview, MaxImagePreviewSetting, optional);
    getter!(max_video_preview, Option<u32>);
    getter!(no_translate, bool);
    getter!(no_image_index, bool);
    getter!(no_ai, bool);
    getter!(no_image_ai, bool);
    getter!(spc, bool);

    pub fn unavailable_after(&self) -> Option<&DateTime<Utc>> {
        self.unavailable_after.as_deref()
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
