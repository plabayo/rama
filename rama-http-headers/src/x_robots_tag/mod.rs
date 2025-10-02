mod tag;
pub use tag::{RobotsTag, robots_tag_parse_iter};

mod components;
pub use components::{CustomRule, DirectiveDateTime, MaxImagePreviewSetting};

mod header;
pub use header::XRobotsTag;
