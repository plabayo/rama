use rama_core::error::OpaqueError;
use std::fmt::Formatter;
use std::str::FromStr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum MaxImagePreviewSetting {
    None,
    Standard,
    Large,
}

impl std::fmt::Display for MaxImagePreviewSetting {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            MaxImagePreviewSetting::None => write!(f, "none"),
            MaxImagePreviewSetting::Standard => write!(f, "standard"),
            MaxImagePreviewSetting::Large => write!(f, "large"),
        }
    }
}

impl FromStr for MaxImagePreviewSetting {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("none") {
            Ok(MaxImagePreviewSetting::None)
        } else if s.eq_ignore_ascii_case("standard") {
            Ok(MaxImagePreviewSetting::Standard)
        } else if s.eq_ignore_ascii_case("large") {
            Ok(MaxImagePreviewSetting::Large)
        } else {
            Err(OpaqueError::from_display(
                "failed to parse MaxImagePreviewSetting",
            ))
        }
    }
}
