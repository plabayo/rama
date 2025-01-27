use rama_core::error::OpaqueError;
use std::fmt::Formatter;
use std::str::FromStr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaxImagePreviewSetting {
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
        match s.to_lowercase().trim() {
            "none" => Ok(MaxImagePreviewSetting::None),
            "standard" => Ok(MaxImagePreviewSetting::Standard),
            "large" => Ok(MaxImagePreviewSetting::Large),
            _ => Err(OpaqueError::from_display(
                "failed to parse MaxImagePreviewSetting",
            )),
        }
    }
}
