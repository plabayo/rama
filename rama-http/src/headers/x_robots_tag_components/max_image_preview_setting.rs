use rama_core::error::OpaqueError;
use std::fmt::Formatter;
use std::str::FromStr;
use MaxImagePreviewSetting::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum MaxImagePreviewSetting {
    None,
    Standard,
    Large,
}

impl MaxImagePreviewSetting {
    fn as_str(&self) -> &'static str {
        match self {
            None => "none",
            Standard => "standard",
            Large => "large",
        }
    }
}

impl std::fmt::Display for MaxImagePreviewSetting {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for MaxImagePreviewSetting {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case(None.as_str()) {
            Ok(None)
        } else if s.eq_ignore_ascii_case(Standard.as_str()) {
            Ok(Standard)
        } else if s.eq_ignore_ascii_case(Large.as_str()) {
            Ok(Large)
        } else {
            Err(OpaqueError::from_display(
                "failed to parse MaxImagePreviewSetting",
            ))
        }
    }
}
