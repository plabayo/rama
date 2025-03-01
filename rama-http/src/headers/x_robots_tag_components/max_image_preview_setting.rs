use rama_core::error::OpaqueError;
use std::fmt::Formatter;
use std::str::FromStr;
use MaxImagePreviewSetting::*;

/// The maximum size of an image preview for this page in a search results.
/// If omitted, search engines may show an image preview of the default size.
/// If you don't want search engines to use larger thumbnail images,
/// specify a max-image-preview value of standard or none. [^source]
///
/// [^source]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Robots-Tag#max-image-preview_setting
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaxImagePreviewSetting {
    /// No image preview is to be shown.
    None,
    /// A default image preview may be shown.
    Standard,
    /// A larger image preview, up to the width of the viewport, may be shown.
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
