use rama_core::error::OpaqueError;
use std::convert::{TryFrom, TryInto};
use std::fmt::Formatter;
use std::str::FromStr;
use crate::headers::x_robots_tag::valid_date::ValidDate;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rule {
    All,
    NoIndex,
    NoFollow,
    None,
    NoSnippet,
    IndexIfEmbedded,
    MaxSnippet(u32),
    MaxImagePreview(MaxImagePreviewSetting),
    MaxVideoPreview(Option<u32>),
    NoTranslate,
    NoImageIndex,
    UnavailableAfter(ValidDate), // "A date must be specified in a format such as RFC 822, RFC 850, or ISO 8601."
    // custom rules
    NoAi,
    NoImageAi,
    SPC
}

impl std::fmt::Display for Rule {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Rule::All => write!(f, "all"),
            Rule::NoIndex => write!(f, "noindex"),
            Rule::NoFollow => write!(f, "nofollow"),
            Rule::None => write!(f, "none"),
            Rule::NoSnippet => write!(f, "nosnippet"),
            Rule::IndexIfEmbedded => write!(f, "indexifembedded"),
            Rule::MaxSnippet(number) => write!(f, "maxsnippet: {}", number),
            Rule::MaxImagePreview(setting) => write!(f, "max-image-preview: {}", setting),
            Rule::MaxVideoPreview(number) => match number {
                Some(number) => write!(f, "max-video-preview: {}", number),
                None => write!(f, "max-video-preview: -1"),
            },
            Rule::NoTranslate => write!(f, "notranslate"),
            Rule::NoImageIndex => write!(f, "noimageindex"),
            Rule::UnavailableAfter(date) => write!(f, "unavailable_after: {}", date),
            Rule::NoAi => write!(f, "noai"),
            Rule::NoImageAi => write!(f, "noimageai"),
            Rule::SPC => write!(f, "spc"),
        }
    }
}

impl FromStr for Rule {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.split(":")
            .map(str::trim)
            .collect::<Vec<_>>()
            .as_slice()
            .try_into()
    }
}

impl TryFrom<&[&str]> for Rule {
    type Error = OpaqueError;

    fn try_from(value: &[&str]) -> Result<Self, Self::Error> {
        match *value {
            ["all"] => Ok(Rule::All),
            ["no_index"] => Ok(Rule::NoIndex),
            ["no_follow"] => Ok(Rule::NoFollow),
            ["none"] => Ok(Rule::None),
            ["no_snippet"] => Ok(Rule::NoSnippet),
            ["indexifembedded"] => Ok(Rule::IndexIfEmbedded),
            ["max-snippet", number] => Ok(Rule::MaxSnippet(
                number.parse().map_err(OpaqueError::from_display)?,
            )),
            ["max-image-preview", setting] => Ok(Rule::MaxImagePreview(setting.parse()?)),
            ["max-video-preview", number] => Ok(Rule::MaxVideoPreview(match number {
                "-1" => None,
                n => Some(n.parse().map_err(OpaqueError::from_display)?),
            })),
            ["notranslate"] => Ok(Rule::NoTranslate),
            ["noimageindex"] => Ok(Rule::NoImageIndex),
            ["unavailable_after", date] => Ok(Rule::UnavailableAfter(date.parse()?)),
            ["noai"] => Ok(Rule::NoAi),
            ["noimageai"] => Ok(Rule::NoImageAi),
            ["spc"] => Ok(Rule::SPC),
            _ => Err(OpaqueError::from_display("Invalid X-Robots-Tag rule")),
        }
    }
}

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
        match s {
            "none" => Ok(MaxImagePreviewSetting::None),
            "standard" => Ok(MaxImagePreviewSetting::Standard),
            "large" => Ok(MaxImagePreviewSetting::Large),
            _ => Err(OpaqueError::from_display(
                "failed to parse MaxImagePreviewSetting",
            )),
        }
    }
}
