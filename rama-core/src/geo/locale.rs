//! A [BCP 47]-style locale: a language with an optional script and region.
//!
//! [BCP 47]: https://www.rfc-editor.org/info/bcp47

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{Country, Language, Script};

/// A locale: a [`Language`] plus an optional [`Script`] and [`Country`] region.
///
/// Modelled on BCP 47 `language[-Script][-Region]` (e.g. `en`, `pt-BR`,
/// `zh-Hant`, `mn-Cyrl-MN`). Subtags are matched case-sensitively in their
/// canonical BCP 47 casing (lowercase language, title-case script, uppercase
/// region) — which is the form geolocation databases store. Variant and
/// extension subtags are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Locale {
    /// The primary language subtag.
    pub language: Language,
    /// The optional script subtag.
    pub script: Option<Script>,
    /// The optional region subtag (an ISO 3166-1 country, or an unknown code
    /// such as a UN M.49 numeric region).
    pub region: Option<Country>,
}

impl Locale {
    /// Create a locale from just a language.
    #[must_use]
    pub fn new(language: Language) -> Self {
        Self {
            language,
            script: None,
            region: None,
        }
    }

    /// Parse a BCP 47-style tag (case-sensitive, canonical casing).
    #[must_use]
    pub fn parse(tag: &str) -> Self {
        let mut parts = tag.split(['-', '_']);
        let language = Language::from_code(parts.next().unwrap_or(""));
        let mut script = None;
        let mut region = None;
        for part in parts {
            let is_alpha = |s: &str| s.chars().all(|c| c.is_ascii_alphabetic());
            let is_digit = |s: &str| s.chars().all(|c| c.is_ascii_digit());
            if script.is_none() && region.is_none() && part.len() == 4 && is_alpha(part) {
                script = Some(Script::from_code(part));
            } else if region.is_none()
                && ((part.len() == 2 && is_alpha(part)) || (part.len() == 3 && is_digit(part)))
            {
                region = Some(Country::from_code(part));
            }
            // variant / extension / private-use subtags are ignored
        }
        Self {
            language,
            script,
            region,
        }
    }
}

impl fmt::Display for Locale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.language.code())?;
        if let Some(script) = &self.script {
            write!(f, "-{}", script.code())?;
        }
        if let Some(region) = &self.region {
            write!(f, "-{}", region.code())?;
        }
        Ok(())
    }
}

impl From<&str> for Locale {
    fn from(tag: &str) -> Self {
        Self::parse(tag)
    }
}

impl Serialize for Locale {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Locale {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let tag = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Ok(Self::parse(&tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_language_only() {
        let l = Locale::parse("en");
        assert_eq!(l.language, Language::English);
        assert_eq!(l.script, None);
        assert_eq!(l.region, None);
        assert_eq!(l.to_string(), "en");
    }

    #[test]
    fn parse_language_region() {
        let l = Locale::parse("pt-BR");
        assert_eq!(l.language, Language::Portuguese);
        assert_eq!(l.region, Some(Country::Brazil));
        assert_eq!(l.to_string(), "pt-BR");
    }

    #[test]
    fn parse_language_script_region() {
        let l = Locale::parse("zh-Hant-TW");
        assert_eq!(l.language, Language::Chinese);
        assert_eq!(l.script, Some(Script::HanTraditional));
        assert_eq!(l.region, Some(Country::Taiwan));
        assert_eq!(l.to_string(), "zh-Hant-TW");
    }

    #[test]
    fn serde_roundtrip() {
        let l = Locale::parse("zh-Hans-CN");
        let json = serde_json::to_string(&l).unwrap();
        assert_eq!(json, "\"zh-Hans-CN\"");
        // CN is not in the placeholder country subset for region, but China is
        let back: Locale = serde_json::from_str(&json).unwrap();
        assert_eq!(back, l);
    }
}
