use serde::{Deserialize, Serialize};
use std::{convert::Infallible, ops::Deref, str::FromStr};
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone)]
/// A string filter that normalizes the string prior to consumption.
///
/// Normalizations:
///
/// - trims whitespace
/// - case-insensitive
/// - NFC normalizes
pub struct StringFilter(String);

impl StringFilter {
    /// Create a string filter which will match anything
    pub fn any() -> Self {
        "*".into()
    }

    /// Create a new string filter.
    pub fn new(value: impl AsRef<str>) -> Self {
        Self(value.as_ref().trim().to_lowercase().nfc().collect())
    }

    /// Get the inner string.
    pub fn inner(&self) -> &str {
        &self.0
    }

    /// Convert the string filter into the inner string.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl PartialEq for StringFilter {
    fn eq(&self, other: &Self) -> bool {
        match (self.0.as_str(), other.0.as_str()) {
            ("*", _) | (_, "*") => true,
            _ => self.0 == other.0,
        }
    }
}

impl Eq for StringFilter {}

impl std::hash::Hash for StringFilter {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl AsRef<str> for StringFilter {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for StringFilter {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

impl std::fmt::Display for StringFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<StringFilter> for String {
    fn from(filter: StringFilter) -> Self {
        filter.0
    }
}

impl From<&StringFilter> for String {
    fn from(filter: &StringFilter) -> Self {
        filter.0.clone()
    }
}

impl From<&str> for StringFilter {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for StringFilter {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&String> for StringFilter {
    fn from(value: &String) -> Self {
        Self::new(value)
    }
}

impl Deref for StringFilter {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for StringFilter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StringFilter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}

impl venndb::Any for StringFilter {
    fn is_any(&self) -> bool {
        self.0 == "*"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_filter_creation() {
        let filter = StringFilter::new("  Hello World  ");
        assert_eq!(filter, "hello world".into());
    }

    #[test]
    fn test_string_filter_nfc() {
        let filter = StringFilter::new("ÅΩ");
        assert_eq!(filter, "ÅΩ".into());
    }

    #[test]
    fn test_string_filter_case_insensitive() {
        let filter = StringFilter::new("Hello World");
        assert_eq!(filter, "hello world".into());
    }

    #[test]
    fn test_string_filter_deref() {
        let filter = StringFilter::new("Hello World");
        assert_eq!(filter.to_ascii_uppercase(), "HELLO WORLD");
    }

    #[test]
    fn test_string_filter_as_str() {
        let filter = StringFilter::new("Hello World");
        assert_eq!(filter.as_ref(), "hello world");
    }

    #[test]
    fn test_string_filter_serialization() {
        let filter = StringFilter::new("Hello World");
        let json = serde_json::to_string(&filter).unwrap();
        assert_eq!(json, "\"hello world\"");
        let filter2: StringFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(filter, filter2);
    }

    #[test]
    fn test_string_filter_deserialization() {
        let json = "\"  Hello World\"";
        let filter: StringFilter = serde_json::from_str(json).unwrap();
        assert_eq!(filter, "hello world".into());
    }

    #[test]
    fn test_string_filter_any() {
        use venndb::Any;

        let filter = StringFilter::any();
        assert!(filter.is_any());

        let filter: StringFilter = "hello".into();
        assert!(!filter.is_any());
    }

    #[test]
    fn test_string_filter_eq_cases() {
        for (a, b) in [
            ("hello", "hello"),
            ("hello", "HELLO"),
            ("HELLO", "hello"),
            ("HELLO", "HELLO"),
            (" foo", "foo "),
            ("foo ", " foo"),
            (" FOO ", " foo"),
            ("*", "*"),
            ("*", "foo"),
            ("foo", "*"),
            ("  * ", "foo"),
            ("foo", "  * "),
        ] {
            let a: StringFilter = a.into();
            let b: StringFilter = b.into();
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_string_filter_neq() {
        for (a, b) in [("hello", "world"), ("world", "hello")] {
            let a: StringFilter = a.into();
            let b: StringFilter = b.into();
            assert_ne!(a, b);
        }
    }
}
