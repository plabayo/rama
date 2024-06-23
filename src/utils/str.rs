//! String utility types.

use std::{borrow::Cow, fmt};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A string which can never be empty.
pub struct NonEmptyString(Cow<'static, str>);

crate::__static_str_error! {
    #[doc = "empty string"]
    pub struct EmptyStringErr;
}

impl NonEmptyString {
    /// Creates a non-empty string a compile time.
    ///
    /// This function requires the static string be non-empty.
    ///
    /// # Panics
    ///
    /// This function panics at **compile time** when the static string is empty.
    pub const fn from_static(src: &'static str) -> NonEmptyString {
        if src.is_empty() {
            panic!("empty static string");
        }

        NonEmptyString(Cow::Borrowed(src))
    }

    /// Views this [`NonEmptyString`] as a string slice.
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl fmt::Display for NonEmptyString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<NonEmptyString> for String {
    fn from(value: NonEmptyString) -> Self {
        value.0.to_string()
    }
}

impl TryFrom<String> for NonEmptyString {
    type Error = EmptyStringErr;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(Self::Error::default())
        } else {
            Ok(Self(Cow::Owned(value)))
        }
    }
}

impl TryFrom<&String> for NonEmptyString {
    type Error = EmptyStringErr;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(Self::Error::default())
        } else {
            Ok(Self(Cow::Owned(value.clone())))
        }
    }
}

impl TryFrom<&str> for NonEmptyString {
    type Error = EmptyStringErr;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err(Self::Error::default())
        } else {
            Ok(Self(Cow::Owned(value.to_owned())))
        }
    }
}

impl std::str::FromStr for NonEmptyString {
    type Err = EmptyStringErr;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl AsRef<str> for NonEmptyString {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl PartialEq<str> for NonEmptyString {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<String> for NonEmptyString {
    fn eq(&self, other: &String) -> bool {
        self.0.as_ref() == other
    }
}

impl PartialEq<&String> for NonEmptyString {
    fn eq(&self, other: &&String) -> bool {
        self.0.as_ref() == *other
    }
}

impl PartialEq<&str> for NonEmptyString {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<NonEmptyString> for str {
    fn eq(&self, other: &NonEmptyString) -> bool {
        other == self
    }
}

impl PartialEq<NonEmptyString> for String {
    fn eq(&self, other: &NonEmptyString) -> bool {
        other == self
    }
}

impl PartialEq<NonEmptyString> for &String {
    fn eq(&self, other: &NonEmptyString) -> bool {
        other == *self
    }
}

impl PartialEq<NonEmptyString> for &str {
    fn eq(&self, other: &NonEmptyString) -> bool {
        other == *self
    }
}

impl serde::Serialize for NonEmptyString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for NonEmptyString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.try_into().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_try_into_err(src: impl TryInto<NonEmptyString>) {
        assert!(src.try_into().is_err());
    }

    fn assert_try_into_ok<S>(src: S)
    where
        S: TryInto<NonEmptyString> + fmt::Debug + Clone + PartialEq<NonEmptyString>,
        <S as TryInto<NonEmptyString>>::Error: std::error::Error,
    {
        let expected = src.clone();
        let value: NonEmptyString = src.try_into().unwrap();
        assert_eq!(expected, value);
    }

    #[test]
    fn test_non_empty_string_construction_failure() {
        assert_try_into_err("");
        assert_try_into_err(String::from(""));
        #[allow(clippy::needless_borrows_for_generic_args)]
        assert_try_into_err(&String::from(""));
    }

    #[test]
    fn test_non_empty_string_construction_success() {
        assert_try_into_ok("a");
        assert_try_into_ok(String::from("b"));
        #[allow(clippy::needless_borrows_for_generic_args)]
        assert_try_into_ok(&String::from("c"));
    }
}
