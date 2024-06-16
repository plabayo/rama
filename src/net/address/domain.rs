use super::Host;
use crate::error::{ErrorContext, OpaqueError};
use std::{borrow::Cow, fmt};

/// A domain.
///
/// # Remarks
///
/// The validation of domains created by this type is very shallow.
/// Proper validation is offloaded to other services such as DNS resolvers.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Domain(Cow<'static, str>);

impl Domain {
    /// Creates a domain at compile time.
    ///
    /// This function requires the static string to be a valid domain
    ///
    /// # Panics
    ///
    /// This function panics at **compile time** when the static string is not a valid domain.
    pub const fn from_static(s: &'static str) -> Self {
        if !is_valid_name(s.as_bytes()) {
            panic!("static str is an invalid domain");
        }
        Self(Cow::Borrowed(s))
    }

    /// Creates the localhost domain.
    pub fn localhost() -> Self {
        Domain(Cow::Borrowed("localhost"))
    }

    /// Creates the example domain.
    pub fn example() -> Self {
        Domain(Cow::Borrowed("example.com"))
    }

    /// Consumes the domain as a host.
    pub fn into_host(self) -> Host {
        Host::Name(self)
    }

    /// Gets the domain name as reference.
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }
}

impl AsRef<str> for Domain {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::str::FromStr for Domain {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Domain::try_from(s.to_owned())
    }
}

impl TryFrom<String> for Domain {
    type Error = OpaqueError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        if is_valid_name(name.as_bytes()) {
            Ok(Self(Cow::Owned(name)))
        } else {
            Err(OpaqueError::from_display("invalid domain"))
        }
    }
}

impl TryFrom<Vec<u8>> for Domain {
    type Error = OpaqueError;

    fn try_from(name: Vec<u8>) -> Result<Self, Self::Error> {
        if is_valid_name(name.as_slice()) {
            Ok(Self(Cow::Owned(
                String::from_utf8(name).context("convert domain bytes to utf-8 string")?,
            )))
        } else {
            Err(OpaqueError::from_display("invalid domain"))
        }
    }
}

impl PartialEq<str> for Domain {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Domain {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Domain> for str {
    fn eq(&self, other: &Domain) -> bool {
        other == self
    }
}

impl PartialEq<Domain> for &str {
    fn eq(&self, other: &Domain) -> bool {
        other == *self
    }
}

impl PartialEq<String> for Domain {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<Domain> for String {
    fn eq(&self, other: &Domain) -> bool {
        other == self
    }
}

impl serde::Serialize for Domain {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Domain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.try_into().map_err(serde::de::Error::custom)
    }
}

impl Domain {
    /// The maximum length of a domain label.
    const MAX_LABEL_LEN: usize = 63;

    /// The maximum length of a domain name.
    const MAX_NAME_LEN: usize = 253;
}

const fn is_valid_label(name: &[u8], start: usize, stop: usize) -> bool {
    if start >= stop
        || stop - start > Domain::MAX_LABEL_LEN
        || name[start] == b'-'
        || start == stop
        || name[stop - 1] == b'-'
    {
        false
    } else {
        let mut i = start;
        while i < stop {
            let c = name[i];
            if !c.is_ascii_alphanumeric() && (c != b'-' || i == start || name[i - 1] == b'-') {
                return false;
            }
            i += 1;
        }
        true
    }
}

/// Checks if the domain name is valid.
const fn is_valid_name(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > Domain::MAX_NAME_LEN {
        false
    } else {
        let mut non_empty_groups = 0;
        let mut i = 0;
        let mut offset = 0;
        while i < name.len() {
            let c = name[i];
            if c == b'.' {
                if offset == i {
                    // empty
                    if i == 0 || i == name.len() - 1 {
                        i += 1;
                        offset = i + 1;
                        continue;
                    } else {
                        // double dot not allowed
                        return false;
                    }
                }
                if !is_valid_label(name, offset, i) {
                    return false;
                }
                offset = i + 1;
                non_empty_groups += 1;
            }
            i += 1;
        }
        if offset == i {
            non_empty_groups > 0
        } else {
            is_valid_label(name, offset, i)
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_fun_call)]
mod tests {
    use super::*;

    #[test]
    fn test_specials() {
        assert_eq!(Domain::localhost(), "localhost");
        assert_eq!(Domain::example(), "example.com");
    }

    #[test]
    fn test_domain_parse_valid() {
        for str in [
            "example.com",
            "www.example.com",
            "a-b-c.com",
            "a-b-c.example.com",
            "a-b-c.example",
            "aA1",
            ".example.com",
            "example.com.",
            ".example.com.",
        ] {
            let msg = format!("to parse: {}", str);
            assert_eq!(Domain::try_from(str.to_owned()).expect(msg.as_str()), str);
            assert_eq!(
                Domain::try_from(str.as_bytes().to_vec()).expect(msg.as_str()),
                str
            );
        }
    }

    #[test]
    fn test_domain_parse_invalid() {
        for str in [
            "",
            ".",
            "..",
            "-",
            ".-",
            "-.",
            ".-.",
            "-.-.",
            "-.-.-",
            ".-.-",
            "-example.com",
            "local!host",
            "thislabeliswaytoolongforbeingeversomethingwewishtocareabout-example.com",
            "example-thislabeliswaytoolongforbeingeversomethingwewishtocareabout.com",
            "こんにちは",
            "こんにちは.com",
            "😀",
            "example..com",
            "example dot com",
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
        ] {
            assert!(Domain::try_from(str.to_owned()).is_err());
            assert!(Domain::try_from(str.as_bytes().to_vec()).is_err());
        }
    }
}
