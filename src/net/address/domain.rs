use super::Host;
use crate::error::{ErrorContext, OpaqueError};
use std::{borrow::Cow, cmp::Ordering, fmt, iter::repeat};

/// A domain.
///
/// # Remarks
///
/// The validation of domains created by this type is very shallow.
/// Proper validation is offloaded to other services such as DNS resolvers.
#[derive(Debug, Clone)]
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

    /// Creates the example [`Domain].
    pub fn example() -> Self {
        Self::from_static("example.com")
    }

    /// Create an new apex [`Domain`] (TLD) meant for loopback purposes.
    ///
    /// As proposed in
    /// <https://itp.cdn.icann.org/en/files/security-and-stability-advisory-committee-ssac-reports/sac-113-en.pdf>.
    ///
    /// In specific this means that it will match on any domain with the TLD `.internal`.
    pub fn tld_private() -> Self {
        Self::from_static("internal")
    }

    /// Creates the localhost [`Domain`].
    pub fn tld_localhost() -> Self {
        Self::from_static("localhost")
    }

    /// Consumes the domain as a host.
    pub fn into_host(self) -> Host {
        Host::Name(self)
    }

    /// Returns `true` if this domain is a Fully Qualified Domain Name.
    pub fn is_fqdn(&self) -> bool {
        self.0.ends_with('.')
    }

    /// Returns `true` if this [`Domain`] is a parent of the other.
    ///
    /// Note that a [`Domain`] is a sub of itself.
    pub fn is_sub_of(&self, other: &Domain) -> bool {
        let a = self.0.as_ref().trim_matches('.');
        let b = other.0.as_ref().trim_matches('.');
        match a.len().cmp(&b.len()) {
            Ordering::Equal => a.eq_ignore_ascii_case(b),
            Ordering::Greater => {
                let n = a.len() - b.len();
                let dot_char = a.chars().nth(n - 1);
                let host_parent = &a[n..];
                dot_char == Some('.') && b.eq_ignore_ascii_case(host_parent)
            }
            Ordering::Less => false,
        }
    }

    #[inline]
    /// Returns `true` if this [`Domain`] is a subdomain of the other.
    ///
    /// Note that a [`Domain`] is a sub of itself.
    pub fn is_parent_of(&self, other: &Domain) -> bool {
        other.is_sub_of(self)
    }

    /// Gets the domain name as reference.
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }

    /// Returns the domain name inner Cow value.
    ///
    /// Should not be exposed in the public rama API.
    pub(crate) fn into_inner(self) -> Cow<'static, str> {
        self.0
    }
}

impl std::hash::Hash for Domain {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let this = self.0.as_ref();
        let this = this.strip_prefix('.').unwrap_or(this);
        for b in this.bytes() {
            let b = b.to_ascii_lowercase();
            b.hash(state);
        }
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

fn cmp_domain(a: impl AsRef<str>, b: impl AsRef<str>) -> Ordering {
    let a = a.as_ref();
    let a = a.strip_prefix('.').unwrap_or(a);
    let a = a.bytes().map(Some).chain(repeat(None));

    let b = b.as_ref();
    let b = b.strip_prefix('.').unwrap_or(b);
    let b = b.bytes().map(Some).chain(repeat(None));

    a.zip(b)
        .find_map(|(a, b)| match (a, b) {
            (Some(a), Some(b)) => match a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase()) {
                Ordering::Greater => Some(Ordering::Greater),
                Ordering::Less => Some(Ordering::Less),
                Ordering::Equal => None,
            },
            (Some(_), None) => Some(Ordering::Greater),
            (None, Some(_)) => Some(Ordering::Less),
            (None, None) => Some(Ordering::Equal),
        })
        .unwrap() // should always be possible to find given we are in an infinite zip :)
}

impl PartialOrd<Domain> for Domain {
    fn partial_cmp(&self, other: &Domain) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Domain {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_domain(self, other)
    }
}

impl PartialOrd<str> for Domain {
    fn partial_cmp(&self, other: &str) -> Option<Ordering> {
        Some(cmp_domain(self, other))
    }
}

impl PartialOrd<Domain> for str {
    fn partial_cmp(&self, other: &Domain) -> Option<Ordering> {
        Some(cmp_domain(self, other))
    }
}

impl PartialOrd<&str> for Domain {
    fn partial_cmp(&self, other: &&str) -> Option<Ordering> {
        Some(cmp_domain(self, other))
    }
}

impl PartialOrd<Domain> for &str {
    fn partial_cmp(&self, other: &Domain) -> Option<Ordering> {
        Some(cmp_domain(self, other))
    }
}

impl PartialOrd<String> for Domain {
    fn partial_cmp(&self, other: &String) -> Option<Ordering> {
        Some(cmp_domain(self, other))
    }
}

impl PartialOrd<Domain> for String {
    fn partial_cmp(&self, other: &Domain) -> Option<Ordering> {
        Some(cmp_domain(self, other))
    }
}

fn partial_eq_domain(a: impl AsRef<str>, b: impl AsRef<str>) -> bool {
    let a = a.as_ref();
    let a = a.strip_prefix('.').unwrap_or(a);

    let b = b.as_ref();
    let b = b.strip_prefix('.').unwrap_or(b);

    a.eq_ignore_ascii_case(b)
}

impl PartialEq<Domain> for Domain {
    fn eq(&self, other: &Domain) -> bool {
        partial_eq_domain(self, other)
    }
}

impl Eq for Domain {}

impl PartialEq<str> for Domain {
    fn eq(&self, other: &str) -> bool {
        partial_eq_domain(self, other)
    }
}

impl PartialEq<&str> for Domain {
    fn eq(&self, other: &&str) -> bool {
        partial_eq_domain(self, other)
    }
}

impl PartialEq<Domain> for str {
    fn eq(&self, other: &Domain) -> bool {
        other == self
    }
}

impl PartialEq<Domain> for &str {
    fn eq(&self, other: &Domain) -> bool {
        partial_eq_domain(self, other)
    }
}

impl PartialEq<String> for Domain {
    fn eq(&self, other: &String) -> bool {
        partial_eq_domain(self, other)
    }
}

impl PartialEq<Domain> for String {
    fn eq(&self, other: &Domain) -> bool {
        partial_eq_domain(self, other)
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
    use std::collections::HashMap;

    #[test]
    fn test_specials() {
        assert_eq!(Domain::tld_localhost(), "localhost");
        assert_eq!(Domain::tld_private(), "internal");
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

    #[test]
    fn is_parent() {
        let test_cases = vec![
            ("www.example.com", "www.example.com"),
            ("www.example.com", "www.example.com."),
            ("www.example.com", ".www.example.com."),
            (".www.example.com", "www.example.com"),
            (".www.example.com", "www.example.com."),
            (".www.example.com.", "www.example.com."),
            ("www.example.com", "WwW.ExamplE.COM"),
            ("example.com", "www.example.com"),
            ("example.com", "m.example.com"),
            ("example.com", "www.EXAMPLE.com"),
            ("example.com", "M.example.com"),
        ];
        for (a, b) in test_cases.into_iter() {
            let a = Domain::from_static(a);
            let b = Domain::from_static(b);
            assert!(a.is_parent_of(&b), "({:?}).is_parent_of({})", a, b);
        }
    }

    #[test]
    fn is_not_parent() {
        let test_cases = vec![
            ("www.example.com", "www.example.co"),
            ("www.example.com", "www.ejemplo.com"),
            ("www.example.com", "www3.example.com"),
            ("w.example.com", "www.example.com"),
            ("gel.com", "kegel.com"),
        ];
        for (a, b) in test_cases.into_iter() {
            let a = Domain::from_static(a);
            let b = Domain::from_static(b);
            assert!(!a.is_parent_of(&b), "!({:?}).is_parent_of({})", a, b);
        }
    }

    #[test]
    fn is_equal() {
        let test_cases = vec![
            ("example.com", "example.com"),
            ("example.com", "EXAMPLE.com"),
            (".example.com", ".example.com"),
            (".example.com", "example.com"),
            ("example.com", ".example.com"),
        ];
        for (a, b) in test_cases.into_iter() {
            assert_eq!(Domain::from_static(a), b);
            assert_eq!(Domain::from_static(a), b.to_owned());
            assert_eq!(Domain::from_static(a), Domain::from_static(b));
            assert_eq!(a, Domain::from_static(b));
            assert_eq!(a.to_owned(), Domain::from_static(b));
        }
    }

    #[test]
    fn is_not_equal() {
        let test_cases = vec![
            ("example.com", "localhost"),
            ("example.com", "example.com."),
            ("example.com", "example.co"),
            ("example.com", "examine.com"),
            ("example.com", "example.com.us"),
            ("example.com", "www.example.com"),
        ];
        for (a, b) in test_cases.into_iter() {
            assert_ne!(Domain::from_static(a), b);
            assert_ne!(Domain::from_static(a), b.to_owned());
            assert_ne!(Domain::from_static(a), Domain::from_static(b));
            assert_ne!(a, Domain::from_static(b));
            assert_ne!(a.to_owned(), Domain::from_static(b));
        }
    }

    #[test]
    fn cmp() {
        let test_cases = vec![
            ("example.com", "example.com", Ordering::Equal),
            ("example.com", "EXAMPLE.com", Ordering::Equal),
            (".example.com", ".example.com", Ordering::Equal),
            (".example.com", "example.com", Ordering::Equal),
            ("example.com", ".example.com", Ordering::Equal),
            ("example.com", "localhost", Ordering::Less),
            ("example.com", "example.com.", Ordering::Less),
            ("example.com", "example.co", Ordering::Greater),
            ("example.com", "examine.com", Ordering::Greater),
            ("example.com", "example.com.us", Ordering::Less),
            ("example.com", "www.example.com", Ordering::Less),
        ];
        for (a, b, expected) in test_cases.into_iter() {
            assert_eq!(Some(expected), Domain::from_static(a).partial_cmp(&b));
            assert_eq!(
                Some(expected),
                Domain::from_static(a).partial_cmp(&b.to_owned())
            );
            assert_eq!(
                Some(expected),
                Domain::from_static(a).partial_cmp(&Domain::from_static(b))
            );
            assert_eq!(
                expected,
                Domain::from_static(a).cmp(&Domain::from_static(b))
            );
            assert_eq!(Some(expected), a.partial_cmp(&Domain::from_static(b)));
            assert_eq!(
                Some(expected),
                a.to_owned().partial_cmp(&Domain::from_static(b))
            );
        }
    }

    #[test]
    fn test_hash() {
        let mut m = HashMap::new();

        assert!(!m.contains_key(&Domain::from_static("example.com")));
        assert!(!m.contains_key(&Domain::from_static("EXAMPLE.COM")));
        assert!(!m.contains_key(&Domain::from_static(".example.com")));
        assert!(!m.contains_key(&Domain::from_static(".example.COM")));

        m.insert(Domain::from_static("eXaMpLe.COm"), ());

        assert!(m.contains_key(&Domain::from_static("example.com")));
        assert!(m.contains_key(&Domain::from_static("EXAMPLE.COM")));
        assert!(m.contains_key(&Domain::from_static(".example.com")));
        assert!(m.contains_key(&Domain::from_static(".example.COM")));

        assert!(!m.contains_key(&Domain::from_static("www.example.com")));
        assert!(!m.contains_key(&Domain::from_static("examine.com")));
        assert!(!m.contains_key(&Domain::from_static("example.com.")));
        assert!(!m.contains_key(&Domain::from_static("example.co")));
        assert!(!m.contains_key(&Domain::from_static("example.commerce")));
    }
}
