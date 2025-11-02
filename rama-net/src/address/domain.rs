use super::Host;
use rama_core::error::{ErrorContext, OpaqueError};
use smol_str::SmolStr;
use std::{cmp::Ordering, fmt, iter::repeat};

/// A domain.
///
/// # Remarks
///
/// The validation of domains created by this type is very shallow.
/// Proper validation is offloaded to other services such as DNS resolvers.
#[derive(Debug, Clone)]
pub struct Domain(SmolStr);

impl Domain {
    /// Creates a domain at compile time.
    ///
    /// This function requires the static string to be a valid domain
    ///
    /// # Panics
    ///
    /// This function panics at **compile time** when the static string is not a valid domain.
    #[must_use]
    pub const fn from_static(s: &'static str) -> Self {
        if !is_valid_name(s.as_bytes()) {
            panic!("static str is an invalid domain");
        }
        Self(SmolStr::new_static(s))
    }

    /// Creates the example [`Domain].
    #[must_use]
    pub fn example() -> Self {
        Self::from_static("example.com")
    }

    /// Create an new apex [`Domain`] (TLD) meant for loopback purposes.
    ///
    /// As proposed in
    /// <https://itp.cdn.icann.org/en/files/security-and-stability-advisory-committee-ssac-reports/sac-113-en.pdf>.
    ///
    /// In specific this means that it will match on any domain with the TLD `.internal`.
    #[must_use]
    pub fn tld_private() -> Self {
        Self::from_static("internal")
    }

    /// Creates the localhost [`Domain`].
    #[must_use]
    pub fn tld_localhost() -> Self {
        Self::from_static("localhost")
    }

    /// Consumes the domain as a host.
    #[must_use]
    pub fn into_host(self) -> Host {
        Host::Name(self)
    }

    /// Returns `true` if this domain is a Fully Qualified Domain Name.
    #[must_use]
    pub fn is_fqdn(&self) -> bool {
        self.0.ends_with('.')
    }

    /// Returns `true` if this domain is a wildcard domain.
    #[must_use]
    pub fn is_wildcard(&self) -> bool {
        self.0.starts_with("*.")
    }

    /// Returns `true` if this domain is Top-Level [`Domain`] (TLD).
    ///
    /// Note that we consider a country-level TLD (ccTLD) such as `org.uk`
    /// also a TLD. That is we consider any `ccTLD` also `TLD`. While
    /// not technically correct, in practice it is at least for the purposes
    /// that we are aware of a non-meaningful distinction to make.
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Domain;
    ///
    /// assert!(Domain::from_static("com").is_tld());
    /// assert!(Domain::from_static(".com").is_tld());
    /// assert!(Domain::from_static("co.uk").is_tld());
    ///
    /// assert!(!Domain::from_static("example.com").is_tld());
    /// assert!(!Domain::from_static("example.co.uk").is_tld());
    /// ```
    #[must_use]
    pub fn is_tld(&self) -> bool {
        self.suffix()
            .map(|s| cmp_domain(&self.0, s).is_eq())
            .unwrap_or_default()
    }

    /// Returns `true` if this domain is Second-Level [`Domain`] (SLD).
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Domain;
    ///
    /// assert!(!Domain::from_static("com").is_sld());
    /// assert!(!Domain::from_static(".com").is_sld());
    /// assert!(!Domain::from_static("co.uk").is_sld());
    /// assert!(!Domain::from_static(".co.uk").is_sld());
    ///
    /// assert!(Domain::from_static(".example.com").is_sld());
    /// assert!(Domain::from_static(".example.co.uk").is_sld());
    ///
    /// assert!(!Domain::from_static("foo.example.com").is_sld());
    /// assert!(!Domain::from_static("foo.example.co.uk").is_sld());
    /// ```
    #[must_use]
    pub fn is_sld(&self) -> bool {
        self.suffix()
            .and_then(|s| self.0.strip_suffix(s))
            .map(|s| {
                let s = s.trim_matches('.');
                !(s.is_empty() || s.contains('.'))
            })
            .unwrap_or_default()
    }

    /// Returns the parent of this wildcard domain,
    /// in case it is indeed a wildcast domain,
    /// otherwise `None` is returned.
    ///
    /// Use [`Self::is_wildcard`] if you just wish to check
    /// it is is a wildcard domain, as it is cheaper to use.
    #[must_use]
    pub fn as_wildcard_parent(&self) -> Option<Self> {
        self.0.strip_prefix("*.").map(|s| Self(s.into()))
    }

    /// Try to create a subdomain from the current [`Domain`] with the given
    /// subdomain prefixed to it
    pub fn try_as_sub(&self, sub: impl AsDomainRef) -> Result<Self, OpaqueError> {
        let sub = smol_str::format_smolstr!("{}.{}", sub.domain_as_str(), self.0);
        if !is_valid_name(sub.as_bytes()) {
            return Err(OpaqueError::from_display("invalid subdomain"));
        }
        Ok(Self(sub))
    }

    /// Promote this [`Domain`] to a wildcard.
    ///
    /// E.g. turn `example.com` in `*.example.com`.
    ///
    /// This can fail, e.g. because the domain becomes too long.
    pub fn try_as_wildcard(&self) -> Result<Self, OpaqueError> {
        let sub = smol_str::format_smolstr!("*.{}", self.0);
        if !is_valid_name(sub.as_bytes()) {
            return Err(OpaqueError::from_display("invalid subdomain"));
        }
        Ok(Self(sub))
    }

    /// Try to strip the subdomain (prefix) from the current domain.
    pub fn strip_sub(&self, prefix: impl AsDomainRef) -> Option<Self> {
        self.0
            .strip_prefix(prefix.domain_as_str())
            .and_then(|s| s.trim_start_matches('.').parse().ok())
    }

    /// Returns `true` if this [`Domain`] is a parent of the other.
    ///
    /// Note that a [`Domain`] is a sub of itself.
    #[must_use]
    pub fn is_sub_of(&self, other: &Self) -> bool {
        let a = self.as_ref().trim_matches('.');
        let b = other.as_ref().trim_matches('.');
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
    #[must_use]
    pub fn is_parent_of(&self, other: &Self) -> bool {
        other.is_sub_of(self)
    }

    /// Compare the registrable domain
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Domain;
    ///
    /// assert!(Domain::from_static("www.example.com")
    ///     .have_same_registrable_domain(&Domain::from_static("example.com")));
    ///
    /// assert!(Domain::from_static("example.com")
    ///     .have_same_registrable_domain(&Domain::from_static("www.example.com")));
    ///
    /// assert!(Domain::from_static("a.example.com")
    ///     .have_same_registrable_domain(&Domain::from_static("b.example.com")));
    ///
    /// assert!(Domain::from_static("example.com")
    ///     .have_same_registrable_domain(&Domain::from_static("example.com")));
    /// ```
    #[must_use]
    pub fn have_same_registrable_domain(&self, other: &Self) -> bool {
        let this_rd = psl::domain_str(self.as_str());
        let other_rd = psl::domain_str(other.as_str());
        this_rd == other_rd
    }

    /// Get the public suffix of the domain
    ///
    /// # Example
    ///
    /// ```
    /// use rama_net::address::Domain;
    ///
    /// assert_eq!(Some("com"), Domain::from_static("www.example.com").suffix());
    /// assert_eq!(Some("co.uk"), Domain::from_static("site.co.uk").suffix());
    /// ```
    #[must_use]
    pub fn suffix(&self) -> Option<&str> {
        psl::suffix_str(self.as_str())
    }

    /// Gets the length of domain
    #[allow(clippy::len_without_is_empty)]
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Gets the domain name as reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.as_ref()
    }

    /// Returns the domain name inner value.
    ///
    /// Should not be exposed in the public rama API.
    pub(crate) fn into_inner(self) -> SmolStr {
        self.0
    }
}

impl std::hash::Hash for Domain {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let this = self.as_ref();
        let this = this.strip_prefix('.').unwrap_or(this);
        for b in this.bytes() {
            let b = b.to_ascii_lowercase();
            b.hash(state);
        }
    }
}

impl AsRef<str> for Domain {
    fn as_ref(&self) -> &str {
        self.0.as_str()
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
        Self::try_from(s.to_owned())
    }
}

impl TryFrom<String> for Domain {
    type Error = OpaqueError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        if is_valid_name(name.as_bytes()) {
            Ok(Self(SmolStr::new(name)))
        } else {
            Err(OpaqueError::from_display("invalid domain"))
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Domain {
    type Error = OpaqueError;

    fn try_from(name: &'a [u8]) -> Result<Self, Self::Error> {
        if is_valid_name(name) {
            Ok(Self(SmolStr::new(
                std::str::from_utf8(name).context("convert domain bytes to utf-8 string")?,
            )))
        } else {
            Err(OpaqueError::from_display("invalid domain"))
        }
    }
}

impl TryFrom<Vec<u8>> for Domain {
    type Error = OpaqueError;

    fn try_from(name: Vec<u8>) -> Result<Self, Self::Error> {
        if is_valid_name(name.as_slice()) {
            Ok(Self(SmolStr::new(
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

impl PartialOrd<Self> for Domain {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
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
    #[inline(always)]
    fn partial_cmp(&self, other: &Domain) -> Option<Ordering> {
        Some(cmp_domain(self, other))
    }
}

impl PartialOrd<String> for Domain {
    #[inline(always)]
    fn partial_cmp(&self, other: &String) -> Option<Ordering> {
        Some(cmp_domain(self, other))
    }
}

impl PartialOrd<Domain> for String {
    #[inline(always)]
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

impl PartialEq<Self> for Domain {
    fn eq(&self, other: &Self) -> bool {
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
    #[inline(always)]
    fn eq(&self, other: &Domain) -> bool {
        partial_eq_domain(self, other)
    }
}

impl PartialEq<String> for Domain {
    #[inline(always)]
    fn eq(&self, other: &String) -> bool {
        partial_eq_domain(self, other)
    }
}

impl PartialEq<Domain> for String {
    #[inline(always)]
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
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
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
            if !c.is_ascii_alphanumeric() && c != b'_' && (c != b'-' || i == start) {
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

        // wildcard special case, only needed once
        if name[0] == b'*' {
            if name.len() <= 2 || name[1] != b'.' {
                return false;
            }
            offset = 2;
            i = 2;
            non_empty_groups = 1;
        }

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

#[allow(private_bounds)]
/// A trait which is used by the `rama-net` crate
/// for places where we wish to have access to
/// a reference to a Domain, directly or indirectly,
/// for non-move purposes.
///
/// For example to compare it, or use it in a derived form.
pub trait AsDomainRef: seal::AsDomainRefPrivate {
    fn as_wildcard_parent(&self) -> Option<Domain> {
        self.domain_as_str()
            .strip_prefix("*.")
            .and_then(|s| s.parse().ok())
    }
}

impl AsDomainRef for &'static str {}
impl AsDomainRef for Domain {}
impl<T: seal::AsDomainRefPrivate> AsDomainRef for &T {}

/// A trait which can be use by crates where a Domain is expected,
/// it can however only be implemented by the rama-net rate.
pub trait IntoDomain: seal::IntoDomainImpl {}

impl IntoDomain for &'static str {}
impl IntoDomain for Domain {}

pub(super) mod seal {
    pub(in crate::address) trait AsDomainRefPrivate {
        fn domain_as_str(&self) -> &str;
    }

    impl AsDomainRefPrivate for &'static str {
        fn domain_as_str(&self) -> &str {
            if !super::is_valid_name(self.as_bytes()) {
                panic!("static str is an invalid domain");
            }
            self
        }
    }

    impl AsDomainRefPrivate for super::Domain {
        fn domain_as_str(&self) -> &str {
            self.as_str()
        }
    }

    impl<T: AsDomainRefPrivate> AsDomainRefPrivate for &T {
        #[inline(always)]
        fn domain_as_str(&self) -> &str {
            (**self).domain_as_str()
        }
    }

    pub trait IntoDomainImpl {
        fn into_domain(self) -> super::Domain;
    }

    impl IntoDomainImpl for &'static str {
        #[inline(always)]
        fn into_domain(self) -> super::Domain {
            super::Domain::from_static(self)
        }
    }

    impl IntoDomainImpl for super::Domain {
        #[inline]
        fn into_domain(self) -> super::Domain {
            self
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_fun_call)]
mod tests {
    use super::*;
    use ahash::{HashMap, HashMapExt as _};

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
            "_acme-challenge.example.com",
            "_acme-challenge_.example.com",
            "_acme_challenge_.example.com",
            "www.example.com",
            "*.com", // technically invalid, but valid for us *shrug*
            "*.example.com",
            "a-b-c.com",
            "a-b-c.example.com",
            "a-b-c.example",
            "aA1",
            ".example.com",
            "example.com.",
            ".example.com.",
            "rr5---sn-q4fl6n6s.video.com", // multiple dashes
            "127.0.0.1",
        ] {
            let msg = format!("to parse: {str}");
            assert_eq!(Domain::try_from(str.to_owned()).expect(msg.as_str()), str);
            assert_eq!(
                Domain::try_from(str.as_bytes().to_vec()).expect(msg.as_str()),
                str
            );
        }
    }

    #[test]
    fn test_domain_is_wildcard() {
        assert!(!Domain::from_static("localhost").is_wildcard());
        assert!(!Domain::from_static("example.com").is_wildcard());
        assert!(!Domain::from_static("foo.example.com").is_wildcard());

        assert!(Domain::from_static("*.com").is_wildcard());
        assert!(Domain::from_static("*.example.com").is_wildcard());
        assert!(Domain::from_static("*.foo.example.com").is_wildcard());
    }

    #[test]
    fn test_domain_as_wildcard_parent() {
        assert!(
            Domain::from_static("localhost")
                .as_wildcard_parent()
                .is_none()
        );
        assert!(
            Domain::from_static("example.com")
                .as_wildcard_parent()
                .is_none()
        );
        assert!(
            Domain::from_static("foo.example.com")
                .as_wildcard_parent()
                .is_none()
        );

        assert_eq!(
            Some(Domain::from_static("com")),
            Domain::from_static("*.com").as_wildcard_parent()
        );
        assert_eq!(
            Some(Domain::from_static("example.com")),
            Domain::from_static("*.example.com").as_wildcard_parent()
        );
        assert_eq!(
            Some(Domain::from_static("foo.example.com")),
            Domain::from_static("*.foo.example.com").as_wildcard_parent()
        );
    }

    #[test]
    fn test_domain_parse_invalid() {
        for str in [
            "",
            ".",
            "..",
            "-",
            "*",
            ".*",
            "*.",
            ".*.",
            ".-",
            "-.",
            ".-.",
            "-.-.",
            "-.-.-",
            ".-.-",
            "2001:db8:3333:4444:5555:6666:7777:8888",
            "-example.com",
            "foo.*.com",
            "*example.com",
            "*foo",
            "o*o",
            "fo*",
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
            assert!(Domain::try_from(str.to_owned()).is_err(), "input = '{str}'");
            assert!(
                Domain::try_from(str.as_bytes().to_vec()).is_err(),
                "input = '{str}'"
            );
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
            assert!(a.is_parent_of(&b), "({a:?}).is_parent_of({b})");
        }
    }

    #[test]
    fn as_wildcard_sub() {
        let test_cases = vec![
            ("example.com", "*.example.com"),
            ("fp.ramaproxy.org", "*.fp.ramaproxy.org"),
            ("print.co.uk", "*.print.co.uk"),
        ];
        for (domain_raw, expected_output) in test_cases.into_iter() {
            let domain = Domain::from_static(domain_raw);
            let msg = format!("{:?}", (domain_raw, expected_output));
            let subdomain = domain.try_as_wildcard().expect(&msg);
            assert_eq!(expected_output, subdomain);
            assert!(subdomain.is_wildcard());
            assert_eq!(Some(domain), subdomain.as_wildcard_parent())
        }
    }

    #[test]
    fn as_sub_success() {
        let test_cases = vec![
            ("example.com", "www", "www.example.com"),
            ("fp.ramaproxy.org", "h1", "h1.fp.ramaproxy.org"),
            (
                // long, but just within limit (251+2)
                "dadadadadadadadadad.llgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.co.uk",
                "a",
                "a.dadadadadadadadadad.llgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.co.uk",
            ),
        ];
        for (domain_raw, sub, expected_output) in test_cases.into_iter() {
            let domain = Domain::from_static(domain_raw);
            let msg = format!("{:?}", (domain_raw, sub, expected_output));
            let subdomain = domain.try_as_sub(sub).expect(&msg);
            assert_eq!(expected_output, subdomain);
        }
    }

    #[test]
    fn as_sub_failure() {
        let test_cases = vec![
            // too long (254 > 253)
            (
                "adadadadadadadadadad.llgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch.co.uk",
                "a",
            ),
        ];
        for (domain_raw, sub) in test_cases.into_iter() {
            let domain = Domain::from_static(domain_raw);
            let msg = format!("{:?}", (domain_raw, sub));
            let _ = domain.try_as_sub(sub).expect_err(&msg);
        }
    }

    #[test]
    fn strip_sub() {
        let test_cases = vec![
            ("www.example.com", "www", Some("example.com")),
            ("example.com", "www", None),
            ("www.www.example.com", "www", Some("www.example.com")),
        ];
        for (sub_raw, prefix, expected_output) in test_cases.into_iter() {
            let sub = Domain::from_static(sub_raw);
            let result = sub.strip_sub(prefix);
            let expected_result = expected_output.map(Domain::from_static);
            assert_eq!(expected_result, result);
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
            assert!(!a.is_parent_of(&b), "!({a:?}).is_parent_of({b})");
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
    fn is_tld() {
        for (expected, input) in [
            (true, ".com"),
            (true, "com"),
            (true, "co.uk"),
            (true, ".co.uk"),
            (false, "example.com"),
            (false, "foo.uk"),
            (false, "foo.example.com"),
        ] {
            assert_eq!(
                expected,
                Domain::from_static(input).is_tld(),
                "input: {input}"
            )
        }
    }

    #[test]
    fn is_sld() {
        for (expected, input) in [
            (false, "com"),
            (false, "co.uk"),
            (true, "example.com"),
            (true, ".example.com"),
            (true, "foo.uk"),
            (true, ".foo.uk"),
            (false, "foo.example.com"),
        ] {
            assert_eq!(
                expected,
                Domain::from_static(input).is_sld(),
                "input: {input}"
            )
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
