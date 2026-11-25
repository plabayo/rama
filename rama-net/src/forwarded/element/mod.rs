use core::{
    cmp::Ordering,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use rama_core::error::BoxError;
use rama_utils::byte_set::is_http_token;

use super::{ForwardedProtocol, ForwardedVersion, NodeId};
use crate::{
    address::{Domain, Host, HostWithOptPort, HostWithPort, SocketAddress},
    std::{boxed::Box, collections::BTreeMap, string::String, vec::Vec},
};

mod parser;
#[doc(inline)]
pub(crate) use parser::{parse_one_plus_forwarded_elements, parse_single_forwarded_element};

#[derive(Debug, Clone, PartialEq, Eq)]
/// A single entry in the [`Forwarded`] chain.
///
/// [`Forwarded`]: crate::forwarded::Forwarded
pub struct ForwardedElement {
    by_node: Option<NodeId>,
    for_node: Option<NodeId>,
    authority: Option<ForwardedAuthority>,
    proto: Option<ForwardedProtocol>,
    proto_version: Option<ForwardedVersion>,

    // not expected, but if used these parameters (keys)
    // should be registered ideally also in
    // <https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#forwarded>
    // BTreeMap (not a hash map): tiny-or-absent in practice, and it keeps
    // this type free of hasher deps in no_std builds.
    extensions: Option<BTreeMap<ExtensionName, ExtensionValue>>,
}

#[derive(Debug, Clone)]
struct ExtensionName(Box<str>);

impl PartialEq for ExtensionName {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for ExtensionName {}

impl PartialOrd for ExtensionName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExtensionName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .bytes()
            .map(|b| b.to_ascii_lowercase())
            .cmp(other.0.bytes().map(|b| b.to_ascii_lowercase()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExtensionValue {
    value: Box<str>,
    quoted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Wrapper of a value [`HostWithOptPort`] to provide some forward-specific utilities.
pub struct ForwardedAuthority(pub HostWithOptPort);

impl ForwardedAuthority {
    /// Create a new [`ForwardedAuthority`]
    #[must_use]
    #[inline(always)]
    pub const fn new(host: Host) -> Self {
        Self(HostWithOptPort::new(host))
    }

    /// Create a new [`ForwardedAuthority`] with port
    #[must_use]
    #[inline(always)]
    pub const fn new_with_port(host: Host, port: u16) -> Self {
        Self(HostWithOptPort::new_with_port(host, port))
    }
}

impl From<Host> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: Host) -> Self {
        Self::new(value)
    }
}

impl From<Domain> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: Domain) -> Self {
        Self::new(value.into())
    }
}

impl From<IpAddr> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: IpAddr) -> Self {
        Self::new(value.into())
    }
}

impl From<Ipv4Addr> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: Ipv4Addr) -> Self {
        Self::new(value.into())
    }
}

impl From<[u8; 4]> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: [u8; 4]) -> Self {
        Self::new(Host::Address(value.into()))
    }
}

impl From<[u8; 16]> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: [u8; 16]) -> Self {
        Self::new(Host::Address(value.into()))
    }
}

impl From<Ipv6Addr> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: Ipv6Addr) -> Self {
        Self::new(value.into())
    }
}

impl From<SocketAddr> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: SocketAddr) -> Self {
        Self(HostWithOptPort {
            host: Host::Address(value.ip()),
            port: crate::address::OptPort::Set(value.port()),
        })
    }
}

impl From<SocketAddress> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: SocketAddress) -> Self {
        Self(HostWithOptPort {
            host: Host::Address(value.ip_addr),
            port: crate::address::OptPort::Set(value.port),
        })
    }
}

impl From<HostWithOptPort> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: HostWithOptPort) -> Self {
        Self(value)
    }
}

impl From<HostWithPort> for ForwardedAuthority {
    #[inline(always)]
    fn from(value: HostWithPort) -> Self {
        Self::new(value.into())
    }
}

impl ForwardedElement {
    /// Merge the properties of another [`ForwardedElement`] into this one.
    pub fn merge(&mut self, other: Self) -> &mut Self {
        if let Some(by_node) = other.by_node {
            self.by_node = Some(by_node);
        }
        if let Some(for_node) = other.for_node {
            self.for_node = Some(for_node);
        }
        if let Some(authority) = other.authority {
            self.authority = Some(authority);
        }
        if let Some(proto) = other.proto {
            self.proto = Some(proto);
        }
        if let Some(extensions) = other.extensions {
            match &mut self.extensions {
                Some(map) => {
                    map.extend(extensions);
                }
                None => {
                    self.extensions = Some(extensions);
                }
            }
        }
        self
    }

    /// Return the host if one is defined.
    #[must_use]
    pub fn authority(&self) -> Option<HostWithOptPort> {
        self.authority.as_ref().map(|authority| authority.0.clone())
    }

    /// Create a new [`ForwardedElement`] with the "host" parameter set
    /// using the given [`Host`], [`Domain`], [`HostWithPort`], [`IpAddr`], [`SocketAddress`] and more.
    pub fn new_forwarded_host(authority: impl Into<ForwardedAuthority>) -> Self {
        Self {
            by_node: None,
            for_node: None,
            authority: Some(authority.into()),
            proto: None,
            proto_version: None,
            extensions: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets the "host" parameter in this [`ForwardedElement`] using
        /// the given authority value.
        pub fn forwarded_host(mut self, authority: impl Into<ForwardedAuthority>) -> Self {
            self.authority = Some(authority.into());
            self
        }
    }

    /// Get a reference to the "host" parameter if it is set.
    #[must_use]
    pub fn forwarded_host(&self) -> Option<&ForwardedAuthority> {
        self.authority.as_ref()
    }

    /// Create a new [`ForwardedElement`] with the "for" parameter
    /// set to the given valid node identifier. Examples are
    /// an Ip Address or Domain, with or without a port.
    pub fn new_forwarded_for(node_id: impl Into<NodeId>) -> Self {
        Self {
            by_node: None,
            for_node: Some(node_id.into()),
            authority: None,
            proto: None,
            proto_version: None,
            extensions: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets the "for" parameter for this [`ForwardedElement`] using the given valid node identifier.
        /// Examples are an Ip Address or Domain, with or without a port.
        pub fn forwarded_for(mut self, node_id: impl Into<NodeId>) -> Self {
            self.for_node = Some(node_id.into());
            self
        }
    }

    /// Get a reference to the "for" parameter if it is set.
    #[must_use]
    pub fn forwarded_for(&self) -> Option<&NodeId> {
        self.for_node.as_ref()
    }

    /// Create a new [`ForwardedElement`] with the "by" parameter
    /// set to the given valid node identifier. Examples are
    /// an Ip Address or Domain, with or without a port.
    pub fn new_forwarded_by(node_id: impl Into<NodeId>) -> Self {
        Self {
            by_node: Some(node_id.into()),
            for_node: None,
            authority: None,
            proto: None,
            proto_version: None,
            extensions: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets the "by" parameter for this [`ForwardedElement`] using the given valid node identifier.
        /// Examples are an Ip Address or Domain, with or without a port.
        pub fn forwarded_by(mut self, node_id: impl Into<NodeId>) -> Self {
            self.by_node = Some(node_id.into());
            self
        }
    }

    /// Get a reference to the "by" parameter if it is set.
    #[must_use]
    pub fn forwarded_by(&self) -> Option<&NodeId> {
        self.by_node.as_ref()
    }

    /// Create a new [`ForwardedElement`] with the "proto" parameter
    /// set to the given valid/recognised [`ForwardedProtocol`]
    #[must_use]
    pub fn new_forwarded_proto(protocol: ForwardedProtocol) -> Self {
        Self {
            by_node: None,
            for_node: None,
            authority: None,
            proto: Some(protocol),
            proto_version: None,
            extensions: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the "proto" parameter to the given valid/recognised [`ForwardedProtocol`].
        pub fn forwarded_proto(mut self, protocol: ForwardedProtocol) -> Self {
            self.proto = Some(protocol);
            self
        }
    }

    /// Get a reference to the "proto" parameter if it is set.
    #[must_use]
    pub fn forwarded_proto(&self) -> Option<ForwardedProtocol> {
        self.proto.clone()
    }

    /// Create a new [`ForwardedElement`] with the "version" parameter
    /// set to the given valid/recognised [`ForwardedVersion`].
    #[must_use]
    pub fn new_forwarded_version(version: ForwardedVersion) -> Self {
        Self {
            by_node: None,
            for_node: None,
            authority: None,
            proto: None,
            proto_version: Some(version),
            extensions: None,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the "version" parameter to the given valid/recognised [`ForwardedVersion`].
        pub fn forwarded_version(mut self, version: ForwardedVersion) -> Self {
            self.proto_version = Some(version);
            self
        }
    }

    /// Get a copy of the "version" parameter, if it is set.
    #[must_use]
    pub fn forwarded_version(&self) -> Option<ForwardedVersion> {
        self.proto_version
    }
}

impl fmt::Display for ForwardedAuthority {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for ForwardedElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut separator = "";

        if let Some(ref by_node) = self.by_node {
            write!(f, "by=")?;
            let quoted =
                by_node.has_any_port() || by_node.ip().map(|ip| ip.is_ipv6()).unwrap_or_default();
            if quoted {
                write!(f, r##""{by_node}""##)?;
            } else {
                by_node.fmt(f)?;
            }
            separator = ";";
        }

        if let Some(ref for_node) = self.for_node {
            write!(f, "{separator}for=")?;
            let quoted =
                for_node.has_any_port() || for_node.ip().map(|ip| ip.is_ipv6()).unwrap_or_default();
            if quoted {
                write!(f, r##""{for_node}""##)?;
            } else {
                for_node.fmt(f)?;
            }
            separator = ";";
        }

        if let Some(ref authority) = self.authority {
            write!(f, "{separator}host=")?;
            // RFC 7239 §4: only a port-less domain or IPv4 host is a valid token
            let quoted = authority.0.port.is_explicit()
                || !matches!(
                    authority.0.host,
                    Host::Name(_) | Host::Address(IpAddr::V4(_))
                );
            if quoted {
                write!(f, r##""{authority}""##)?;
            } else {
                authority.fmt(f)?;
            }
            separator = ";";
        }

        if let Some(ref proto) = self.proto {
            write!(f, "{separator}proto=")?;
            proto.fmt(f)?;
            separator = ";";
        }

        for (key, ext) in self.extensions.iter().flatten() {
            write!(f, "{separator}{}=", key.0)?;
            if ext.quoted || !is_http_token(ext.value.as_bytes()) {
                f.write_str("\"")?;
                for c in ext.value.chars() {
                    if c == '"' || c == '\\' {
                        f.write_str("\\")?;
                    }
                    write!(f, "{c}")?;
                }
                f.write_str("\"")?;
            } else {
                f.write_str(&ext.value)?;
            }
            separator = ";";
        }

        Ok(())
    }
}

impl core::str::FromStr for ForwardedElement {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_single_forwarded_element(s.as_bytes())
    }
}

impl TryFrom<String> for ForwardedElement {
    type Error = BoxError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        parse_single_forwarded_element(s.as_bytes())
    }
}

impl TryFrom<&str> for ForwardedElement {
    type Error = BoxError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        parse_single_forwarded_element(s.as_bytes())
    }
}

impl TryFrom<Vec<u8>> for ForwardedElement {
    type Error = BoxError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        parse_single_forwarded_element(bytes.as_ref())
    }
}

impl TryFrom<&[u8]> for ForwardedElement {
    type Error = BoxError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        parse_single_forwarded_element(bytes)
    }
}

impl core::str::FromStr for ForwardedAuthority {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let address = HostWithOptPort::from_str(s)?;
        Ok(Self(address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarded::Forwarded;

    fn split_unquoted(input: &str, sep: char) -> Vec<&str> {
        let mut parts = Vec::new();
        let (mut start, mut quoted, mut escaped) = (0, false, false);
        for (i, c) in input.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' if quoted => escaped = true,
                '"' => quoted = !quoted,
                c if c == sep && !quoted => {
                    parts.push(&input[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
        parts.push(&input[start..]);
        parts
    }

    fn unquoted(value: &str) -> Box<str> {
        let Some(inner) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) else {
            assert!(is_http_token(value.as_bytes()), "value {value:?}");
            return value.into();
        };
        let mut decoded = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            decoded.push(if c == '\\' { chars.next().unwrap() } else { c });
        }
        decoded.into_boxed_str()
    }

    fn strict_elements(input: &str) -> Vec<Vec<(Box<str>, Box<str>)>> {
        split_unquoted(input, ',')
            .into_iter()
            .map(|element| {
                let mut pairs: Vec<(Box<str>, Box<str>)> = split_unquoted(element, ';')
                    .into_iter()
                    .filter(|pair| !pair.trim().is_empty())
                    .map(|pair| {
                        let (name, value) = pair.split_once('=').expect("pair has a value");
                        let name = name.trim();
                        assert!(is_http_token(name.as_bytes()), "name {name:?} in {input}");
                        (name.to_ascii_lowercase().into(), unquoted(value.trim()))
                    })
                    .collect();
                pairs.sort();
                pairs
            })
            .collect()
    }

    #[test]
    fn a_bare_pair_name_cannot_smuggle_an_element() {
        for input in ["for=_a;b,c=d", "for=_a;b,for=_c", "for=_a;b ,for=_c"] {
            Forwarded::try_from(input).unwrap_err();
        }
        ForwardedElement::try_from("for=_a;b").unwrap_err();
    }

    #[test]
    fn pair_names_must_be_tokens() {
        for delimiter in [
            " ", "\t", ",", ";", "(", ")", "<", ">", "@", "/", "?", "{", "}", "[", "]", ":", "\"",
            "\\",
        ] {
            let input = format!("for=_a;e{delimiter}x=1");
            Forwarded::try_from(input.as_str()).expect_err(&input);
            ForwardedElement::try_from(input.as_str()).expect_err(&input);
        }
        ForwardedElement::try_from("for=_a;e!#$%&'*+-.^_`|~x=1").unwrap();
    }

    #[test]
    fn empty_pairs_are_skipped_and_a_comma_after_one_ends_the_element() {
        let forwarded = Forwarded::try_from("for=_a;;proto=http;, for=_c").unwrap();
        let elements: Vec<_> = forwarded.iter().collect();
        assert_eq!(elements.len(), 2);
        assert!(elements[0].forwarded_proto().is_some());
        assert!(elements[1].forwarded_for().is_some());
    }

    #[test]
    fn emitted_elements_read_the_same_to_a_strict_parser() {
        for input in [
            "for=_a;ext=x, for=_b;other=y",
            r#"for=_a;ext="a,b;c=d", for=_b"#,
            r#"for=_a;ext="x\"y", for=_b"#,
            "for=_a;Ext=x;;proto=http",
            r#"for="[::1]:80";by=unknown;host="[::1]";proto=https;e-x.t=v"#,
            "for=192.0.2.43, for=198.51.100.17",
        ] {
            let forwarded = Forwarded::try_from(input).expect(input);
            let shown = forwarded.to_string();
            let strict = strict_elements(&shown);
            assert_eq!(strict.len(), forwarded.iter().count(), "{input} -> {shown}");
            assert_eq!(strict, strict_elements(input), "{input} -> {shown}");
        }
        for input in ["for=_a;b,c=d", "for=_a;b c=d", "for=_a;b,for=_c"] {
            Forwarded::try_from(input).expect_err(input);
        }
    }

    #[test]
    fn a_parameter_occurs_once_per_element_whatever_its_case() {
        for input in [
            "for=_a;x=1;X=2",
            ";for=_a;x=1;X=2",
            "for=_a;x=1;x=2",
            "for=_a;For=_b",
        ] {
            Forwarded::try_from(input).expect_err(input);
        }
        let element = ForwardedElement::try_from("for=_a;Ext=1").unwrap();
        assert_eq!(element.to_string(), "for=_a;Ext=1");
    }

    #[test]
    fn an_unquoted_value_is_a_token() {
        for input in [
            "for=_a;ext=a b",
            "for=_a;ext=",
            "for=_a;ext=(x)",
            "for=",
            "for=_a;ext=a@b",
        ] {
            Forwarded::try_from(input).expect_err(input);
        }
        for input in [
            "for=_a ;ext=x ",
            "for=_a;ext=x\t, for=_b",
            "for=_a;ext=\"a b\"",
        ] {
            Forwarded::try_from(input).expect(input);
        }
    }

    #[test]
    fn display_round_trips_through_the_parser() {
        for input in [
            "for=_a;ext=x",
            r#"for=_a;ext="x\"y""#,
            r#"for=_a;ext="a;b,c""#,
            r#"for=_a;ext="""#,
            r#"for="[::1]:80";by=unknown;host="[::1]";proto=https"#,
            r#"for="_hidden:_p""#,
            "for=_a;Ext=x;other=y",
        ] {
            let el: ForwardedElement = input.parse().unwrap();
            let shown = el.to_string();
            let reparsed: ForwardedElement = shown
                .parse()
                .unwrap_or_else(|err| panic!("{input} -> {shown}: {err}"));
            assert_eq!(reparsed, el, "{input} -> {shown}");
        }
    }

    #[test]
    fn test_forwarded_element_parse_invalid() {
        for s in [
            "",
            "foobar",
            "127.0.0.1",
            "⌨️",
            "for=_foo;for=_bar",
            "for=foo,proto=http",
        ] {
            if let Ok(el) = ForwardedElement::try_from(s) {
                panic!("unexpected parse success: input {s}: {el:?}");
            }
        }
    }

    #[test]
    fn test_forwarded_element_parse_happy_spec() {
        for (s, expected) in [
            (
                r##"for="_gazonk""##,
                ForwardedElement::new_forwarded_for(NodeId::try_from("_gazonk").unwrap()),
            ),
            (
                r##"For="[2001:db8:cafe::17]:4711""##,
                ForwardedElement::new_forwarded_for(
                    NodeId::try_from("[2001:db8:cafe::17]:4711").unwrap(),
                ),
            ),
            (
                r##"For="[2001:db8:cafe::17]:4711";proto=http"##,
                ForwardedElement {
                    by_node: None,
                    for_node: Some(NodeId::try_from("[2001:db8:cafe::17]:4711").unwrap()),
                    authority: None,
                    proto: Some(ForwardedProtocol::HTTP),
                    proto_version: None,
                    extensions: None,
                },
            ),
            (
                r##"For="[2001:db8:cafe::17]:4711";proto=http;foo=bar"##,
                ForwardedElement {
                    by_node: None,
                    for_node: Some(NodeId::try_from("[2001:db8:cafe::17]:4711").unwrap()),
                    authority: None,
                    proto: Some(ForwardedProtocol::HTTP),
                    proto_version: None,
                    extensions: Some(
                        [(
                            ExtensionName("foo".into()),
                            ExtensionValue {
                                value: "bar".into(),
                                quoted: false,
                            },
                        )]
                        .into_iter()
                        .collect(),
                    ),
                },
            ),
            (
                r##"for=192.0.2.60;proto=http;by=203.0.113.43"##,
                ForwardedElement {
                    by_node: Some(NodeId::try_from("203.0.113.43").unwrap()),
                    for_node: Some(NodeId::try_from("192.0.2.60").unwrap()),
                    authority: None,
                    proto: Some(ForwardedProtocol::HTTP),
                    proto_version: None,
                    extensions: None,
                },
            ),
        ] {
            let element = match ForwardedElement::try_from(s) {
                Ok(el) => el,
                Err(err) => panic!("failed to parse happy spec el '{s}': {err}"),
            };
            assert_eq!(element, expected, "input: {s}");
        }
    }

    #[test]
    fn merged_extension_names_remain_case_insensitively_unique() {
        let mut element = ForwardedElement::try_from("for=_a;Ext=1").unwrap();
        element.merge(ForwardedElement::try_from("for=_b;ext=2").unwrap());
        let reparsed = ForwardedElement::try_from(element.to_string().as_str()).unwrap();
        assert_eq!(reparsed, element);
        assert_eq!(reparsed.extensions.as_ref().unwrap().len(), 1);
        assert_eq!(
            reparsed
                .extensions
                .as_ref()
                .unwrap()
                .values()
                .next()
                .unwrap()
                .value
                .as_ref(),
            "2"
        );
    }

    /// Regression: RFC 7230 §3.2.6 `quoted-string` allows `quoted-pair`
    /// (`\` followed by one byte). The first parser version found the
    /// closing `"` with a naive `position` scan, mis-parsing legal
    /// values like `host="a\"b"` (split mid-value at the escaped quote).
    #[test]
    fn regression_forwarded_quoted_pair_rfc7230() {
        // Escaped `"` inside an extension value must round-trip into the
        // decoded value.
        let el = ForwardedElement::try_from(r#"for=_a;ext="x\"y""#).unwrap();
        let ext = el
            .extensions
            .as_ref()
            .expect("extensions parsed")
            .get(&ExtensionName("ext".into()))
            .expect("ext present");
        assert_eq!(ext.value.as_ref(), r#"x"y"#);
        assert!(ext.quoted);

        // Escaped backslash.
        let el = ForwardedElement::try_from(r#"for=_a;ext="x\\y""#).unwrap();
        let ext = el
            .extensions
            .unwrap()
            .remove(&ExtensionName("ext".into()))
            .unwrap();
        assert_eq!(ext.value.as_ref(), r#"x\y"#);

        // A trailing `\` with no escapable byte must error, not silently
        // succeed (would otherwise be a `quoted-string missing trailer`).
        ForwardedElement::try_from(r#"for=_a;ext="abc\"#).unwrap_err();
    }

    /// Regression: RFC 7230 §3.2.6 `qdtext` permits `obs-text` (0x80–0xFF).
    /// The first parser version rejected the entire 0x80–0xFF range inside
    /// quoted values via a `(32..127)` charset check, which made any
    /// UTF-8 high-byte fail.
    #[test]
    fn regression_forwarded_obs_text_in_qdtext() {
        // UTF-8 encoding of `é` (0xC3 0xA9) inside a quoted ext value.
        let el = ForwardedElement::try_from("for=_a;ext=\"café\"").unwrap();
        let ext = el
            .extensions
            .unwrap()
            .remove(&ExtensionName("ext".into()))
            .unwrap();
        assert_eq!(ext.value.as_ref(), "café");
        // Token-form values stay strict (no obs-text outside quotes).
        ForwardedElement::try_from("for=_a;ext=café").unwrap_err();
    }

    /// Regression: RFC 7230 OWS = `*( SP / HTAB )`. The first parser version
    /// only trimmed SP, so any `\t` around `;`/`=`/list-separator caused a
    /// parse error on otherwise legal Forwarded headers.
    #[test]
    fn regression_forwarded_ows_handles_htab() {
        // HTAB after the `;` separator.
        let el = ForwardedElement::try_from("for=_a;\tproto=http").unwrap();
        assert_eq!(el.forwarded_proto(), Some(ForwardedProtocol::HTTP));
        // HTAB padding around `=` and inside the list comma between elements.
        let s = "for=_a;\tproto=http,\tfor=_b";
        let (first, others) = parse_one_plus_forwarded_elements(s.as_bytes()).unwrap();
        assert_eq!(first.forwarded_for().unwrap().to_string(), "_a");
        assert_eq!(others.len(), 1);
        assert_eq!(others[0].forwarded_for().unwrap().to_string(), "_b");
    }

    /// Regression: a zone-id (RFC 6874) inside a Forwarded `for=` value
    /// must never be accepted. The lower-level `Ipv6Addr` parser already
    /// rejects `%`; this pins the rejection at the Forwarded entry point
    /// so future changes can't silently re-allow it.
    #[test]
    fn regression_forwarded_rejects_ipv6_zone_id() {
        for s in [r#"for="[fe80::1%eth0]""#, r#"for="[fe80::1%25eth0]:80""#] {
            assert!(
                ForwardedElement::try_from(s).is_err(),
                "forwarded element should reject zone-id input {s:?}",
            );
        }
    }

    #[test]
    fn regression_forwarded_host_reg_name_is_quoted_on_display() {
        for (input, expected) in [
            (r#"host="a;for=1.2.3.4""#, r#"host="a;for=1.2.3.4""#),
            (r#"host="a,for=1.2.3.4""#, r#"host="a,for=1.2.3.4""#),
            (r#"host="[v1.fe80::a]""#, r#"host="[v1.fe80::a]""#),
            ("host=example.com", "host=example.com"),
            ("host=192.0.2.1", "host=192.0.2.1"),
        ] {
            let el = ForwardedElement::try_from(input).unwrap();
            let encoded = el.to_string();
            assert_eq!(encoded, expected, "input: {input}");
            let reparsed = ForwardedElement::try_from(encoded.as_str()).unwrap();
            assert_eq!(reparsed, el, "input: {input}");
            assert!(reparsed.forwarded_for().is_none(), "input: {input}");
        }

        let el = ForwardedElement::new_forwarded_host(
            "a;for=1.2.3.4".parse::<ForwardedAuthority>().unwrap(),
        );
        assert_eq!(el.to_string(), r#"host="a;for=1.2.3.4""#);
    }
}
