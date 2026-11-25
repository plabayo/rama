//! Server identity matching for verifiers that only validate the chain.

use std::net::IpAddr;

use rama_net::{
    address::{DomainLabels as _, DomainRef},
    tls::ServerName,
};
use x509_parser::{certificate::X509Certificate, extensions::GeneralName, prelude::FromDer as _};

/// Whether the subject alternative names of `leaf` cover `server_name`, or
/// `None` when `leaf` is not a certificate.
///
/// A wildcard covers exactly one left-most label, and IP addresses match
/// `iPAddress` entries. The subject common name is not consulted.
pub(super) fn leaf_matches(leaf: &[u8], server_name: &ServerName) -> Option<bool> {
    check_leaf_name(leaf, server_name, false)
}

pub(super) fn native_leaf_matches(leaf: &[u8], server_name: &ServerName) -> Option<bool> {
    check_leaf_name(leaf, server_name, true)
}

fn check_leaf_name(
    leaf: &[u8],
    server_name: &ServerName,
    native_common_name: bool,
) -> Option<bool> {
    let (_, certificate) = X509Certificate::from_der(leaf).ok()?;
    let names = match certificate.subject_alternative_name() {
        Ok(Some(names)) => names,
        Ok(None) => {
            return Some(native_common_name && common_name_matches(&certificate, server_name));
        }
        Err(_) => return Some(false),
    };
    let names = &names.value.general_names;
    if native_common_name
        && !names
            .iter()
            .any(|name| matches!(name, GeneralName::DNSName(_) | GeneralName::IPAddress(_)))
    {
        return Some(common_name_matches(&certificate, server_name));
    }

    if let Some(ip) = server_name.as_ip() {
        return Some(names.iter().any(|name| match name {
            GeneralName::IPAddress(bytes) => ip_matches(ip, bytes),
            _ => false,
        }));
    }
    let Some(server_name) = server_name.as_domain() else {
        return Some(false);
    };
    let Ok(server_name) = DomainRef::try_from(server_name.as_str()) else {
        return Some(false);
    };
    Some(names.iter().any(|name| match name {
        GeneralName::DNSName(pattern) => {
            DomainRef::try_from(*pattern).is_ok_and(|pattern| dns_matches(pattern, server_name))
        }
        _ => false,
    }))
}

fn common_name_matches(certificate: &X509Certificate<'_>, server_name: &ServerName) -> bool {
    let Some(domain) = server_name.as_domain() else {
        return false;
    };
    let target = DomainRef::from(domain);
    certificate.subject().iter_common_name().any(|name| {
        name.as_str()
            .ok()
            .and_then(|name| DomainRef::try_from(name).ok())
            .is_some_and(|pattern| dns_matches(pattern, target))
    })
}

fn ip_matches(ip: IpAddr, bytes: &[u8]) -> bool {
    match ip {
        IpAddr::V4(ip) => bytes == ip.octets(),
        IpAddr::V6(ip) => bytes == ip.octets(),
    }
}

fn dns_matches(pattern: DomainRef<'_>, server_name: DomainRef<'_>) -> bool {
    let mut pattern_labels = pattern.labels();
    if !pattern_labels
        .next()
        .is_some_and(|label| label.is_wildcard())
    {
        return pattern == server_name;
    }
    // Never a wildcard over a single label such as `*.com`.
    pattern.label_count() > 2
        && pattern.label_count() == server_name.label_count()
        && pattern_labels.eq(server_name.labels().skip(1))
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "boring", feature = "aws-lc", feature = "ring"))]
    use rama_net::address::Domain;

    use super::*;
    #[cfg(any(feature = "boring", feature = "aws-lc", feature = "ring"))]
    use crate::cert::{GeneratedServerAuthConfig, generate_server_auth};
    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    use crate::dep::rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    fn matches(pattern: &str, server_name: &str) -> bool {
        match (
            DomainRef::try_from(pattern),
            DomainRef::try_from(server_name),
        ) {
            (Ok(pattern), Ok(server_name)) => dns_matches(pattern, server_name),
            _ => false,
        }
    }

    #[test]
    fn dns_names_match_case_insensitively() {
        assert!(matches("Example.COM", "example.com"));
        assert!(matches("example.com.", "example.com"));
        assert!(!matches("example.com", "www.example.com"));
    }

    #[test]
    fn wildcards_cover_exactly_one_leftmost_label() {
        assert!(matches("*.example.com", "www.example.com"));
        assert!(!matches("*.example.com", "example.com"));
        assert!(!matches("*.example.com", "a.b.example.com"));
        assert!(!matches("*.com", "example.com"));
        assert!(!matches("w*.example.com", "www.example.com"));
        assert!(!matches("*.*.example.com", "a.b.example.com"));
    }

    #[test]
    #[cfg(any(feature = "boring", feature = "aws-lc", feature = "ring"))]
    fn leaf_names_come_from_subject_alternative_names() {
        let (chain, _) = generate_server_auth(GeneratedServerAuthConfig::generated_ca_for(
            Domain::from_static("leaf.example.com"),
        ))
        .unwrap();
        assert_eq!(
            leaf_matches(&chain[0], &"leaf.example.com".parse().unwrap()),
            Some(true)
        );
        assert_eq!(
            leaf_matches(&chain[0], &"LEAF.example.com".parse().unwrap()),
            Some(true)
        );
        assert_eq!(
            leaf_matches(&chain[0], &"other.example.com".parse().unwrap()),
            Some(false)
        );

        let (chain, _) = generate_server_auth(GeneratedServerAuthConfig::generated_ca_for(
            std::net::IpAddr::from([127, 0, 0, 1]),
        ))
        .unwrap();
        assert_eq!(
            leaf_matches(&chain[0], &"127.0.0.1".parse().unwrap()),
            Some(true)
        );
        assert_eq!(
            leaf_matches(&chain[0], &"127.0.0.2".parse().unwrap()),
            Some(false)
        );
        assert_eq!(
            leaf_matches(
                &chain[0],
                &ServerName::from(Domain::from_static("127.0.0.1."))
            ),
            Some(false)
        );
        assert_eq!(leaf_matches(&[0x30], &"127.0.0.1".parse().unwrap()), None);
        for text in ["127.0.0.1.", "127.1", "0177.0.0.1", "0x7f000001"] {
            let target = ServerName::from(Domain::try_from(text).unwrap());
            assert_eq!(native_leaf_matches(&chain[0], &target), Some(false));
        }
    }

    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    #[test]
    fn native_common_name_fallback_preserves_dns_identity() {
        let key = KeyPair::generate().unwrap();
        for (common_name, target, expected) in [
            ("legacy.test", "legacy.test", true),
            ("legacy.test", "other.test", false),
            ("127.0.0.1", "127.1", false),
        ] {
            let mut params = CertificateParams::default();
            params.distinguished_name = DistinguishedName::new();
            params
                .distinguished_name
                .push(DnType::CommonName, common_name);
            let certificate = params.self_signed(&key).unwrap();
            let target = ServerName::from(Domain::try_from(target).unwrap());
            assert_eq!(
                native_leaf_matches(certificate.der(), &target),
                Some(expected)
            );
            assert_eq!(leaf_matches(certificate.der(), &target), Some(false));
        }
    }

    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    #[test]
    fn native_common_name_fallback_depends_on_identity_san_presence() {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "legacy.test");
        params.subject_alt_names = vec![SanType::URI("urn:service:legacy".try_into().unwrap())];
        let target = ServerName::from(Domain::from_static("legacy.test"));
        let certificate = params.self_signed(&key).unwrap();
        assert_eq!(native_leaf_matches(certificate.der(), &target), Some(true));
        for san in [
            SanType::DnsName("other.test".try_into().unwrap()),
            SanType::IpAddress([127, 0, 0, 1].into()),
        ] {
            let mut params = params.clone();
            params.subject_alt_names.push(san);
            let certificate = params.self_signed(&key).unwrap();
            assert_eq!(native_leaf_matches(certificate.der(), &target), Some(false));
        }
    }

    #[test]
    fn ip_addresses_match_by_octets() {
        assert!(ip_matches("127.0.0.1".parse().unwrap(), &[127, 0, 0, 1]));
        assert!(!ip_matches("127.0.0.1".parse().unwrap(), &[127, 0, 0, 2]));
        assert!(ip_matches(
            "::1".parse().unwrap(),
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        ));
    }
}
