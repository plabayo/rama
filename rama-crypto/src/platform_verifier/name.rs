//! Server identity matching for verifiers that only validate the chain.

use std::net::IpAddr;

use x509_parser::{certificate::X509Certificate, extensions::GeneralName, prelude::FromDer as _};

/// Whether the subject alternative names of `leaf` cover `server_name`.
///
/// DNS names match ASCII case-insensitively, with a wildcard only as the
/// complete left-most label; IP addresses match `iPAddress` entries. The
/// subject common name is not consulted, as with every current browser.
#[cfg_attr(
    not(any(
        target_os = "android",
        all(test, any(feature = "boring", feature = "aws-lc", feature = "ring"))
    )),
    expect(dead_code, reason = "only Android's verifier leaves names to rama")
)]
pub(super) fn leaf_matches(leaf: &[u8], server_name: &str) -> bool {
    let Ok((_, certificate)) = X509Certificate::from_der(leaf) else {
        return false;
    };
    let Ok(Some(names)) = certificate.subject_alternative_name() else {
        return false;
    };
    let names = &names.value.general_names;

    if let Ok(ip) = server_name.parse::<IpAddr>() {
        return names.iter().any(|name| match name {
            GeneralName::IPAddress(bytes) => ip_matches(ip, bytes),
            _ => false,
        });
    }

    names.iter().any(|name| match name {
        GeneralName::DNSName(pattern) => dns_matches(pattern, server_name),
        _ => false,
    })
}

fn ip_matches(ip: IpAddr, bytes: &[u8]) -> bool {
    match ip {
        IpAddr::V4(ip) => bytes == ip.octets(),
        IpAddr::V6(ip) => bytes == ip.octets(),
    }
}

fn dns_matches(pattern: &str, server_name: &str) -> bool {
    let pattern = pattern.strip_suffix('.').unwrap_or(pattern);
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return pattern.eq_ignore_ascii_case(server_name);
    };
    // A wildcard stands for exactly one non-empty label, and never covers a
    // public suffix on its own.
    if suffix.is_empty() || !suffix.contains('.') || suffix.contains('*') {
        return false;
    }
    match server_name.split_once('.') {
        Some((label, rest)) => !label.is_empty() && rest.eq_ignore_ascii_case(suffix),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_names_match_case_insensitively() {
        assert!(dns_matches("Example.COM", "example.com"));
        assert!(dns_matches("example.com.", "example.com"));
        assert!(!dns_matches("example.com", "www.example.com"));
    }

    #[test]
    fn wildcards_cover_exactly_one_leftmost_label() {
        assert!(dns_matches("*.example.com", "www.example.com"));
        assert!(!dns_matches("*.example.com", "example.com"));
        assert!(!dns_matches("*.example.com", "a.b.example.com"));
        assert!(!dns_matches("*.com", "example.com"));
        assert!(!dns_matches("w*.example.com", "www.example.com"));
        assert!(!dns_matches("*.*.example.com", "a.b.example.com"));
    }

    #[test]
    #[cfg(any(feature = "boring", feature = "aws-lc", feature = "ring"))]
    fn leaf_names_come_from_subject_alternative_names() {
        use crate::cert::{GeneratedServerAuthConfig, generate_server_auth};
        use rama_net::address::Domain;

        let (chain, _) = generate_server_auth(GeneratedServerAuthConfig::generated_ca_for(
            Domain::from_static("leaf.example.com"),
        ))
        .unwrap();
        assert!(leaf_matches(&chain[0], "leaf.example.com"));
        assert!(leaf_matches(&chain[0], "LEAF.example.com"));
        assert!(!leaf_matches(&chain[0], "other.example.com"));

        let (chain, _) = generate_server_auth(GeneratedServerAuthConfig::generated_ca_for(
            std::net::IpAddr::from([127, 0, 0, 1]),
        ))
        .unwrap();
        assert!(leaf_matches(&chain[0], "127.0.0.1"));
        assert!(!leaf_matches(&chain[0], "127.0.0.2"));
        assert!(!leaf_matches(&[0x30], "127.0.0.1"));
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
