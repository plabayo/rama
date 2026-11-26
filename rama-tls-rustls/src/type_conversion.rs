use std::{borrow::Cow, net::IpAddr};

use rama_core::{
    conversion::{RamaFrom, RamaTryFrom},
    error::{BoxError, BoxErrorExt as _, ErrorContext, ErrorExt},
};
use rama_net::{
    address::{Domain, Host},
    tls::{ApplicationProtocol, ServerName},
};
use rama_tls::{
    CipherSuite, ProtocolVersion, SignatureScheme, SupportedGroup,
    client::{ClientHello, ClientHelloExtension, NegotiatedTlsAlgorithms},
};
use rustls::pki_types::DnsName;

use crate::RamaTlsRustlsCrateMarker;

macro_rules! enum_from_rustls {
    ($t:ty => $($name:ident),+$(,)?) => {
        $(
            impl RamaFrom<rustls::$name, RamaTlsRustlsCrateMarker> for rama_tls::$name {
                fn rama_from(value: ::rustls::$name) -> Self {
                    let n: $t = value.into();
                    n.into()
                }
            }

            impl RamaFrom<rama_tls::$name, RamaTlsRustlsCrateMarker> for rustls::$name {
                fn rama_from(value: rama_tls::$name) -> Self {
                    let n: $t = value.into();
                    n.into()
                }
            }
        )+
    };
}

enum_from_rustls!(u16 => ProtocolVersion, CipherSuite, SignatureScheme);

impl RamaFrom<&rustls::CommonState, RamaTlsRustlsCrateMarker> for NegotiatedTlsAlgorithms {
    fn rama_from(state: &rustls::CommonState) -> Self {
        Self {
            cipher_suite: state
                .negotiated_cipher_suite()
                .map(|suite| CipherSuite::rama_from(suite.suite())),
            key_exchange_group: state
                .negotiated_key_exchange_group()
                .map(|group| SupportedGroup::from(u16::from(group.name()))),
            // rustls reports neither the peer's signature scheme nor certificate compression.
            peer_signature_scheme: None,
            certificate_compression: None,
        }
    }
}

impl RamaTryFrom<ProtocolVersion, RamaTlsRustlsCrateMarker> for &rustls::SupportedProtocolVersion {
    type Error = ProtocolVersion;

    fn rama_try_from(value: ProtocolVersion) -> Result<Self, Self::Error> {
        match value {
            ProtocolVersion::TLSv1_2 => Ok(&rustls::version::TLS12),
            ProtocolVersion::TLSv1_3 => Ok(&rustls::version::TLS13),
            other => Err(other),
        }
    }
}

impl<'a> RamaTryFrom<rustls::pki_types::ServerName<'a>, RamaTlsRustlsCrateMarker> for Host {
    type Error = BoxError;

    fn rama_try_from(value: rustls::pki_types::ServerName<'a>) -> Result<Self, Self::Error> {
        match value {
            rustls::pki_types::ServerName::DnsName(name) => {
                Ok(Domain::try_from(name.as_ref().to_owned())?.into())
            }
            rustls::pki_types::ServerName::IpAddress(ip) => Ok(Self::from(IpAddr::from(ip))),
            _ => Err(
                BoxError::from_static_str("unrecognised rustls (PKI) server name")
                    .with_context_debug_field("server_name", || value.to_owned()),
            ),
        }
    }
}

impl RamaTryFrom<Host, RamaTlsRustlsCrateMarker> for rustls::pki_types::ServerName<'_> {
    type Error = BoxError;

    fn rama_try_from(value: Host) -> Result<Self, Self::Error> {
        match value.canonicalize() {
            Host::Name(domain) => Ok(Self::DnsName(
                DnsName::try_from(domain.as_str().to_owned())
                    .context("convert domain to rustls (PKI) ServerName")?,
            )),
            Host::Address(ip) => Ok(Self::IpAddress(ip.into())),
            _ => Err(BoxError::from_static_str(
                "host is not a domain or IP for rustls ServerName",
            )),
        }
    }
}

impl<'a> RamaTryFrom<&rustls::pki_types::ServerName<'a>, RamaTlsRustlsCrateMarker> for Host {
    type Error = BoxError;

    fn rama_try_from(value: &rustls::pki_types::ServerName<'a>) -> Result<Self, Self::Error> {
        match value {
            rustls::pki_types::ServerName::DnsName(name) => {
                Ok(Domain::try_from(name.as_ref().to_owned())?.into())
            }
            rustls::pki_types::ServerName::IpAddress(ip) => Ok(Self::from(IpAddr::from(*ip))),
            _ => Err(
                BoxError::from_static_str("urecognised rustls (PKI) server name")
                    .with_context_debug_field("value", || value.to_owned()),
            ),
        }
    }
}

impl<'a> RamaTryFrom<&'a ServerName, RamaTlsRustlsCrateMarker>
    for rustls::pki_types::ServerName<'a>
{
    type Error = BoxError;

    fn rama_try_from(value: &'a ServerName) -> Result<Self, Self::Error> {
        if let Some(ip) = value.as_ip() {
            return Ok(Self::IpAddress(ip.into()));
        }
        let domain = value
            .as_domain()
            .context("server name is neither a domain nor an IP")?;
        Ok(Self::DnsName(
            DnsName::try_from(domain.as_str())
                .context("convert domain to rustls (PKI) ServerName")?,
        ))
    }
}

impl<'a> RamaTryFrom<&'a Host, RamaTlsRustlsCrateMarker> for rustls::pki_types::ServerName<'a> {
    type Error = BoxError;

    fn rama_try_from(value: &'a Host) -> Result<Self, Self::Error> {
        if let Host::Name(domain) = value
            && domain.as_ip().is_none()
        {
            return Ok(Self::DnsName(
                DnsName::try_from(domain.as_str())
                    .context("convert domain to rustls (PKI) ServerName")?,
            ));
        }
        match value.canonical_identity() {
            Cow::Borrowed(Host::Name(domain)) => Ok(Self::DnsName(
                DnsName::try_from(domain.as_str())
                    .context("convert domain to rustls (PKI) ServerName")?,
            )),
            Cow::Borrowed(Host::Address(ip)) => Ok(Self::IpAddress((*ip).into())),
            Cow::Owned(Host::Name(domain)) => Ok(Self::DnsName(
                DnsName::try_from(domain.as_str().to_owned())
                    .context("convert domain to rustls (PKI) ServerName")?,
            )),
            Cow::Owned(Host::Address(ip)) => Ok(Self::IpAddress(ip.into())),
            _ => Err(BoxError::from_static_str(
                "host is not a domain or IP for rustls ServerName",
            )),
        }
    }
}

impl<'a> RamaFrom<rustls::server::ClientHello<'a>, RamaTlsRustlsCrateMarker> for ClientHello {
    fn rama_from(value: rustls::server::ClientHello<'a>) -> Self {
        let cipher_suites = value
            .cipher_suites()
            .iter()
            .map(|cs| CipherSuite::rama_from(*cs))
            .collect();

        let mut extensions = Vec::with_capacity(3);

        extensions.push(ClientHelloExtension::SignatureAlgorithms(
            value
                .signature_schemes()
                .iter()
                .map(|sc| SignatureScheme::rama_from(*sc))
                .collect(),
        ));

        if let Some(server_name) = value
            .server_name()
            .and_then(|name| name.parse::<ServerName>().ok())
        {
            extensions.push(ClientHelloExtension::ServerName(Some(server_name)));
        }

        if let Some(alpn) = value.alpn() {
            extensions.push(ClientHelloExtension::ApplicationLayerProtocolNegotiation(
                alpn.map(ApplicationProtocol::from).collect(),
            ));
        }

        Self::new(
            // TODO: support if rustls can handle this
            ProtocolVersion::Unknown(0),
            cipher_suites,
            vec![],
            extensions,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use rustls::pki_types;

    use super::*;

    #[test]
    fn borrowed_dns_conversion_keeps_the_input_storage() {
        for domain in [Domain::example(), Domain::from_static("EXAMPLE.com")] {
            let host = Host::Name(domain);
            let name = pki_types::ServerName::rama_try_from(&host).unwrap();
            let pki_types::ServerName::DnsName(name) = name else {
                panic!("expected DNS name");
            };
            let Host::Name(domain) = &host else {
                panic!("expected domain host");
            };
            assert_eq!(name.as_ref().as_ptr(), domain.as_str().as_ptr());
        }
    }

    #[test]
    fn test_rustls_to_common_to_rustls() {
        let p = rustls::ProtocolVersion::TLSv1_3;
        let p = ProtocolVersion::rama_from(p);
        assert_eq!(p, ProtocolVersion::TLSv1_3);
        let p = rustls::ProtocolVersion::rama_from(p);
        assert_eq!(p, rustls::ProtocolVersion::TLSv1_3);
    }

    // ---- Uninterpreted host promotion fallback (audit M3 / C13) ----------
    //
    // Both the owned and borrowed `Host → ServerName` conversions retry
    // `Domain::try_from` on `Uninterpreted` hosts so a pct-encoded or
    // IDN reg-name reaches the TLS layer as a proper `DnsName` rather
    // than tripping the AddressTypeNotSupported / OpaqueError path.

    #[test]
    fn owned_host_uninterpreted_recovers_to_dns_name() {
        let host = Host::try_from("exa%6Dple.com").unwrap();
        assert_matches!(host, Host::Uninterpreted(_));
        let sn = rustls::pki_types::ServerName::rama_try_from(host).unwrap();
        match sn {
            rustls::pki_types::ServerName::DnsName(dns) => {
                assert_eq!(dns.as_ref(), "example.com");
            }
            other => panic!("expected DnsName from pct-encoded Uninterpreted, got {other:?}"),
        }
    }

    #[test]
    fn borrowed_host_uninterpreted_recovers_to_dns_name() {
        let host = Host::try_from("exa%6Dple.com").unwrap();
        // Borrowed-input conversion (the audit added this recovery
        // branch — used to error unconditionally).
        let sn = rustls::pki_types::ServerName::rama_try_from(&host).unwrap();
        match sn {
            rustls::pki_types::ServerName::DnsName(dns) => {
                assert_eq!(dns.as_ref(), "example.com");
            }
            other => panic!("expected DnsName from pct-encoded Uninterpreted, got {other:?}"),
        }
    }

    #[test]
    fn host_uninterpreted_bracketed_ipvfuture_still_errors() {
        // No typed recovery is possible for IPvFuture — must surface
        // the conversion error rather than emitting a bogus DnsName.
        let host = Host::try_from("[v1.fe80::a]").unwrap();
        rustls::pki_types::ServerName::rama_try_from(host).unwrap_err();
    }

    #[test]
    fn owned_numeric_domain_is_an_ip_identity() {
        let host = Host::Name(Domain::try_from("127.0.0.1").unwrap());
        let server_name = rustls::pki_types::ServerName::rama_try_from(host).unwrap();
        assert_matches!(server_name, rustls::pki_types::ServerName::IpAddress(_));
    }

    #[test]
    fn borrowed_numeric_domain_is_an_ip_identity() {
        let host = Host::Name(Domain::try_from("127.0.0.1").unwrap());
        let server_name = rustls::pki_types::ServerName::rama_try_from(&host).unwrap();
        assert_matches!(server_name, rustls::pki_types::ServerName::IpAddress(_));
    }
}

#[cfg(test)]
mod literal_sni_tests {
    use rustls::pki_types::{DnsName, ServerName};

    #[test]
    fn validated_dns_names_cannot_carry_ip_literals() {
        for literal in ["192.0.2.1", "192.0.2.1.", "2001:db8::1", "[2001:db8::1]"] {
            assert!(DnsName::try_from(literal).is_err(), "{literal}");
        }
        DnsName::try_from("192.0.2.example").unwrap();
        ServerName::try_from("[2001:db8::1]").unwrap_err();
        for literal in ["192.0.2.1", "2001:db8::1"] {
            assert!(matches!(
                ServerName::try_from(literal).unwrap(),
                ServerName::IpAddress(_)
            ));
        }
    }
}
