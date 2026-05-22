use crate::RamaTlsRustlsCrateMarker;
use rama_core::conversion::{RamaFrom, RamaTryFrom};
use rama_core::error::extra::OpaqueError;
use rama_core::error::{BoxError, ErrorContext, ErrorExt};
use rama_net::{
    address::{Domain, Host},
    tls::{
        ApplicationProtocol, CipherSuite, DataEncoding, ProtocolVersion, SignatureScheme,
        client::{ClientHello, ClientHelloExtension},
    },
};
use rustls::pki_types;
use std::net::IpAddr;

macro_rules! enum_from_rustls {
    ($t:ty => $($name:ident),+$(,)?) => {
        $(
            impl RamaFrom<rustls::$name, RamaTlsRustlsCrateMarker> for rama_net::tls::$name {
                fn rama_from(value: ::rustls::$name) -> Self {
                    let n: $t = value.into();
                    n.into()
                }
            }

            impl RamaFrom<rama_net::tls::$name, RamaTlsRustlsCrateMarker> for rustls::$name {
                fn rama_from(value: rama_net::tls::$name) -> Self {
                    let n: $t = value.into();
                    n.into()
                }
            }
        )+
    };
}

enum_from_rustls!(u16 => ProtocolVersion, CipherSuite, SignatureScheme);

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
                OpaqueError::from_static_str("unrecognised rustls (PKI) server name")
                    .with_context_debug_field("server_name", || value.to_owned()),
            ),
        }
    }
}
impl RamaTryFrom<Host, RamaTlsRustlsCrateMarker> for rustls::pki_types::ServerName<'_> {
    type Error = BoxError;

    fn rama_try_from(value: Host) -> Result<Self, Self::Error> {
        match value {
            Host::Name(name) => Ok(rustls::pki_types::ServerName::DnsName(
                rustls::pki_types::DnsName::try_from(name.as_str().to_owned())
                    .context("convert domain to rustls (PKI) ServerName")?,
            )),
            Host::Address(ip) => Ok(rustls::pki_types::ServerName::IpAddress(ip.into())),
            // Try to recover a DNS name (pct-decode + IDN). Bracketed
            // IP-literals fall through to an error — rustls SNI/IP
            // categories don't cover IPvFuture.
            Host::Uninterpreted(host) => {
                let domain = Domain::try_from(host)
                    .context("uninterpreted host is not a domain for rustls ServerName")?;
                Ok(rustls::pki_types::ServerName::DnsName(
                    rustls::pki_types::DnsName::try_from(domain.as_str().to_owned())
                        .context("convert domain to rustls (PKI) ServerName")?,
                ))
            }
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
                OpaqueError::from_static_str("urecognised rustls (PKI) server name")
                    .with_context_debug_field("value", || value.to_owned()),
            ),
        }
    }
}

impl<'a> RamaTryFrom<&'a Host, RamaTlsRustlsCrateMarker> for rustls::pki_types::ServerName<'a> {
    type Error = BoxError;

    fn rama_try_from(value: &'a Host) -> Result<Self, Self::Error> {
        match value {
            Host::Name(name) => Ok(rustls::pki_types::ServerName::DnsName(
                rustls::pki_types::DnsName::try_from(name.as_str())
                    .context("convert domain to rustls (PKI) ServerName")?,
            )),
            Host::Address(ip) => Ok(rustls::pki_types::ServerName::IpAddress((*ip).into())),
            // For the borrowed form we can't borrow into a pct-decoded
            // domain string — the decoded bytes don't live in the
            // input. But it's worth trying the recovery and returning a
            // `DnsName` built from the resulting owned `String` so a
            // pct-encoded / IDN reg-name (`exa%6Dple.com`, `münchen.de`)
            // doesn't trip this path. Bracketed IPvFuture and sub-delim
            // reg-names still fail — rustls's ServerName grammar
            // doesn't model them.
            Host::Uninterpreted(host) => {
                let domain = Domain::try_from(host).context(
                    "uninterpreted host is not a domain for rustls ServerName \
                     (borrowed conversion)",
                )?;
                Ok(rustls::pki_types::ServerName::DnsName(
                    rustls::pki_types::DnsName::try_from(domain.as_str().to_owned())
                        .context("convert recovered domain to rustls (PKI) ServerName")?,
                ))
            }
        }
    }
}

impl RamaFrom<&pki_types::CertificateDer<'static>, RamaTlsRustlsCrateMarker> for DataEncoding {
    fn rama_from(value: &pki_types::CertificateDer<'static>) -> Self {
        Self::Der(value.as_ref().into())
    }
}

impl RamaFrom<&[pki_types::CertificateDer<'static>], RamaTlsRustlsCrateMarker> for DataEncoding {
    fn rama_from(value: &[pki_types::CertificateDer<'static>]) -> Self {
        Self::DerStack(
            value
                .iter()
                .map(|cert| Into::<Vec<u8>>::into(cert.as_ref()))
                .collect(),
        )
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

        if let Some(domain) = value.server_name().and_then(|d| d.parse().ok()) {
            extensions.push(ClientHelloExtension::ServerName(Some(domain)));
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
    use super::*;

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
    //
    // `UninterpretedHost::from_validated_bytes` is crate-private to
    // `rama-net`, so cross-crate tests construct the variant via the
    // URI parser (the only public path that produces it).

    fn parse_uninterpreted_host(uri_input: &str) -> Host {
        let uri = rama_net::uri::Uri::parse(uri_input).expect("valid URI");
        uri.host().expect("authority present").into_owned()
    }

    #[test]
    fn owned_host_uninterpreted_recovers_to_dns_name() {
        let host = parse_uninterpreted_host("http://exa%6Dple.com/");
        assert!(matches!(host, Host::Uninterpreted(_)));
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
        let host = parse_uninterpreted_host("http://exa%6Dple.com/");
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
        let host = parse_uninterpreted_host("http://[v1.fe80::a]/");
        rustls::pki_types::ServerName::rama_try_from(host).unwrap_err();
    }
}
