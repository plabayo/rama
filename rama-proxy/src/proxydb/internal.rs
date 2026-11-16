use super::{ProxyContext, ProxyFilter, ProxyType, StringFilter};
use rama_core::extensions::Extension;

use rama_net::{
    address::{HostWithPort, ProxyProtocol},
    asn::Asn,
    transport::TransportProtocol,
    user::ProxyCredential,
};
use rama_utils::str::NonEmptyStr;
use serde::{Deserialize, Serialize};

#[cfg(feature = "memory-db")]
use venndb::VennDB;

#[expect(
    clippy::disallowed_types,
    reason = "the handful of protocols of one trusted record is no hash-DoS surface"
)]
/// The protocols a [`Proxy`] speaks.
pub type ProxyProtocols = std::collections::HashSet<ProxyProtocol>;

#[derive(Debug, Clone, Serialize, Deserialize, Extension)]
#[extension(tags(proxy))]
#[cfg_attr(feature = "memory-db", derive(VennDB))]
#[cfg_attr(feature = "memory-db", venndb(validator = proxydb_insert_validator))]
/// A proxy record returned by a [`ProxyDB`](super::ProxyDB).
///
/// A record names every protocol the proxy speaks, and the
/// [`ProxyDBService`](crate::ProxyDBService) turns a record plus the requested
/// transport into one `ProxyAddress` with one of them.
pub struct Proxy {
    #[cfg_attr(feature = "memory-db", venndb(key))]
    /// Unique identifier of the proxy.
    pub id: NonEmptyStr,

    /// Host and port to connect to the proxy on.
    pub address: HostWithPort,

    /// Credential to authenticate with at the proxy.
    #[serde(default, with = "credential_str")]
    pub credential: Option<ProxyCredential>,

    #[cfg_attr(feature = "memory-db", venndb(filter, set))]
    #[serde(with = "protocol_tokens")]
    /// Every protocol the proxy speaks, with the HTTP version and MASQUE template
    /// that belong to it.
    ///
    /// Written as `scheme[+option][template]` outside of Rust, the scheme of a proxy
    /// address followed by the path its tunnels live on: see
    /// [`ProxyProtocol::try_from_scheme_and_path`]. An option appears only where it differs from
    /// the scheme's default, so `socks5h+udp`, `h2` and
    /// `masque/m{?target_host,target_port}` are three.
    pub protocols: ProxyProtocols,

    #[cfg_attr(feature = "memory-db", venndb(filter))]
    /// Where the IP of the proxy comes from.
    #[serde(rename = "type")]
    pub kind: ProxyType,

    #[cfg_attr(feature = "memory-db", venndb(filter, any = StringFilter::is_any))]
    /// Pool ID of the proxy.
    pub pool_id: Option<StringFilter>,

    #[cfg_attr(feature = "memory-db", venndb(filter, any = StringFilter::is_any))]
    /// Continent of the proxy.
    pub continent: Option<StringFilter>,

    #[cfg_attr(feature = "memory-db", venndb(filter, any = StringFilter::is_any))]
    /// Country of the proxy.
    pub country: Option<StringFilter>,

    #[cfg_attr(feature = "memory-db", venndb(filter, any = StringFilter::is_any))]
    /// State of the proxy.
    pub state: Option<StringFilter>,

    #[cfg_attr(feature = "memory-db", venndb(filter, any = StringFilter::is_any))]
    /// City of the proxy.
    pub city: Option<StringFilter>,

    #[cfg_attr(feature = "memory-db", venndb(filter, any = StringFilter::is_any))]
    /// Mobile carrier of the proxy.
    pub carrier: Option<StringFilter>,

    #[cfg_attr(feature = "memory-db", venndb(filter, any = Asn::is_any))]
    ///  Autonomous System Number (ASN).
    pub asn: Option<Asn>,
}

#[cfg(feature = "memory-db")]
/// Validate the proxy is valid according to rules that are not enforced by the type system.
fn proxydb_insert_validator(proxy: &Proxy) -> bool {
    !proxy.protocols.is_empty()
}

fn string_filter_matches(
    filters: Option<&[StringFilter]>,
    candidate: Option<&StringFilter>,
) -> bool {
    match filters {
        None => true,
        Some(filters) => candidate.is_some_and(|candidate| {
            filters
                .iter()
                .any(|filter| candidate.is_any() || filter.is_any() || filter == candidate)
        }),
    }
}

/// Whether the protocol relays UDP: SOCKS5 with UDP ASSOCIATE, or MASQUE with CONNECT-UDP.
fn relays_udp(protocol: &ProxyProtocol) -> bool {
    matches!(protocol, ProxyProtocol::Socks5 { udp: true, .. }) || protocol.supports_connect_udp()
}

impl Proxy {
    /// Whether the proxy offers any MASQUE method on at least one HTTP version.
    #[must_use]
    pub fn is_masque(&self) -> bool {
        self.protocols.iter().any(ProxyProtocol::is_masque)
    }

    /// Whether the proxy tunnels UDP with CONNECT-UDP on at least one HTTP version.
    #[must_use]
    pub fn supports_connect_udp(&self) -> bool {
        self.protocols
            .iter()
            .any(ProxyProtocol::supports_connect_udp)
    }

    /// Whether the proxy can carry traffic of the given transport.
    ///
    /// Every proxy protocol tunnels TCP; UDP needs one that relays it.
    #[must_use]
    pub fn supports_transport(&self, protocol: TransportProtocol) -> bool {
        match protocol {
            TransportProtocol::Udp => self.protocols.iter().any(relays_udp),
            TransportProtocol::Tcp => !self.protocols.is_empty(),
        }
    }

    /// Check if the proxy is a match for the given[`ProxyContext`] and [`ProxyFilter`].
    #[must_use]
    pub fn is_match(&self, ctx: &ProxyContext, filter: &ProxyFilter) -> bool {
        if let Some(id) = &filter.id
            && id != &self.id
        {
            return false;
        }

        if !self.supports_transport(ctx.protocol) {
            return false;
        }

        string_filter_matches(filter.continent.as_deref(), self.continent.as_ref())
            && string_filter_matches(filter.country.as_deref(), self.country.as_ref())
            && string_filter_matches(filter.state.as_deref(), self.state.as_ref())
            && string_filter_matches(filter.city.as_deref(), self.city.as_ref())
            && string_filter_matches(filter.pool_id.as_deref(), self.pool_id.as_ref())
            && string_filter_matches(filter.carrier.as_deref(), self.carrier.as_ref())
            && filter
                .asn
                .as_ref()
                .map(|a| {
                    let asn = self.asn.as_ref();
                    a.iter().any(|a| Some(a) == asn)
                })
                .unwrap_or(true)
            && filter
                .kind
                .as_ref()
                .is_none_or(|kinds| kinds.contains(&self.kind))
    }
}

#[cfg(test)]
mod serde_tests {
    use super::*;
    use rama_net::Protocol;
    use rama_net::user::credentials::{basic, bearer};
    use rama_utils::str::non_empty_str;

    fn protocols() -> ProxyProtocols {
        ProxyProtocols::from([
            ProxyProtocol::HTTPS.with_http_version(rama_net::http::Version::HTTP_2),
            ProxyProtocol::Socks5 {
                remote_dns: true,
                udp: true,
            },
            ProxyProtocol::Other(Protocol::from_static("warp")),
            protocol_token::parse("h3/m?h={target_host}&p={target_port}").unwrap(),
        ])
    }

    fn proxy(credential: Option<ProxyCredential>) -> Proxy {
        Proxy {
            id: non_empty_str!("id"),
            address: "proxy.example:443".parse().unwrap(),
            credential,
            protocols: protocols(),
            kind: ProxyType::Datacenter,
            pool_id: None,
            continent: None,
            country: Some("be".into()),
            state: None,
            city: None,
            carrier: None,
            asn: None,
        }
    }

    #[test]
    fn a_proxy_row_round_trips_through_json() {
        for credential in [
            None,
            Some(basic!("user", "p@ss").into()),
            Some(ProxyCredential::Bearer(bearer!("token"))),
        ] {
            let original = proxy(credential);
            let json = serde_json::to_string(&original).unwrap();
            let parsed: Proxy = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.credential, original.credential, "{json}");
            assert_eq!(parsed.address, original.address);
            assert_eq!(parsed.protocols, original.protocols, "{json}");
        }
    }

    #[test]
    fn protocols_serialize_as_sorted_tokens() {
        let json = serde_json::to_value(proxy(None)).unwrap();
        assert_eq!(
            json["protocols"],
            serde_json::json!([
                "h2",
                "h3/m?h={target_host}&p={target_port}",
                "socks5h+udp",
                "warp",
            ]),
        );
    }

    #[test]
    fn a_protocol_token_names_one_protocol() {
        for (token, protocol) in [
            ("http", Some(ProxyProtocol::HTTP)),
            (
                "h1",
                Some(ProxyProtocol::HTTPS.with_http_version(rama_net::http::Version::HTTP_11)),
            ),
            (
                "h2c",
                Some(ProxyProtocol::HTTP.with_http_version(rama_net::http::Version::HTTP_2)),
            ),
            ("https", Some(ProxyProtocol::HTTPS)),
            (
                "h3+udp",
                Some(ProxyProtocol::try_from_scheme("h3+udp").unwrap()),
            ),
            ("socks5", Some(ProxyProtocol::SOCKS5)),
            ("socks5h", Some(ProxyProtocol::SOCKS5H)),
            (
                "socks5+udp",
                Some(ProxyProtocol::Socks5 {
                    remote_dns: false,
                    udp: true,
                }),
            ),
            (
                "h3/.well-known/masque/udp/{target_host}/{target_port}/",
                Some(ProxyProtocol::try_from_scheme("h3+udp").unwrap()),
            ),
            (
                "warp",
                Some(ProxyProtocol::Other(Protocol::from_static("warp"))),
            ),
            // An option belongs to its own scheme, and only TLS carries HTTP/3.
            ("socks5+h2", None),
            ("https+h2", None),
            ("warp+h2", None),
            ("http+h3", None),
            ("https+h4", None),
            // A template belongs to MASQUE, and has to be one.
            ("socks5/m/{target_host}/{target_port}", None),
            ("h3/not-a-template", None),
        ] {
            assert_eq!(protocol_token::parse(token), protocol, "{token}");
        }
    }

    #[test]
    fn a_tls_scheme_with_a_template_is_masque_in_the_version_it_asked_for() {
        let protocol = protocol_token::parse("h2/m/{target_host}/{target_port}").unwrap();
        assert!(protocol.supports_connect_udp());
        assert_eq!(
            protocol.http_version(),
            Some(rama_net::http::Version::HTTP_2)
        );
        assert_eq!(
            protocol_token::display(&protocol).to_string(),
            "h2/m/{target_host}/{target_port}"
        );
    }

    #[test]
    fn every_protocol_token_round_trips() {
        for protocol in protocols() {
            let token = protocol_token::display(&protocol).to_string();
            assert_eq!(protocol_token::parse(&token), Some(protocol), "{token}");
        }
    }
}

#[cfg(all(feature = "csv", feature = "memory-db"))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxydb::csv::{ProxyCsvRowReader, parse_csv_row};
    use crate::proxydb::internal::{ProxyDB, ProxyDBErrorKind};
    use itertools::Itertools;

    #[test]
    fn test_proxy_db_happy_path_basic() {
        let mut db = ProxyDB::new();
        let proxy = parse_csv_row("id,datacenter,authority:80,,,,,,,,,http").unwrap();
        db.append(proxy).unwrap();

        let mut query = db.query();
        query.protocols(ProxyProtocol::HTTP);

        let proxy = query.execute().unwrap().any();
        assert_eq!(proxy.id, "id");
    }

    #[tokio::test]
    async fn test_proxy_db_happy_path_any_country() {
        let mut db = ProxyDB::new();
        let mut reader = ProxyCsvRowReader::raw(
            "1,datacenter,authority:80,,,US,,,,,,http\n2,datacenter,authority:80,,,*,,,,,,http",
        );
        while let Some(proxy) = reader.next().await.unwrap() {
            db.append(proxy).unwrap();
        }

        let mut query = db.query();
        query.protocols(ProxyProtocol::HTTP).country("US");

        let proxies: Vec<_> = query
            .execute()
            .unwrap()
            .iter()
            .sorted_by(|a, b| a.id.cmp(&b.id))
            .collect();
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].id, "1");
        assert_eq!(proxies[1].id, "2");

        query.reset().country("BE");
        let proxies: Vec<_> = query
            .execute()
            .unwrap()
            .iter()
            .sorted_by(|a, b| a.id.cmp(&b.id))
            .collect();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].id, "2");
    }

    #[test]
    fn direct_match_rejects_empty_filter_for_wildcard_candidate() {
        let proxy =
            parse_csv_row("2,datacenter,authority:80,,,*,,,,,,http").expect("valid proxy row");
        let filter = ProxyFilter {
            country: Some(Vec::new()),
            ..Default::default()
        };

        assert!(!proxy.is_match(
            &ProxyContext {
                protocol: TransportProtocol::Tcp,
            },
            &filter,
        ));
    }

    #[tokio::test]
    async fn test_proxy_db_happy_path_any_country_city() {
        let mut db = ProxyDB::new();
        let mut reader = ProxyCsvRowReader::raw(
            "1,datacenter,authority:80,,,US,,New York,,,,http\n2,datacenter,authority:80,,,*,,*,,,,http",
        );
        while let Some(proxy) = reader.next().await.unwrap() {
            db.append(proxy).unwrap();
        }

        let mut query = db.query();
        query
            .protocols(ProxyProtocol::HTTP)
            .country("US")
            .city("new york");

        let proxies: Vec<_> = query
            .execute()
            .unwrap()
            .iter()
            .sorted_by(|a, b| a.id.cmp(&b.id))
            .collect();
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].id, "1");
        assert_eq!(proxies[1].id, "2");

        query.reset().country("US").city("Los Angeles");
        let proxies: Vec<_> = query
            .execute()
            .unwrap()
            .iter()
            .sorted_by(|a, b| a.id.cmp(&b.id))
            .collect();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].id, "2");

        query.reset().city("Ghent");
        let proxies: Vec<_> = query
            .execute()
            .unwrap()
            .iter()
            .sorted_by(|a, b| a.id.cmp(&b.id))
            .collect();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].id, "2");
    }

    #[tokio::test]
    async fn test_proxy_db_happy_path_specific_asn_within_continents() {
        let mut db = ProxyDB::new();
        let mut reader = ProxyCsvRowReader::raw(
            "1,datacenter,authority:80,,europe,BE,,Brussels,,1348,,http\n2,datacenter,authority:80,,asia,CN,,Shenzen,,1348,,http\n3,datacenter,authority:80,,asia,CN,,Peking,,42,,http",
        );
        while let Some(proxy) = reader.next().await.unwrap() {
            db.append(proxy).unwrap();
        }

        let mut query = db.query();
        query
            .protocols(ProxyProtocol::HTTP)
            .continent("europe")
            .continent("asia")
            .asn(Asn::from_static(1348));

        let proxies: Vec<_> = query
            .execute()
            .unwrap()
            .iter()
            .sorted_by(|a, b| a.id.cmp(&b.id))
            .collect();
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].id, "1");
        assert_eq!(proxies[1].id, "2");

        query.reset().asn(Asn::from_static(42));
        let proxies: Vec<_> = query
            .execute()
            .unwrap()
            .iter()
            .sorted_by(|a, b| a.id.cmp(&b.id))
            .collect();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].id, "3");
    }

    #[tokio::test]
    async fn test_proxy_db_happy_path_states() {
        let mut db = ProxyDB::new();
        let mut reader = ProxyCsvRowReader::raw(
            "1,datacenter,authority:80,,,US,Texas,,,,,http\n2,datacenter,authority:80,,,US,New York,,,,,http\n3,datacenter,authority:80,,,US,California,,,,,http",
        );
        while let Some(proxy) = reader.next().await.unwrap() {
            db.append(proxy).unwrap();
        }

        let mut query = db.query();
        query
            .protocols(ProxyProtocol::HTTP)
            .state("texas")
            .state("new york");

        let proxies: Vec<_> = query
            .execute()
            .unwrap()
            .iter()
            .sorted_by(|a, b| a.id.cmp(&b.id))
            .collect();
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].id, "1");
        assert_eq!(proxies[1].id, "2");

        query.reset().state("california");
        let proxies: Vec<_> = query
            .execute()
            .unwrap()
            .iter()
            .sorted_by(|a, b| a.id.cmp(&b.id))
            .collect();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].id, "3");
    }

    #[tokio::test]
    async fn test_proxy_db_invalid_row_cases() {
        let mut db = ProxyDB::new();
        let mut reader = ProxyCsvRowReader::raw(
            "id1,datacenter,authority:80,,,,,,,,,\nid2,mobile,authority:80,,,,,,,,,;",
        );
        while let Some(proxy) = reader.next().await.unwrap() {
            assert_eq!(
                ProxyDBErrorKind::InvalidRow,
                db.append(proxy).unwrap_err().kind
            );
        }
    }
}

/// `basic <userinfo>` / `bearer <token>`, the only shapes a [`ProxyCredential`] has.
mod credential_str {
    use rama_net::{
        address::UserInfo,
        user::{Bearer, ProxyCredential},
    };
    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};

    #[expect(clippy::ref_option, reason = "signature serde's `with` module demands")]
    pub(super) fn serialize<S: Serializer>(
        credential: &Option<ProxyCredential>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match credential {
            Some(ProxyCredential::Basic(basic)) => {
                serializer.collect_str(&format_args!("basic {}", UserInfo::from(basic.clone())))
            }
            Some(ProxyCredential::Bearer(bearer)) => {
                serializer.collect_str(&format_args!("bearer {bearer}"))
            }
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<ProxyCredential>, D::Error> {
        let Some(text) = Option::<String>::deserialize(deserializer)? else {
            return Ok(None);
        };
        let (scheme, value) = text
            .split_once(' ')
            .ok_or_else(|| D::Error::custom("proxy credential is missing its scheme"))?;
        if scheme.eq_ignore_ascii_case("basic") {
            let basic = value
                .parse::<UserInfo>()
                .and_then(|user_info| user_info.to_basic())
                .map_err(D::Error::custom)?;
            Ok(Some(ProxyCredential::Basic(basic)))
        } else if scheme.eq_ignore_ascii_case("bearer") {
            let bearer = value.parse::<Bearer>().map_err(D::Error::custom)?;
            Ok(Some(ProxyCredential::Bearer(bearer)))
        } else {
            Err(D::Error::custom("unknown proxy credential scheme"))
        }
    }
}

/// The textual form of a [`ProxyProtocol`]; see [`Proxy::protocols`].
///
/// A token is the scheme of a proxy address with the path a MASQUE one offers its tunnels
/// on, which is how [`ProxyProtocol::try_from_scheme_and_path`] reads it.
pub(super) mod protocol_token {
    use rama_net::address::ProxyProtocol;
    use std::fmt;

    pub(crate) fn parse(token: &str) -> Option<ProxyProtocol> {
        let (scheme, path) = match token.find('/') {
            Some(index) => (&token[..index], &token[index..]),
            None => (token, ""),
        };
        ProxyProtocol::try_from_scheme_and_path(scheme, path).ok()
    }

    pub(crate) fn display(protocol: &ProxyProtocol) -> impl fmt::Display {
        Token(protocol.clone())
    }

    struct Token(ProxyProtocol);

    impl fmt::Display for Token {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.0.scheme().fmt(f)?;
            if let Some(connect_udp) = self.0.connect_udp()
                && !connect_udp.template.is_connect_udp_default()
            {
                connect_udp.template.fmt(f)?;
            }
            Ok(())
        }
    }
}

/// `protocols` as a list of [`protocol_token`]s.
mod protocol_tokens {
    use super::{ProxyProtocols, protocol_token};
    use serde::{
        Deserialize as _, Deserializer, Serializer, de::Error as _, ser::SerializeSeq as _,
    };

    pub(super) fn serialize<S: Serializer>(
        protocols: &ProxyProtocols,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut tokens: Vec<_> = protocols
            .iter()
            .map(|protocol| protocol_token::display(protocol).to_string())
            .collect();
        // A set has no order of its own, and a record should serialize the same every time.
        tokens.sort_unstable();
        let mut sequence = serializer.serialize_seq(Some(tokens.len()))?;
        for token in tokens {
            sequence.serialize_element(&token)?;
        }
        sequence.end()
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<ProxyProtocols, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|token| {
                protocol_token::parse(&token)
                    .ok_or_else(|| D::Error::custom(format!("invalid proxy protocol: {token}")))
            })
            .collect()
    }
}
