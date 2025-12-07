use super::{ProxyContext, ProxyFilter, StringFilter};
use rama_net::{address::ProxyAddress, asn::Asn, transport::TransportProtocol};
use rama_utils::str::NonEmptyStr;
use serde::{Deserialize, Serialize};

#[cfg(feature = "memory-db")]
use venndb::VennDB;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "memory-db", derive(VennDB))]
#[cfg_attr(feature = "memory-db", venndb(validator = proxydb_insert_validator))]
/// The selected proxy to use to connect to the proxy.
pub struct Proxy {
    #[cfg_attr(feature = "memory-db", venndb(key))]
    /// Unique identifier of the proxy.
    pub id: NonEmptyStr,

    /// The address to be used to connect to the proxy, including credentials if needed.
    pub address: ProxyAddress,

    /// True if the proxy supports TCP connections.
    pub tcp: bool,

    /// True if the proxy supports UDP connections.
    pub udp: bool,

    /// http-proxy enabled
    pub http: bool,

    /// https-proxy enabled
    pub https: bool,

    /// socks5-proxy enabled
    pub socks5: bool,

    /// socks5h-proxy enabled
    pub socks5h: bool,

    /// Proxy is located in a datacenter.
    pub datacenter: bool,

    /// Proxy's IP is labeled as residential.
    pub residential: bool,

    /// Proxy's IP originates from a mobile network.
    pub mobile: bool,

    #[cfg_attr(feature = "memory-db", venndb(filter, any))]
    /// Pool ID of the proxy.
    pub pool_id: Option<StringFilter>,

    #[cfg_attr(feature = "memory-db", venndb(filter, any))]
    /// Continent of the proxy.
    pub continent: Option<StringFilter>,

    #[cfg_attr(feature = "memory-db", venndb(filter, any))]
    /// Country of the proxy.
    pub country: Option<StringFilter>,

    #[cfg_attr(feature = "memory-db", venndb(filter, any))]
    /// State of the proxy.
    pub state: Option<StringFilter>,

    #[cfg_attr(feature = "memory-db", venndb(filter, any))]
    /// City of the proxy.
    pub city: Option<StringFilter>,

    #[cfg_attr(feature = "memory-db", venndb(filter, any))]
    /// Mobile carrier of the proxy.
    pub carrier: Option<StringFilter>,

    #[cfg_attr(feature = "memory-db", venndb(filter, any))]
    ///  Autonomous System Number (ASN).
    pub asn: Option<Asn>,
}

#[cfg(feature = "memory-db")]
/// Validate the proxy is valid according to rules that are not enforced by the type system.
fn proxydb_insert_validator(proxy: &Proxy) -> bool {
    (proxy.datacenter || proxy.residential || proxy.mobile)
        && (((proxy.http || proxy.https) && proxy.tcp)
            || ((proxy.socks5 || proxy.socks5h) && (proxy.tcp || proxy.udp)))
}

impl Proxy {
    /// Check if the proxy is a match for the given[`ProxyContext`] and [`ProxyFilter`].
    #[must_use]
    pub fn is_match(&self, ctx: &ProxyContext, filter: &ProxyFilter) -> bool {
        if let Some(id) = &filter.id
            && id != &self.id
        {
            return false;
        }

        match ctx.protocol {
            TransportProtocol::Udp => {
                if !(self.socks5 || self.socks5h) || !self.udp {
                    return false;
                }
            }
            TransportProtocol::Tcp => {
                if !self.tcp || !(self.http || self.https || self.socks5 || self.socks5h) {
                    return false;
                }
            }
        }

        filter
            .continent
            .as_ref()
            .map(|c| {
                let continent = self.continent.as_ref();
                c.iter().any(|c| Some(c) == continent)
            })
            .unwrap_or(true)
            && filter
                .country
                .as_ref()
                .map(|c| {
                    let country = self.country.as_ref();
                    c.iter().any(|c| Some(c) == country)
                })
                .unwrap_or(true)
            && filter
                .state
                .as_ref()
                .map(|s| {
                    let state = self.state.as_ref();
                    s.iter().any(|s| Some(s) == state)
                })
                .unwrap_or(true)
            && filter
                .city
                .as_ref()
                .map(|c| {
                    let city = self.city.as_ref();
                    c.iter().any(|c| Some(c) == city)
                })
                .unwrap_or(true)
            && filter
                .pool_id
                .as_ref()
                .map(|p| {
                    let pool_id = self.pool_id.as_ref();
                    p.iter().any(|p| Some(p) == pool_id)
                })
                .unwrap_or(true)
            && filter
                .carrier
                .as_ref()
                .map(|c| {
                    let carrier = self.carrier.as_ref();
                    c.iter().any(|c| Some(c) == carrier)
                })
                .unwrap_or(true)
            && filter
                .asn
                .as_ref()
                .map(|a| {
                    let asn = self.asn.as_ref();
                    a.iter().any(|a| Some(a) == asn)
                })
                .unwrap_or(true)
            && filter
                .datacenter
                .map(|d| d == self.datacenter)
                .unwrap_or(true)
            && filter
                .residential
                .map(|r| r == self.residential)
                .unwrap_or(true)
            && filter.mobile.map(|m| m == self.mobile).unwrap_or(true)
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
        let proxy = parse_csv_row("id,1,,1,,,,1,,,authority:80,,,,,,,,").unwrap();
        db.append(proxy).unwrap();

        let mut query = db.query();
        query.tcp(true).http(true);

        let proxy = query.execute().unwrap().any();
        assert_eq!(proxy.id, "id");
    }

    #[tokio::test]
    async fn test_proxy_db_happy_path_any_country() {
        let mut db = ProxyDB::new();
        let mut reader = ProxyCsvRowReader::raw(
            "1,1,,1,,,,1,,,authority:80,,,US,,,,,\n2,1,,1,,,,1,,,authority:80,,,*,,,,,",
        );
        while let Some(proxy) = reader.next().await.unwrap() {
            db.append(proxy).unwrap();
        }

        let mut query = db.query();
        query.tcp(true).http(true).country("US");

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

    #[tokio::test]
    async fn test_proxy_db_happy_path_any_country_city() {
        let mut db = ProxyDB::new();
        let mut reader = ProxyCsvRowReader::raw(
            "1,1,,1,,,,1,,,authority:80,,,US,,New York,,,\n2,1,,1,,,,1,,,authority:80,,,*,,*,,,",
        );
        while let Some(proxy) = reader.next().await.unwrap() {
            db.append(proxy).unwrap();
        }

        let mut query = db.query();
        query.tcp(true).http(true).country("US").city("new york");

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
            "1,1,,1,,,,1,,,authority:80,,europe,BE,,Brussels,,1348,\n2,1,,1,,,,1,,,authority:80,,asia,CN,,Shenzen,,1348,\n3,1,,1,,,,1,,,authority:80,,asia,CN,,Peking,,42,",
        );
        while let Some(proxy) = reader.next().await.unwrap() {
            db.append(proxy).unwrap();
        }

        let mut query = db.query();
        query
            .tcp(true)
            .http(true)
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
            "1,1,,1,,,,1,,,authority:80,,,US,Texas,,,,\n2,1,,1,,,,1,,,authority:80,,,US,New York,,,,\n3,1,,1,,,,1,,,authority:80,,,US,California,,,,",
        );
        while let Some(proxy) = reader.next().await.unwrap() {
            db.append(proxy).unwrap();
        }

        let mut query = db.query();
        query.tcp(true).http(true).state("texas").state("new york");

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
            "id1,1,,,,,,,,,authority:80,,,,,,,\nid2,,1,,,,,,,,authority:80,,,,,,,\nid3,,1,1,,,,,,,authority:80,,,,,,,\nid4,,1,1,,,,,1,,authority:80,,,,,,,\nid5,,1,1,,,,,1,,authority:80,,,,,,,",
        );
        while let Some(proxy) = reader.next().await.unwrap() {
            assert_eq!(
                ProxyDBErrorKind::InvalidRow,
                db.append(proxy).unwrap_err().kind
            );
        }
    }
}
