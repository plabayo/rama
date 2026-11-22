use super::{Proxy, ProxyProtocols, StringFilter, internal::protocol_token};
use rama_net::{
    address::ProxyAddress,
    asn::{Asn, InvalidAsn},
};
use std::path::Path;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader, Lines},
};

#[derive(Debug)]
/// A CSV Reader that can be used to create a [`Proxy`] database from a CSV file or raw data.
///
/// One proxy per line, in this column order:
///
/// ```text
/// id,ip_category,address,pool_id,continent,country,state,city,carrier,asn,credential,protocols
/// ```
///
/// - `ip_category`: an [`IpCategory`](crate::IpCategory) name, such as `residential`
/// - `address`: `[user[:pass]@]host:port`, without a scheme
/// - `credential`: replaces the credential of the address when set, written as a
///   [`ProxyCredential`](rama_net::user::ProxyCredential)
/// - `protocols`: every protocol the proxy speaks, `;`-separated and in order of
///   preference, as [`Proxy::protocols`] documents, such as `socks5+tcp;socks5+udp;h2`
///
/// A `,` separates columns and a `;` protocols, so neither can appear in a template here.
pub struct ProxyCsvRowReader {
    data: ProxyCsvRowReaderData,
    line: usize,
}

impl ProxyCsvRowReader {
    /// Create a new [`ProxyCsvRowReader`] from the given CSV file.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, ProxyCsvRowReaderError> {
        let file = rama_utils::fs::safe_open(path).await?;
        let reader = BufReader::new(file);
        let lines = reader.lines();
        Ok(Self {
            data: ProxyCsvRowReaderData::File(lines),
            line: 0,
        })
    }

    /// Create a new [`ProxyCsvRowReader`] from the given CSV data.
    pub fn raw(data: impl AsRef<str>) -> Self {
        let lines: Vec<_> = data.as_ref().lines().rev().map(str::to_owned).collect();
        Self {
            data: ProxyCsvRowReaderData::Raw(lines),
            line: 0,
        }
    }

    /// Read the next row from the CSV file.
    pub async fn next(&mut self) -> Result<Option<Proxy>, ProxyCsvRowReaderError> {
        let line = match &mut self.data {
            ProxyCsvRowReaderData::File(lines) => lines.next_line().await?,
            ProxyCsvRowReaderData::Raw(lines) => lines.pop(),
        };
        let Some(line) = line else {
            return Ok(None);
        };
        self.line += 1;
        match parse_csv_row(&line) {
            Some(proxy) => Ok(Some(proxy)),
            None => Err(ProxyCsvRowReaderError {
                kind: ProxyCsvRowReaderErrorKind::InvalidRow { line: self.line },
            }),
        }
    }
}

fn strip_csv_quotes(p: &str) -> &str {
    p.strip_prefix('"')
        .and_then(|p| p.strip_suffix('"'))
        .unwrap_or(p)
}

pub(crate) fn parse_csv_row(row: &str) -> Option<Proxy> {
    let mut iter = row.split(',').map(strip_csv_quotes);

    let id = iter.next().and_then(|s| s.try_into().ok())?;

    let kind = iter.next()?.parse().ok()?;
    let address = iter.next().filter(|s| !s.is_empty() && !s.contains('/'))?;
    let ProxyAddress {
        address,
        mut credential,
        ..
    } = address.parse().ok()?;

    let pool_id = parse_csv_opt_string_filter(iter.next()?);
    let continent = parse_csv_opt_string_filter(iter.next()?);
    let country = parse_csv_opt_string_filter(iter.next()?);
    let state = parse_csv_opt_string_filter(iter.next()?);
    let city = parse_csv_opt_string_filter(iter.next()?);
    let carrier = parse_csv_opt_string_filter(iter.next()?);
    let asn = parse_csv_opt_asn(iter.next()?).ok()?;

    let value = iter.next()?;
    if !value.is_empty() {
        credential = Some(value.parse().ok()?);
    }

    let protocols = iter
        .next()?
        .split(';')
        .filter(|token| !token.is_empty())
        .map(protocol_token::parse)
        .collect::<Option<ProxyProtocols>>()?;

    if iter.next().is_some() {
        return None;
    }

    Some(Proxy {
        id,
        address,
        credential,
        protocols,
        ip_category: kind,
        pool_id,
        continent,
        country,
        state,
        city,
        carrier,
        asn,
    })
}

fn parse_csv_opt_string_filter(value: &str) -> Option<StringFilter> {
    if value.is_empty() {
        None
    } else {
        Some(StringFilter::from(value))
    }
}

fn parse_csv_opt_asn(value: &str) -> Result<Option<Asn>, InvalidAsn> {
    if value.is_empty() {
        Ok(None)
    } else {
        Asn::try_from(value).map(Some)
    }
}

#[derive(Debug)]
enum ProxyCsvRowReaderData {
    File(Lines<BufReader<File>>),
    Raw(Vec<String>),
}

#[derive(Debug)]
/// An error that can occur when reading a Proxy CSV row.
pub struct ProxyCsvRowReaderError {
    kind: ProxyCsvRowReaderErrorKind,
}

#[derive(Debug)]
/// The kind of error that can occur when reading a Proxy CSV row.
pub enum ProxyCsvRowReaderErrorKind {
    /// An I/O error occurred while reading the CSV row.
    IoError(std::io::Error),
    /// The CSV row is invalid, and could not be parsed.
    ///
    /// A row holds credentials, so it is named by its 1-based line number only.
    InvalidRow {
        /// The 1-based line number of the row.
        line: usize,
    },
}

impl std::fmt::Display for ProxyCsvRowReaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ProxyCsvRowReaderErrorKind::IoError(err) => write!(f, "I/O error: {err}"),
            ProxyCsvRowReaderErrorKind::InvalidRow { line } => {
                write!(f, "Invalid row at line {line}")
            }
        }
    }
}

impl std::error::Error for ProxyCsvRowReaderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ProxyCsvRowReaderErrorKind::IoError(err) => Some(err),
            ProxyCsvRowReaderErrorKind::InvalidRow { .. } => None,
        }
    }
}

impl From<std::io::Error> for ProxyCsvRowReaderError {
    fn from(err: std::io::Error) -> Self {
        Self {
            kind: ProxyCsvRowReaderErrorKind::IoError(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IpCategory;
    use crate::{ProxyFilter, proxydb::ProxyContext};
    use rama_net::address::{ProxyPathTemplate, ProxyProtocol};
    use rama_net::http::Version;
    use rama_net::transport::TransportProtocol;
    use rama_net::user::credentials::basic;
    use rama_utils::str::{NonEmptyStr, non_empty_str, smol_str::SmolStr};

    #[test]
    fn test_parse_csv_opt_string_filter() {
        for (input, output) in [
            ("", None),
            ("value", Some("value")),
            ("*", Some("*")),
            ("Foo", Some("foo")),
            ("  ok ", Some("ok")),
            (" NO  ", Some("no")),
        ] {
            assert_eq!(
                parse_csv_opt_string_filter(input)
                    .as_ref()
                    .map(|f| f.as_ref()),
                output,
            );
        }
    }

    #[test]
    fn test_parse_csv_opt_string_filter_is_any() {
        let filter = parse_csv_opt_string_filter("*").unwrap();
        assert!(filter.is_any());
    }

    fn proxy(id: NonEmptyStr, address: &str, kind: IpCategory) -> Proxy {
        Proxy {
            id,
            address: address.parse().unwrap(),
            credential: None,
            protocols: ProxyProtocols::new(),
            ip_category: kind,
            pool_id: None,
            continent: None,
            country: None,
            state: None,
            city: None,
            carrier: None,
            asn: None,
        }
    }

    #[test]
    fn test_parse_csv_row_happy_path() {
        for (input, output) in [
            (
                "id,datacenter,authority:80,,,,,,,,,",
                proxy(non_empty_str!("id"), "authority:80", IpCategory::Datacenter),
            ),
            (
                "id,Mobile,authority:80,pool_id,,country,,city,carrier,,Basic dXNlcm5hbWU6cGFzc3dvcmQ=,http",
                Proxy {
                    credential: Some(basic!("username", "password").into()),
                    protocols: ProxyProtocols::from([ProxyProtocol::HTTP]),
                    pool_id: Some("pool_id".into()),
                    country: Some("country".into()),
                    city: Some("city".into()),
                    carrier: Some("carrier".into()),
                    ..proxy(non_empty_str!("id"), "authority:80", IpCategory::Mobile)
                },
            ),
            (
                "123,residential,host:1234,,americas,*,*,*,carrier,13335,,socks5+tcp",
                Proxy {
                    protocols: ProxyProtocols::from([ProxyProtocol::SOCKS5_TCP]),
                    continent: Some("americas".into()),
                    country: Some("*".into()),
                    state: Some("*".into()),
                    city: Some("*".into()),
                    carrier: Some("carrier".into()),
                    asn: Some(Asn::from_static(13335)),
                    ..proxy(non_empty_str!("123"), "host:1234", IpCategory::Residential)
                },
            ),
            (
                "foo,isp,john:secret@bar:443,,europe,,,,,0,,https;socks5h+udp",
                Proxy {
                    credential: Some(basic!("john", "secret").into()),
                    protocols: ProxyProtocols::from([
                        ProxyProtocol::HTTPS,
                        ProxyProtocol::SOCKS5H_UDP,
                    ]),
                    continent: Some("europe".into()),
                    asn: Some(Asn::unspecified()),
                    ..proxy(non_empty_str!("foo"), "bar:443", IpCategory::Isp)
                },
            ),
            (
                "foo,datacenter,john:secret@bar:443,,,,,,,,Basic amFuZTpvdGhlcg==,h2",
                Proxy {
                    credential: Some(basic!("jane", "other").into()),
                    protocols: ProxyProtocols::from([ProxyProtocol::H2]),
                    ..proxy(non_empty_str!("foo"), "bar:443", IpCategory::Datacenter)
                },
            ),
        ] {
            let proxy = parse_csv_row(input).unwrap();
            assert_eq!(proxy.id, output.id, "{input}");
            assert_eq!(proxy.address, output.address, "{input}");
            assert_eq!(proxy.credential, output.credential, "{input}");
            assert_eq!(proxy.protocols, output.protocols, "{input}");
            assert_eq!(proxy.ip_category, output.ip_category, "{input}");
            assert_eq!(proxy.pool_id, output.pool_id, "{input}");
            assert_eq!(proxy.continent, output.continent, "{input}");
            assert_eq!(proxy.country, output.country, "{input}");
            assert_eq!(proxy.state, output.state, "{input}");
            assert_eq!(proxy.city, output.city, "{input}");
            assert_eq!(proxy.carrier, output.carrier, "{input}");
            assert_eq!(proxy.asn, output.asn, "{input}");
        }
    }

    #[test]
    fn test_parse_csv_row_mistakes() {
        for input in [
            // garbage rows
            "",
            ",",
            ",,,,,,",
            ",,,,,,,,,,,,,",
            ",,,,,,,,,,,,,,",
            // too many columns
            "id,datacenter,authority:80,,,,,,,,,http,",
            // too few columns
            "id,datacenter,authority:80,,,,,,,,",
            // missing id, ip category or address
            ",datacenter,authority:80,,,,,,,,,http",
            "id,,authority:80,,,,,,,,,http",
            "id,datacenter,,,,,,,,,,http",
            // unknown ip category
            "id,hosting,authority:80,,,,,,,,,http",
            // an address with a scheme or path
            "id,datacenter,http://authority:80,,,,,,,,,http",
            "id,datacenter,authority:80/x,,,,,,,,,http",
            // invalid asn, credential or protocol
            "id,datacenter,authority:80,,,,,,,foo,,http",
            "id,datacenter,authority:80,,,,,,,,:foo,http",
            "id,datacenter,authority:80,,,,,,,,,socks5+h2",
        ] {
            assert!(parse_csv_row(input).is_none(), "input: {input}");
        }
    }

    #[test]
    fn the_protocols_column_names_every_protocol() {
        let row = "id,mobile,authority:443,,,,,,,,,h2;h3+udp;socks5h+udp;warp;";
        let proxy = parse_csv_row(row).unwrap();
        assert_eq!(
            proxy.protocols,
            ProxyProtocols::from([
                ProxyProtocol::H2,
                ProxyProtocol::connect_udp(Version::HTTP_3),
                ProxyProtocol::SOCKS5H_UDP,
                ProxyProtocol::Custom(SmolStr::new_static("warp")),
            ]),
        );
    }

    #[test]
    fn a_protocol_carries_its_connect_udp_template() {
        let row = "id,mobile,authority:443,,,,,,,,,h3/m?h={target_host}&p={target_port}";
        let proxy = parse_csv_row(row).unwrap();
        let [protocol] = Vec::from_iter(proxy.protocols).try_into().unwrap();
        assert_eq!(protocol.http_version(), Some(Version::HTTP_3));
        assert_eq!(
            protocol.path_template().map(ProxyPathTemplate::as_str),
            Some("/m?h={target_host}&p={target_port}"),
        );
    }

    #[tokio::test]
    async fn test_proxy_csv_row_reader_happy_one_row() {
        let mut reader = ProxyCsvRowReader::raw(
            "id,datacenter,authority:80,pool_id,continent,country,state,city,carrier,13335,Basic dXNlcm5hbWU6cGFzc3dvcmQ=,http",
        );
        let proxy = reader.next().await.unwrap().unwrap();

        assert_eq!(proxy.id, "id");
        assert_eq!(proxy.address, "authority:80".parse().unwrap());
        assert_eq!(
            proxy.credential,
            Some(basic!("username", "password").into())
        );
        assert_eq!(proxy.protocols, ProxyProtocols::from([ProxyProtocol::HTTP]));
        assert_eq!(proxy.ip_category, IpCategory::Datacenter);
        assert_eq!(proxy.pool_id, Some("pool_id".into()));
        assert_eq!(proxy.continent, Some("continent".into()));
        assert_eq!(proxy.country, Some("country".into()));
        assert_eq!(proxy.state, Some("state".into()));
        assert_eq!(proxy.city, Some("city".into()));
        assert_eq!(proxy.carrier, Some("carrier".into()));
        assert_eq!(proxy.asn, Some(Asn::from_static(13335)));

        // no more rows to read
        assert!(reader.next().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_proxy_csv_row_reader_happy_multi_row() {
        let mut reader = ProxyCsvRowReader::raw(
            "id,datacenter,authority:80,pool_id,continent,country,state,city,carrier,42,Basic dXNlcm5hbWU6cGFzc3dvcmQ=,https;socks5+tcp\nid2,residential,authority2:80,pool_id2,continent2,country2,state2,city2,carrier2,1,,http",
        );

        let proxy = reader.next().await.unwrap().unwrap();
        assert_eq!(proxy.id, "id");
        assert_eq!(proxy.address, "authority:80".parse().unwrap());
        assert_eq!(
            proxy.credential,
            Some(basic!("username", "password").into())
        );
        assert_eq!(
            proxy.protocols,
            ProxyProtocols::from([ProxyProtocol::HTTPS, ProxyProtocol::SOCKS5_TCP]),
        );
        assert_eq!(proxy.ip_category, IpCategory::Datacenter);
        assert_eq!(proxy.pool_id, Some("pool_id".into()));
        assert_eq!(proxy.continent, Some("continent".into()));
        assert_eq!(proxy.country, Some("country".into()));
        assert_eq!(proxy.state, Some("state".into()));
        assert_eq!(proxy.city, Some("city".into()));
        assert_eq!(proxy.carrier, Some("carrier".into()));
        assert_eq!(proxy.asn, Some(Asn::from_static(42)));

        let proxy = reader.next().await.unwrap().unwrap();
        assert_eq!(proxy.id, "id2");
        assert_eq!(proxy.address, "authority2:80".parse().unwrap());
        assert_eq!(proxy.credential, None);
        assert_eq!(proxy.protocols, ProxyProtocols::from([ProxyProtocol::HTTP]));
        assert_eq!(proxy.ip_category, IpCategory::Residential);
        assert_eq!(proxy.pool_id, Some("pool_id2".into()));
        assert_eq!(proxy.continent, Some("continent2".into()));
        assert_eq!(proxy.country, Some("country2".into()));
        assert_eq!(proxy.state, Some("state2".into()));
        assert_eq!(proxy.city, Some("city2".into()));
        assert_eq!(proxy.carrier, Some("carrier2".into()));
        assert_eq!(proxy.asn, Some(Asn::from_static(1)));

        assert!(reader.next().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_proxy_csv_row_reader_failure_empty_data() {
        let mut reader = ProxyCsvRowReader::raw("");
        assert!(reader.next().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_proxy_csv_row_reader_failure_invalid_row() {
        let mut reader = ProxyCsvRowReader::raw(",,,,,,,,,,,");
        reader.next().await.unwrap_err();
    }

    #[tokio::test]
    async fn an_invalid_row_error_names_the_line_and_not_the_row() {
        let mut reader = ProxyCsvRowReader::raw(
            "id,true,false,true,,false,,true,false,true,authority:80,pool_id,continent,country,state,city,carrier,13335,Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
        );
        let error = reader.next().await.unwrap_err().to_string();
        assert!(!error.contains("dXNlcm5hbWU6cGFzc3dvcmQ="), "{error}");
        assert!(!error.contains("password"), "{error}");
        assert!(error.contains("line 1"), "{error}");
    }

    #[test]
    fn test_proxy_is_match_happy_path_proxy_with_any_filter_string_cases() {
        let proxy = parse_csv_row("id,datacenter,authority:80,*,*,*,*,*,*,0,,http").unwrap();
        let ctx = ProxyContext {
            protocol: TransportProtocol::Tcp,
        };

        for filter in [
            ProxyFilter::default(),
            ProxyFilter {
                pool_id: Some(vec![StringFilter::new("pool_a")]),
                country: Some(vec![StringFilter::new("country_a")]),
                city: Some(vec![StringFilter::new("city_a")]),
                carrier: Some(vec![StringFilter::new("carrier_a")]),
                ..Default::default()
            },
            ProxyFilter {
                pool_id: Some(vec![StringFilter::new("pool_a")]),
                ..Default::default()
            },
            ProxyFilter {
                continent: Some(vec![StringFilter::new("continent_a")]),
                ..Default::default()
            },
            ProxyFilter {
                country: Some(vec![StringFilter::new("country_a")]),
                ..Default::default()
            },
            ProxyFilter {
                state: Some(vec![StringFilter::new("state_a")]),
                ..Default::default()
            },
            ProxyFilter {
                city: Some(vec![StringFilter::new("city_a")]),
                carrier: Some(vec![StringFilter::new("carrier_a")]),
                ..Default::default()
            },
            ProxyFilter {
                carrier: Some(vec![StringFilter::new("carrier_a")]),
                ..Default::default()
            },
        ] {
            assert!(proxy.is_match(&ctx, &filter), "filter: {filter:?}");
        }
    }

    #[test]
    fn direct_match_requires_a_wildcard_row_for_a_wildcard_filter() {
        let proxy = parse_csv_row(
            "id,datacenter,authority:80,pool,continent,country,state,city,carrier,42,,http",
        )
        .unwrap();
        let ctx = ProxyContext {
            protocol: TransportProtocol::Tcp,
        };

        assert!(proxy.is_match(&ctx, &ProxyFilter::default()));
        assert!(proxy.is_match(
            &ctx,
            &ProxyFilter {
                pool_id: Some(vec![StringFilter::new("pool")]),
                continent: Some(vec![StringFilter::new("continent")]),
                country: Some(vec![StringFilter::new("country")]),
                state: Some(vec![StringFilter::new("state")]),
                city: Some(vec![StringFilter::new("city")]),
                carrier: Some(vec![StringFilter::new("carrier")]),
                asn: Some(vec![Asn::from_static(42)]),
                ..Default::default()
            }
        ));
        for filter in [
            ProxyFilter {
                pool_id: Some(vec![StringFilter::new("*")]),
                ..Default::default()
            },
            ProxyFilter {
                continent: Some(vec![StringFilter::new("*")]),
                ..Default::default()
            },
            ProxyFilter {
                country: Some(vec![StringFilter::new("*")]),
                ..Default::default()
            },
            ProxyFilter {
                state: Some(vec![StringFilter::new("*")]),
                ..Default::default()
            },
            ProxyFilter {
                city: Some(vec![StringFilter::new("*")]),
                ..Default::default()
            },
            ProxyFilter {
                carrier: Some(vec![StringFilter::new("*")]),
                ..Default::default()
            },
            ProxyFilter {
                pool_id: Some(vec![StringFilter::new("*")]),
                country: Some(vec![StringFilter::new("country")]),
                city: Some(vec![StringFilter::new("city")]),
                carrier: Some(vec![StringFilter::new("carrier")]),
                ..Default::default()
            },
            ProxyFilter {
                pool_id: Some(vec![StringFilter::new("pool")]),
                country: Some(vec![StringFilter::new("*")]),
                city: Some(vec![StringFilter::new("city")]),
                carrier: Some(vec![StringFilter::new("carrier")]),
                ..Default::default()
            },
            ProxyFilter {
                pool_id: Some(vec![StringFilter::new("pool")]),
                country: Some(vec![StringFilter::new("country")]),
                city: Some(vec![StringFilter::new("*")]),
                carrier: Some(vec![StringFilter::new("carrier")]),
                ..Default::default()
            },
            ProxyFilter {
                pool_id: Some(vec![StringFilter::new("pool")]),
                country: Some(vec![StringFilter::new("country")]),
                city: Some(vec![StringFilter::new("city")]),
                carrier: Some(vec![StringFilter::new("*")]),
                ..Default::default()
            },
            ProxyFilter {
                continent: Some(vec![StringFilter::new("*")]),
                ..Default::default()
            },
        ] {
            assert!(!proxy.is_match(&ctx, &filter), "filter: {filter:?}");
        }
    }
}
