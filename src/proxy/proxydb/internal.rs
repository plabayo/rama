use super::{ProxyFilter, StringFilter};
use crate::{
    net::{
        address::ProxyAddress,
        asn::{Asn, InvalidAsn},
        transport::{TransportContext, TransportProtocol},
        user::ProxyCredential,
    },
    utils::str::NonEmptyString,
};
use std::path::Path;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader, Lines},
};
use venndb::VennDB;

#[derive(Debug, Clone, VennDB)]
#[venndb(validator = proxydb_insert_validator)]
/// The selected proxy to use to connect to the proxy.
pub struct Proxy {
    #[venndb(key)]
    /// Unique identifier of the proxy.
    pub id: NonEmptyString,

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

    #[venndb(filter, any)]
    /// Pool ID of the proxy.
    pub pool_id: Option<StringFilter>,

    #[venndb(filter, any)]
    /// Continent of the proxy.
    pub continent: Option<StringFilter>,

    #[venndb(filter, any)]
    /// Country of the proxy.
    pub country: Option<StringFilter>,

    #[venndb(filter, any)]
    /// State of the proxy.
    pub state: Option<StringFilter>,

    #[venndb(filter, any)]
    /// City of the proxy.
    pub city: Option<StringFilter>,

    #[venndb(filter, any)]
    /// Mobile carrier of the proxy.
    pub carrier: Option<StringFilter>,

    #[venndb(filter, any)]
    ///  Autonomous System Number (ASN).
    pub asn: Option<Asn>,
}

/// Validate the proxy is valid according to rules that are not enforced by the type system.
fn proxydb_insert_validator(proxy: &Proxy) -> bool {
    (proxy.datacenter || proxy.residential || proxy.mobile)
        && (((proxy.http || proxy.https) && proxy.tcp)
            || ((proxy.socks5 || proxy.socks5h) && (proxy.tcp || proxy.udp)))
}

impl Proxy {
    /// Check if the proxy is a match for the given[`TransportContext`] and [`ProxyFilter`].
    pub fn is_match(&self, ctx: &TransportContext, filter: &ProxyFilter) -> bool {
        if let Some(id) = &filter.id {
            if id != &self.id {
                return false;
            }
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

        return filter
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
            && filter.mobile.map(|m| m == self.mobile).unwrap_or(true);
    }
}

#[derive(Debug)]
/// A CSV Reader that can be used to create a [`MemoryProxyDB`] from a CSV file or raw data.
///
/// [`MemoryProxyDB`]: crate::proxy::proxydb::MemoryProxyDB
pub struct ProxyCsvRowReader {
    data: ProxyCsvRowReaderData,
}

impl ProxyCsvRowReader {
    /// Create a new [`ProxyCsvRowReader`] from the given CSV file.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, ProxyCsvRowReaderError> {
        let file = tokio::fs::File::open(path).await?;
        let reader = BufReader::new(file);
        let lines = reader.lines();
        Ok(ProxyCsvRowReader {
            data: ProxyCsvRowReaderData::File(lines),
        })
    }

    /// Create a new [`ProxyCsvRowReader`] from the given CSV data.
    pub fn raw(data: impl AsRef<str>) -> Self {
        let lines: Vec<_> = data.as_ref().lines().rev().map(str::to_owned).collect();
        ProxyCsvRowReader {
            data: ProxyCsvRowReaderData::Raw(lines),
        }
    }

    /// Read the next row from the CSV file.
    pub async fn next(&mut self) -> Result<Option<Proxy>, ProxyCsvRowReaderError> {
        match &mut self.data {
            ProxyCsvRowReaderData::File(lines) => {
                let line = lines.next_line().await?;
                match line {
                    Some(line) => Ok(Some(match parse_csv_row(&line) {
                        Some(proxy) => proxy,
                        None => {
                            return Err(ProxyCsvRowReaderError {
                                kind: ProxyCsvRowReaderErrorKind::InvalidRow(line),
                            });
                        }
                    })),
                    None => Ok(None),
                }
            }
            ProxyCsvRowReaderData::Raw(lines) => match lines.pop() {
                Some(line) => Ok(Some(match parse_csv_row(&line) {
                    Some(proxy) => proxy,
                    None => {
                        return Err(ProxyCsvRowReaderError {
                            kind: ProxyCsvRowReaderErrorKind::InvalidRow(line),
                        });
                    }
                })),
                None => Ok(None),
            },
        }
    }
}

fn strip_csv_quotes(p: &str) -> &str {
    p.strip_prefix('"')
        .and_then(|p| p.strip_suffix('"'))
        .unwrap_or(p)
}

fn parse_csv_row(row: &str) -> Option<Proxy> {
    let mut iter = row.split(',').map(strip_csv_quotes);

    let id = iter.next().and_then(|s| s.try_into().ok())?;

    let tcp = iter.next().and_then(parse_csv_bool)?;
    let udp = iter.next().and_then(parse_csv_bool)?;
    let http = iter.next().and_then(parse_csv_bool)?;
    let https = iter.next().and_then(parse_csv_bool)?;
    let socks5 = iter.next().and_then(parse_csv_bool)?;
    let socks5h = iter.next().and_then(parse_csv_bool)?;
    let datacenter = iter.next().and_then(parse_csv_bool)?;
    let residential = iter.next().and_then(parse_csv_bool)?;
    let mobile = iter.next().and_then(parse_csv_bool)?;
    let mut address = iter.next().and_then(|s| {
        if s.is_empty() {
            None
        } else {
            ProxyAddress::try_from(s).ok()
        }
    })?;
    let pool_id = parse_csv_opt_string_filter(iter.next()?);
    let continent = parse_csv_opt_string_filter(iter.next()?);
    let country = parse_csv_opt_string_filter(iter.next()?);
    let state = parse_csv_opt_string_filter(iter.next()?);
    let city = parse_csv_opt_string_filter(iter.next()?);
    let carrier = parse_csv_opt_string_filter(iter.next()?);
    let asn = parse_csv_opt_asn(iter.next()?).ok()?;

    // support header format or cleartext format
    if let Some(value) = iter.next() {
        if !value.is_empty() {
            let credential = ProxyCredential::try_from_header_str(value)
                .or_else(|_| ProxyCredential::try_from_clear_str(value.to_owned()))
                .ok()?;
            address.credential = Some(credential);
        }
    }

    // Ensure there are no more values in the row
    if iter.next().is_some() {
        return None;
    }

    Some(Proxy {
        id,
        address,
        tcp,
        udp,
        http,
        https,
        socks5,
        socks5h,
        datacenter,
        residential,
        mobile,
        pool_id,
        continent,
        country,
        state,
        city,
        carrier,
        asn,
    })
}

fn parse_csv_bool(value: &str) -> Option<bool> {
    match_ignore_ascii_case_str! {
        match(value) {
            "true" | "1" => Some(true),
            "" | "false" | "0" | "null" | "nil" => Some(false),
            _ => None,
        }
    }
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
    InvalidRow(String),
}

impl std::fmt::Display for ProxyCsvRowReaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            ProxyCsvRowReaderErrorKind::IoError(err) => write!(f, "I/O error: {}", err),
            ProxyCsvRowReaderErrorKind::InvalidRow(row) => write!(f, "Invalid row: {}", row),
        }
    }
}

impl std::error::Error for ProxyCsvRowReaderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ProxyCsvRowReaderErrorKind::IoError(err) => Some(err),
            ProxyCsvRowReaderErrorKind::InvalidRow(_) => None,
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
    use std::str::FromStr;

    use itertools::Itertools;

    use crate::net::Protocol;

    use super::*;

    #[test]
    fn test_parse_csv_bool() {
        for (input, output) in &[
            ("1", Some(true)),
            ("true", Some(true)),
            ("True", Some(true)),
            ("TRUE", Some(true)),
            ("0", Some(false)),
            ("false", Some(false)),
            ("False", Some(false)),
            ("FALSE", Some(false)),
            ("null", Some(false)),
            ("nil", Some(false)),
            ("NULL", Some(false)),
            ("NIL", Some(false)),
            ("", Some(false)),
            ("invalid", None),
        ] {
            assert_eq!(parse_csv_bool(input), *output);
        }
    }

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
        assert!(venndb::Any::is_any(&filter));
    }

    #[test]
    fn test_parse_csv_row_happy_path() {
        for (input, output) in [
            // most minimal
            (
                "id,,,,,,,,,,authority,,,,,,,,",
                Proxy {
                    id: NonEmptyString::from_static("id"),
                    address: ProxyAddress::from_str("authority").unwrap(),
                    tcp: false,
                    udp: false,
                    http: false,
                    https: false,
                    socks5: false,
                    socks5h: false,
                    datacenter: false,
                    residential: false,
                    mobile: false,
                    pool_id: None,
                    continent: None,
                    country: None,
                    state: None,
                    city: None,
                    carrier: None,
                    asn: None,
                },
            ),
            // more happy row tests
            (
                "id,true,false,true,,false,,true,false,true,authority,pool_id,,country,,city,carrier,,Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
                Proxy {
                   id: NonEmptyString::from_static("id"),
                    address: ProxyAddress::from_str("username:password@authority").unwrap(),
                    tcp: true,
                    udp: false,
                    http: true,
                    https: false,
                    socks5: false,
                    socks5h: false,
                    datacenter: true,
                    residential: false,
                    mobile: true,
                    pool_id: Some("pool_id".into()),
                    continent: None,
                    country: Some("country".into()),
                    state: None,
                    city: Some("city".into()),
                    carrier: Some("carrier".into()),
                    asn: None,
                },
            ),
            (
                "123,1,0,False,,True,,null,false,true,host:1234,,americas,*,*,*,carrier,13335,",
                Proxy {
                   id: NonEmptyString::from_static("123"),
                    address: ProxyAddress::from_str("host:1234").unwrap(),
                    tcp: true,
                    udp: false,
                    http: false,
                    https: false,
                    socks5: true,
                    socks5h: false,
                    datacenter: false,
                    residential: false,
                    mobile: true,
                    pool_id: None,
                    continent: Some("americas".into()),
                    country: Some("*".into()),
                    state: Some("*".into()),
                    city: Some("*".into()),
                    carrier: Some("carrier".into()),
                    asn: Some(Asn::from_static(13335)),
                },
            ),
            (
                "123,1,0,False,,True,,null,false,true,host:1234,,europe,*,,*,carrier,0",
                Proxy {
                   id: NonEmptyString::from_static("123"),
                    address: ProxyAddress::from_str("host:1234").unwrap(),
                    tcp: true,
                    udp: false,
                    http: false,
                    https: false,
                    socks5: true,
                    socks5h: false,
                    datacenter: false,
                    residential: false,
                    mobile: true,
                    pool_id: None,
                    continent: Some("europe".into()),
                    country: Some("*".into()),
                    state: None,
                    city: Some("*".into()),
                    carrier: Some("carrier".into()),
                    asn: Some(Asn::unspecified()),
                },
            ),
            (
                "foo,1,0,1,,0,,1,0,0,bar,baz,,US,,,,",
                Proxy {
                   id: NonEmptyString::from_static("foo"),
                    address: ProxyAddress::from_str("bar").unwrap(),
                    tcp: true,
                    udp: false,
                    http: true,
                    https: false,
                    socks5: false,
                    socks5h: false,
                    datacenter: true,
                    residential: false,
                    mobile: false,
                    pool_id: Some("baz".into()),
                    continent: None,
                    country: Some("us".into()),
                    state: None,
                    city: None,
                    carrier: None,
                    asn: None,
                },
            ),
        ] {
            let proxy = parse_csv_row(input).unwrap();
            assert_eq!(proxy.id, output.id);
            assert_eq!(proxy.address, output.address);
            assert_eq!(proxy.tcp, output.tcp);
            assert_eq!(proxy.udp, output.udp);
            assert_eq!(proxy.http, output.http);
            assert_eq!(proxy.socks5, output.socks5);
            assert_eq!(proxy.datacenter, output.datacenter);
            assert_eq!(proxy.residential, output.residential);
            assert_eq!(proxy.mobile, output.mobile);
            assert_eq!(proxy.pool_id, output.pool_id);
            assert_eq!(proxy.continent, output.continent);
            assert_eq!(proxy.country, output.country);
            assert_eq!(proxy.state, output.state);
            assert_eq!(proxy.city, output.city);
            assert_eq!(proxy.carrier, output.carrier);
            assert_eq!(proxy.asn, output.asn);
        }
    }

    #[test]
    fn test_parse_csv_row_mistakes() {
        for input in [
            // garbage rows
            "",
            ",",
            ",,,,,,",
            ",,,,,,,,,,,,,,,,,,,,",
            ",,,,,,,,,,,,,,,,,,,,,,",
            ",,,,,,,,,,,,,,,,,,,,,,,",
            // too many rows
            "id,true,false,true,false,true,false,true,authority,pool_id,continent,country,state,city,carrier,15169,Basic dXNlcm5hbWU6cGFzc3dvcmQ=,",
            // missing authority
            "id,,,,,,,,,,,,,,,,",
            // missing proxy id
            ",,,,,,,,authority,,,,,,,,",
            // invalid bool values
            "id,foo,,,,,,,,,authority,,,,,,,,",
            "id,,foo,,,,,,,,authority,,,,,,,,",
            "id,,,foo,,,,,,,authority,,,,,,,,",
            "id,,,,,foo,,,,,authority,,,,,,,,",
            "id,,,,,,foo,,,,authority,,,,,,,,",
            "id,,,,,,,,foo,,authority,,,,,,,,",
            "id,,,,,,,foo,authority,,,,,,,,",
            // invalid credentials
            "id,,,,,,,,authority,,,,,:foo",
        ] {
            assert!(parse_csv_row(input).is_none(), "input: {}", input);
        }
    }

    #[tokio::test]
    async fn test_proxy_csv_row_reader_happy_one_row() {
        let mut reader = ProxyCsvRowReader::raw("id,true,false,true,,false,,true,false,true,authority,pool_id,continent,country,state,city,carrier,13335,Basic dXNlcm5hbWU6cGFzc3dvcmQ=");
        let proxy = reader.next().await.unwrap().unwrap();

        assert_eq!(proxy.id, "id");
        assert_eq!(
            proxy.address,
            ProxyAddress::from_str("username:password@authority").unwrap()
        );
        assert!(proxy.tcp);
        assert!(!proxy.udp);
        assert!(proxy.http);
        assert!(!proxy.socks5);
        assert!(proxy.datacenter);
        assert!(!proxy.residential);
        assert!(proxy.mobile);
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
        let mut reader = ProxyCsvRowReader::raw("id,true,false,false,true,true,false,true,false,true,authority,pool_id,continent,country,state,city,carrier,42,Basic dXNlcm5hbWU6cGFzc3dvcmQ=\nid2,1,0,0,0,0,0,1,0,0,authority2,pool_id2,continent2,country2,state2,city2,carrier2,1");

        let proxy = reader.next().await.unwrap().unwrap();
        assert_eq!(proxy.id, "id");
        assert_eq!(
            proxy.address,
            ProxyAddress::from_str("username:password@authority").unwrap()
        );
        assert!(proxy.tcp);
        assert!(!proxy.udp);
        assert!(!proxy.http);
        assert!(proxy.https);
        assert!(proxy.socks5);
        assert!(!proxy.socks5h);
        assert!(proxy.datacenter);
        assert!(!proxy.residential);
        assert!(proxy.mobile);
        assert_eq!(proxy.pool_id, Some("pool_id".into()));
        assert_eq!(proxy.continent, Some("continent".into()));
        assert_eq!(proxy.country, Some("country".into()));
        assert_eq!(proxy.state, Some("state".into()));
        assert_eq!(proxy.city, Some("city".into()));
        assert_eq!(proxy.carrier, Some("carrier".into()));
        assert_eq!(proxy.asn, Some(Asn::from_static(42)));

        let proxy = reader.next().await.unwrap().unwrap();

        assert_eq!(proxy.id, "id2");
        assert_eq!(proxy.address, ProxyAddress::from_str("authority2").unwrap());
        assert!(proxy.tcp);
        assert!(!proxy.udp);
        assert!(!proxy.http);
        assert!(!proxy.https);
        assert!(!proxy.socks5);
        assert!(!proxy.socks5h);
        assert!(proxy.datacenter);
        assert!(!proxy.residential);
        assert!(!proxy.mobile);
        assert_eq!(proxy.pool_id, Some("pool_id2".into()));
        assert_eq!(proxy.continent, Some("continent2".into()));
        assert_eq!(proxy.country, Some("country2".into()));
        assert_eq!(proxy.city, Some("city2".into()));
        assert_eq!(proxy.state, Some("state2".into()));
        assert_eq!(proxy.carrier, Some("carrier2".into()));
        assert_eq!(proxy.asn, Some(Asn::from_static(1)));

        // no more rows to read
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
        assert!(reader.next().await.is_err());
    }

    #[test]
    fn test_proxy_is_match_happy_path_explicit_h2() {
        let proxy = Proxy {
            id: NonEmptyString::from_static("id"),
            address: ProxyAddress::from_str("authority").unwrap(),
            tcp: true,
            udp: false,
            http: true,
            https: false,
            socks5: false,
            socks5h: false,
            datacenter: true,
            residential: false,
            mobile: true,
            pool_id: Some("pool_id".into()),
            continent: Some("continent".into()),
            country: Some("country".into()),
            state: Some("state".into()),
            city: Some("city".into()),
            carrier: Some("carrier".into()),
            asn: Some(Asn::from_static(1)),
        };

        let ctx = TransportContext {
            protocol: TransportProtocol::Tcp,
            app_protocol: Some(Protocol::HTTPS),
            http_version: None,
            authority: "localhost:8443".try_into().unwrap(),
        };

        let filter = ProxyFilter {
            id: Some(NonEmptyString::from_static("id")),
            continent: Some(vec![StringFilter::new("continent")]),
            country: Some(vec![StringFilter::new("country")]),
            state: Some(vec![StringFilter::new("state")]),
            city: Some(vec![StringFilter::new("city")]),
            pool_id: Some(vec![StringFilter::new("pool_id")]),
            carrier: Some(vec![StringFilter::new("carrier")]),
            asn: Some(vec![Asn::from_static(1)]),
            datacenter: Some(true),
            residential: Some(false),
            mobile: Some(true),
        };

        assert!(proxy.is_match(&ctx, &filter));
    }

    #[test]
    fn test_proxy_is_match_happy_path_explicit_h2_https() {
        let proxy = Proxy {
            id: NonEmptyString::from_static("id"),
            address: ProxyAddress::from_str("authority").unwrap(),
            tcp: true,
            udp: false,
            http: false,
            https: true,
            socks5: false,
            socks5h: false,
            datacenter: true,
            residential: false,
            mobile: true,
            pool_id: Some("pool_id".into()),
            continent: Some("continent".into()),
            country: Some("country".into()),
            state: Some("state".into()),
            city: Some("city".into()),
            carrier: Some("carrier".into()),
            asn: Some(Asn::from_static(1)),
        };

        let ctx = TransportContext {
            protocol: TransportProtocol::Tcp,
            app_protocol: Some(Protocol::HTTPS),
            http_version: None,
            authority: "localhost:8443".try_into().unwrap(),
        };

        let filter = ProxyFilter {
            id: Some(NonEmptyString::from_static("id")),
            continent: Some(vec![StringFilter::new("continent")]),
            country: Some(vec![StringFilter::new("country")]),
            state: Some(vec![StringFilter::new("state")]),
            city: Some(vec![StringFilter::new("city")]),
            pool_id: Some(vec![StringFilter::new("pool_id")]),
            carrier: Some(vec![StringFilter::new("carrier")]),
            asn: Some(vec![Asn::from_static(1)]),
            datacenter: Some(true),
            residential: Some(false),
            mobile: Some(true),
        };

        assert!(proxy.is_match(&ctx, &filter));
    }

    #[test]
    fn test_proxy_is_match_failure_tcp_explicit_h2() {
        let proxy = Proxy {
            id: NonEmptyString::from_static("id"),
            address: ProxyAddress::from_str("authority").unwrap(),
            tcp: false,
            udp: false,
            http: true,
            https: false,
            socks5: false,
            socks5h: false,
            datacenter: true,
            residential: false,
            mobile: true,
            pool_id: Some("pool_id".into()),
            continent: Some("continent".into()),
            country: Some("country".into()),
            state: Some("state".into()),
            city: Some("city".into()),
            carrier: Some("carrier".into()),
            asn: Some(Asn::from_static(1)),
        };

        let ctx = TransportContext {
            protocol: TransportProtocol::Tcp,
            app_protocol: Some(Protocol::HTTPS),
            http_version: None,
            authority: "localhost:8443".try_into().unwrap(),
        };

        let filter = ProxyFilter {
            datacenter: Some(true),
            residential: Some(false),
            mobile: Some(true),
            ..Default::default()
        };

        assert!(!proxy.is_match(&ctx, &filter));
    }

    #[test]
    fn test_proxy_is_match_happy_path_explicit_h3() {
        let proxy = Proxy {
            id: NonEmptyString::from_static("id"),
            address: ProxyAddress::from_str("authority").unwrap(),
            tcp: false,
            udp: true,
            http: false,
            https: false,
            socks5: true,
            socks5h: false,
            datacenter: true,
            residential: false,
            mobile: true,
            pool_id: Some("pool_id".into()),
            continent: None,
            country: Some("country".into()),
            state: None,
            city: Some("city".into()),
            carrier: Some("carrier".into()),
            asn: None,
        };

        let ctx = TransportContext {
            protocol: TransportProtocol::Udp,
            app_protocol: Some(Protocol::HTTPS),
            http_version: None,
            authority: "localhost:8443".try_into().unwrap(),
        };

        let filter = ProxyFilter {
            datacenter: Some(true),
            residential: Some(false),
            mobile: Some(true),
            ..Default::default()
        };

        assert!(proxy.is_match(&ctx, &filter));
    }

    #[test]
    fn test_proxy_is_match_happy_path_explicit_h3_socks5h() {
        let proxy = Proxy {
            id: NonEmptyString::from_static("id"),
            address: ProxyAddress::from_str("authority").unwrap(),
            tcp: false,
            udp: true,
            http: false,
            https: false,
            socks5: false,
            socks5h: true,
            datacenter: true,
            residential: false,
            mobile: true,
            pool_id: Some("pool_id".into()),
            continent: None,
            country: Some("country".into()),
            state: None,
            city: Some("city".into()),
            carrier: Some("carrier".into()),
            asn: None,
        };

        let ctx = TransportContext {
            protocol: TransportProtocol::Udp,
            app_protocol: Some(Protocol::HTTPS),
            http_version: None,
            authority: "localhost:8443".try_into().unwrap(),
        };

        let filter = ProxyFilter {
            datacenter: Some(true),
            residential: Some(false),
            mobile: Some(true),
            ..Default::default()
        };

        assert!(proxy.is_match(&ctx, &filter));
    }

    #[test]
    fn test_proxy_is_match_failure_udp_explicit_h3() {
        let proxy = Proxy {
            id: NonEmptyString::from_static("id"),
            address: ProxyAddress::from_str("authority").unwrap(),
            tcp: false,
            udp: false,
            http: false,
            https: false,
            socks5: true,
            socks5h: false,
            datacenter: true,
            residential: false,
            mobile: true,
            pool_id: Some("pool_id".into()),
            continent: None,
            country: Some("country".into()),
            state: None,
            city: Some("city".into()),
            carrier: Some("carrier".into()),
            asn: None,
        };

        let ctx = TransportContext {
            protocol: TransportProtocol::Udp,
            app_protocol: Some(Protocol::HTTPS),
            http_version: None,
            authority: "localhost:8443".try_into().unwrap(),
        };

        let filter = ProxyFilter {
            datacenter: Some(true),
            residential: Some(false),
            mobile: Some(true),
            ..Default::default()
        };

        assert!(!proxy.is_match(&ctx, &filter));
    }

    #[test]
    fn test_proxy_is_match_failure_socks5_explicit_h3() {
        let proxy = Proxy {
            id: NonEmptyString::from_static("id"),
            address: ProxyAddress::from_str("authority").unwrap(),
            tcp: false,
            udp: true,
            http: false,
            https: false,
            socks5: false,
            socks5h: false,
            datacenter: true,
            residential: false,
            mobile: true,
            pool_id: Some("pool_id".into()),
            continent: None,
            country: Some("country".into()),
            state: None,
            city: Some("city".into()),
            carrier: Some("carrier".into()),
            asn: None,
        };

        let ctx = TransportContext {
            protocol: TransportProtocol::Udp,
            app_protocol: Some(Protocol::HTTPS),
            http_version: None,
            authority: "localhost:8443".try_into().unwrap(),
        };

        let filter = ProxyFilter {
            datacenter: Some(true),
            residential: Some(false),
            mobile: Some(true),
            ..Default::default()
        };

        assert!(!proxy.is_match(&ctx, &filter));
    }

    #[test]
    fn test_proxy_is_match_happy_path_filter_cases() {
        for (proxy_csv, filter) in [
            ("id,1,,1,,,,,,,authority,,,,,,,,", ProxyFilter::default()),
            (
                "id,1,,1,,,,,,,authority,,,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,,authority,,,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    datacenter: Some(false),
                    residential: Some(false),
                    mobile: Some(false),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,1,,,authority,,,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    datacenter: Some(true),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,1,,,authority,,,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    datacenter: Some(true),
                    residential: Some(false),
                    mobile: Some(false),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,1,,authority,,,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    residential: Some(true),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,1,,authority,,,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    datacenter: Some(false),
                    residential: Some(true),
                    mobile: Some(false),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,1,authority,,,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    mobile: Some(true),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,1,authority,,,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    datacenter: Some(false),
                    residential: Some(false),
                    mobile: Some(true),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,,authority,FooBAR,,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    pool_id: Some(vec![StringFilter::new(" FooBar")]),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,,authority,,FooBAR,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    continent: Some(vec![StringFilter::new(" FooBar")]),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,,authority,,,FooBAR,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    country: Some(vec![StringFilter::new(" FooBar")]),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,,authority,,,,FooBAR,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    state: Some(vec![StringFilter::new(" FooBar")]),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,,authority,,,,,FooBAR,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    city: Some(vec![StringFilter::new(" FooBar")]),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,,authority,,,,,,FooBAR,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    carrier: Some(vec![StringFilter::new(" FooBar")]),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,,authority,,,,,,,42,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    asn: Some(vec![Asn::from_static(42)]),
                    ..Default::default()
                },
            ),
        ] {
            let proxy = match parse_csv_row(proxy_csv) {
                Some(proxy) => proxy,
                None => panic!("failed to parse proxy row: `{proxy_csv}`"),
            };
            let ctx = TransportContext {
                protocol: TransportProtocol::Tcp,
                app_protocol: Some(Protocol::HTTPS),
                http_version: None,
                authority: "localhost:8443".try_into().unwrap(),
            };

            assert!(proxy.is_match(&ctx, &filter), "filter: {:?}", filter);
        }
    }

    #[test]
    fn test_proxy_is_match_failure_filter_cases() {
        for (proxy_csv, filter) in [
            (
                "id,1,,1,,,,,,,authority,,,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    datacenter: Some(true),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,,authority,,,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    residential: Some(true),
                    mobile: Some(true),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,1,,,authority,,,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    datacenter: Some(false),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,1,,authority,,,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    residential: Some(false),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,1,authority,,,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    mobile: Some(false),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,1,authority,,,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    datacenter: Some(false),
                    residential: Some(true),
                    mobile: Some(true),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,,authority,FooBAR,,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    pool_id: Some(vec![StringFilter::new("baz")]),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,,authority,,FooBAR,,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    continent: Some(vec![StringFilter::new("baz")]),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,,authority,,,FooBAR,,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    country: Some(vec![StringFilter::new("baz")]),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,,authority,,,,FooBAR,,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    state: Some(vec![StringFilter::new("baz")]),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,,authority,,,,,FooBAR,,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    city: Some(vec![StringFilter::new("baz")]),
                    ..Default::default()
                },
            ),
            (
                "id,1,,1,,,,,,,authority,,,,,,FooBAR,,",
                ProxyFilter {
                    id: Some(NonEmptyString::from_static("id")),
                    carrier: Some(vec![StringFilter::new("baz")]),
                    ..Default::default()
                },
            ),
        ] {
            let proxy = parse_csv_row(proxy_csv).unwrap();
            let ctx = TransportContext {
                protocol: TransportProtocol::Tcp,
                app_protocol: Some(Protocol::HTTPS),
                http_version: None,
                authority: "localhost:8443".try_into().unwrap(),
            };

            assert!(
                !proxy.is_match(&ctx, &filter),
                "filter: {:?}; proxy: {:?}",
                filter,
                proxy
            );
        }
    }

    #[test]
    fn test_proxy_is_match_happy_path_proxy_with_any_filter_string_cases() {
        let proxy = parse_csv_row("id,1,,1,,,,,,,authority,*,*,*,*,*,*,0").unwrap();
        let ctx = TransportContext {
            protocol: TransportProtocol::Tcp,
            app_protocol: Some(Protocol::HTTPS),
            http_version: None,
            authority: "localhost:8443".try_into().unwrap(),
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
            assert!(proxy.is_match(&ctx, &filter), "filter: {:?}", filter);
        }
    }

    #[test]
    fn test_proxy_is_match_happy_path_proxy_with_any_filters_cases() {
        let proxy =
            parse_csv_row("id,1,,1,,,,,,,authority,pool,continent,country,state,city,carrier,42")
                .unwrap();
        let ctx = TransportContext {
            protocol: TransportProtocol::Tcp,
            app_protocol: Some(Protocol::HTTPS),
            http_version: None,
            authority: "localhost:8443".try_into().unwrap(),
        };

        for filter in [
            ProxyFilter::default(),
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
                pool_id: Some(vec![StringFilter::new("pool")]),
                continent: Some(vec![StringFilter::new("continent")]),
                country: Some(vec![StringFilter::new("country")]),
                state: Some(vec![StringFilter::new("state")]),
                city: Some(vec![StringFilter::new("city")]),
                carrier: Some(vec![StringFilter::new("carrier")]),
                asn: Some(vec![Asn::from_static(42)]),
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
            assert!(proxy.is_match(&ctx, &filter), "filter: {:?}", filter);
        }
    }

    #[test]
    fn test_proxy_db_happy_path_basic() {
        let mut db = ProxyDB::new();
        let proxy = parse_csv_row("id,1,,1,,,,1,,,authority,,,,,,,,").unwrap();
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
            "1,1,,1,,,,1,,,authority,,,US,,,,,\n2,1,,1,,,,1,,,authority,,,*,,,,,",
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
            "1,1,,1,,,,1,,,authority,,,US,,New York,,,\n2,1,,1,,,,1,,,authority,,,*,,*,,,",
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
            "1,1,,1,,,,1,,,authority,,europe,BE,,Brussels,,1348,\n2,1,,1,,,,1,,,authority,,asia,CN,,Shenzen,,1348,\n3,1,,1,,,,1,,,authority,,asia,CN,,Peking,,42,",
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
            "1,1,,1,,,,1,,,authority,,,US,Texas,,,,\n2,1,,1,,,,1,,,authority,,,US,New York,,,,\n3,1,,1,,,,1,,,authority,,,US,California,,,,",
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
        let mut reader = ProxyCsvRowReader::raw("id1,1,,,,,,,,,authority,,,,,,,\nid2,,1,,,,,,,,authority,,,,,,,\nid3,,1,1,,,,,,,authority,,,,,,,\nid4,,1,1,,,,,1,,authority,,,,,,,\nid5,,1,1,,,,,1,,authority,,,,,,,");
        while let Some(proxy) = reader.next().await.unwrap() {
            assert_eq!(
                ProxyDBErrorKind::InvalidRow,
                db.append(proxy).unwrap_err().kind
            );
        }
    }
}
