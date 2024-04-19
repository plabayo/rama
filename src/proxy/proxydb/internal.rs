use super::{ProxyCredentials, ProxyFilter, StringFilter};
use crate::http::{RequestContext, Version};
use std::path::Path;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader, Lines},
};
use venndb::VennDB;

#[derive(Debug, Clone, VennDB)]
#[venndb(validator = proxy_is_valid)]
/// The selected proxy to use to connect to the proxy.
pub struct Proxy {
    #[venndb(key)]
    /// Unique identifier of the proxy.
    pub id: String,

    /// True if the proxy supports TCP connections.
    pub tcp: bool,

    /// True if the proxy supports UDP connections.
    pub udp: bool,

    /// http-proxy enabled
    pub http: bool,

    /// socks5-proxy enabled
    pub socks5: bool,

    /// Proxy is located in a datacenter.
    pub datacenter: bool,

    /// Proxy's IP is labeled as residential.
    pub residential: bool,

    /// Proxy's IP originates from a mobile network.
    pub mobile: bool,

    /// The authority of the proxy to use to connect to the proxy (`host[:port]`)
    pub authority: String,

    #[venndb(filter, any)]
    /// Pool ID of the proxy.
    pub pool_id: Option<StringFilter>,

    #[venndb(filter, any)]
    /// Country of the proxy.
    pub country: Option<StringFilter>,

    #[venndb(filter, any)]
    /// City of the proxy.
    pub city: Option<StringFilter>,

    #[venndb(filter, any)]
    /// Mobile carrier of the proxy.
    pub carrier: Option<StringFilter>,

    /// The optional credentials to use to authenticate with the proxy.
    ///
    /// See [`ProxyCredentials`] for more information.
    pub credentials: Option<ProxyCredentials>,
}

/// Validate the proxy is valid according to rules that are not enforced by the type system.
pub fn proxy_is_valid(proxy: &Proxy) -> bool {
    !proxy.id.is_empty()
        && !proxy.authority.is_empty()
        && (proxy.datacenter || proxy.residential || proxy.mobile)
        && ((proxy.http && proxy.tcp) || (proxy.socks5 && (proxy.tcp || proxy.udp)))
}

impl Proxy {
    /// Check if the proxy is a match for the given[`RequestContext`] and [`ProxyFilter`].
    pub fn is_match(&self, ctx: &RequestContext, filter: &ProxyFilter) -> bool {
        if let Some(id) = &filter.id {
            if id != &self.id {
                return false;
            }
        }

        if (ctx.http_version == Version::HTTP_3 && (!self.socks5 || !self.udp))
            || (ctx.http_version != Version::HTTP_3 && (!self.tcp || !(self.http || self.socks5)))
        {
            return false;
        }

        return filter
            .country
            .as_ref()
            .map(|c| Some(c) == self.country.as_ref())
            .unwrap_or(true)
            && filter
                .city
                .as_ref()
                .map(|c| Some(c) == self.city.as_ref())
                .unwrap_or(true)
            && filter
                .pool_id
                .as_ref()
                .map(|p| Some(p) == self.pool_id.as_ref())
                .unwrap_or(true)
            && filter
                .carrier
                .as_ref()
                .map(|c| Some(c) == self.carrier.as_ref())
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

fn parse_csv_row(row: &str) -> Option<Proxy> {
    let mut iter = row.split(',');

    let id = iter.next().and_then(|s| {
        if s.is_empty() {
            None
        } else {
            Some(s.to_owned())
        }
    })?;
    let tcp = iter.next().and_then(parse_csv_bool)?;
    let udp = iter.next().and_then(parse_csv_bool)?;
    let http = iter.next().and_then(parse_csv_bool)?;
    let socks5 = iter.next().and_then(parse_csv_bool)?;
    let datacenter = iter.next().and_then(parse_csv_bool)?;
    let residential = iter.next().and_then(parse_csv_bool)?;
    let mobile = iter.next().and_then(parse_csv_bool)?;
    let authority = iter.next().and_then(|s| {
        if s.is_empty() {
            None
        } else {
            Some(s.to_owned())
        }
    })?;
    let pool_id = parse_csv_opt_string_filter(iter.next()?);
    let country = parse_csv_opt_string_filter(iter.next()?);
    let city = parse_csv_opt_string_filter(iter.next()?);
    let carrier = parse_csv_opt_string_filter(iter.next()?);

    let credentials = match iter.next() {
        Some(value) => {
            if value.is_empty() {
                None
            } else {
                Some(value.parse().ok()?)
            }
        }
        _ => None,
    };

    // Ensure there are no more values in the row
    if iter.next().is_some() {
        return None;
    }

    Some(Proxy {
        id,
        tcp,
        udp,
        http,
        socks5,
        datacenter,
        residential,
        mobile,
        authority,
        pool_id,
        country,
        city,
        carrier,
        credentials,
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
    use itertools::Itertools;

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
                "id,,,,,,,,authority,,,,,",
                Proxy {
                    id: "id".into(),
                    tcp: false,
                    udp: false,
                    http: false,
                    socks5: false,
                    datacenter: false,
                    residential: false,
                    mobile: false,
                    authority: "authority".into(),
                    pool_id: None,
                    country: None,
                    city: None,
                    carrier: None,
                    credentials: None,
                },
            ),
            // more happy row tests
            (
                "id,true,false,true,false,true,false,true,authority,pool_id,country,city,carrier,Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
                Proxy {
                    id: "id".into(),
                    tcp: true,
                    udp: false,
                    http: true,
                    socks5: false,
                    datacenter: true,
                    residential: false,
                    mobile: true,
                    authority: "authority".into(),
                    pool_id: Some("pool_id".into()),
                    country: Some("country".into()),
                    city: Some("city".into()),
                    carrier: Some("carrier".into()),
                    credentials: Some(ProxyCredentials::Basic {
                        username: "username".into(),
                        password: Some("password".into()),
                    }),
                },
            ),
            (
                "123,1,0,False,True,null,false,true,host:1234,,*,*,carrier,",
                Proxy {
                    id: "123".into(),
                    tcp: true,
                    udp: false,
                    http: false,
                    socks5: true,
                    datacenter: false,
                    residential: false,
                    mobile: true,
                    authority: "host:1234".into(),
                    pool_id: None,
                    country: Some("*".into()),
                    city: Some("*".into()),
                    carrier: Some("carrier".into()),
                    credentials: None,
                },
            ),
            (
                "123,1,0,False,True,null,false,true,host:1234,,*,*,carrier",
                Proxy {
                    id: "123".into(),
                    tcp: true,
                    udp: false,
                    http: false,
                    socks5: true,
                    datacenter: false,
                    residential: false,
                    mobile: true,
                    authority: "host:1234".into(),
                    pool_id: None,
                    country: Some("*".into()),
                    city: Some("*".into()),
                    carrier: Some("carrier".into()),
                    credentials: None,
                },
            ),
            (
                "foo,1,0,1,0,1,0,0,bar,baz,US,,",
                Proxy {
                    id: "foo".into(),
                    tcp: true,
                    udp: false,
                    http: true,
                    socks5: false,
                    datacenter: true,
                    residential: false,
                    mobile: false,
                    authority: "bar".into(),
                    pool_id: Some("baz".into()),
                    country: Some("us".into()),
                    city: None,
                    carrier: None,
                    credentials: None,
                },
            ),
        ] {
            let proxy = parse_csv_row(input).unwrap();
            assert_eq!(proxy.id, output.id);
            assert_eq!(proxy.tcp, output.tcp);
            assert_eq!(proxy.udp, output.udp);
            assert_eq!(proxy.http, output.http);
            assert_eq!(proxy.socks5, output.socks5);
            assert_eq!(proxy.datacenter, output.datacenter);
            assert_eq!(proxy.residential, output.residential);
            assert_eq!(proxy.mobile, output.mobile);
            assert_eq!(proxy.authority, output.authority);
            assert_eq!(proxy.pool_id, output.pool_id);
            assert_eq!(proxy.country, output.country);
            assert_eq!(proxy.city, output.city);
            assert_eq!(proxy.carrier, output.carrier);
            assert_eq!(proxy.credentials, output.credentials);
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
            // too many rows
            "id,true,false,true,false,true,false,true,authority,pool_id,country,city,carrier,Basic dXNlcm5hbWU6cGFzc3dvcmQ=,",
            // missing authority
            "id,,,,,,,,,,,,,",
            // missing proxy id
            ",,,,,,,,authority,,,,,",
            // invalid bool values
            "id,foo,,,,,,,authority,,,,,",
            "id,,foo,,,,,,authority,,,,,",
            "id,,,foo,,,,,authority,,,,,",
            "id,,,,,foo,,,authority,,,,,",
            "id,,,,,,foo,,authority,,,,,",
            "id,,,,,,,foo,authority,,,,,",
            // invalid credentials
            "id,,,,,,,,authority,,,,,foo",
            "id,,,,,,,,authority,,,,,Basic kaboo",
        ] {
            assert!(parse_csv_row(input).is_none());
        }
    }

    #[tokio::test]
    async fn test_proxy_csv_row_reader_happy_one_row() {
        let mut reader = ProxyCsvRowReader::raw("id,true,false,true,false,true,false,true,authority,pool_id,country,city,carrier,Basic dXNlcm5hbWU6cGFzc3dvcmQ=");
        let proxy = reader.next().await.unwrap().unwrap();

        assert_eq!(proxy.id, "id");
        assert!(proxy.tcp);
        assert!(!proxy.udp);
        assert!(proxy.http);
        assert!(!proxy.socks5);
        assert!(proxy.datacenter);
        assert!(!proxy.residential);
        assert!(proxy.mobile);
        assert_eq!(proxy.authority, "authority");
        assert_eq!(proxy.pool_id, Some("pool_id".into()));
        assert_eq!(proxy.country, Some("country".into()));
        assert_eq!(proxy.city, Some("city".into()));
        assert_eq!(proxy.carrier, Some("carrier".into()));
        assert_eq!(
            proxy.credentials,
            Some(ProxyCredentials::Basic {
                username: "username".into(),
                password: Some("password".into()),
            })
        );

        // no more rows to read
        assert!(reader.next().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_proxy_csv_row_reader_happy_multi_row() {
        let mut reader = ProxyCsvRowReader::raw("id,true,false,true,false,true,false,true,authority,pool_id,country,city,carrier,Basic dXNlcm5hbWU6cGFzc3dvcmQ=\nid2,1,0,0,0,1,0,0,authority2,pool_id2,country2,city2,carrier2");

        let proxy = reader.next().await.unwrap().unwrap();
        assert_eq!(proxy.id, "id");
        assert!(proxy.tcp);
        assert!(!proxy.udp);
        assert!(proxy.http);
        assert!(!proxy.socks5);
        assert!(proxy.datacenter);
        assert!(!proxy.residential);
        assert!(proxy.mobile);
        assert_eq!(proxy.authority, "authority");
        assert_eq!(proxy.pool_id, Some("pool_id".into()));
        assert_eq!(proxy.country, Some("country".into()));
        assert_eq!(proxy.city, Some("city".into()));
        assert_eq!(proxy.carrier, Some("carrier".into()));
        assert_eq!(
            proxy.credentials,
            Some(ProxyCredentials::Basic {
                username: "username".into(),
                password: Some("password".into()),
            })
        );

        let proxy = reader.next().await.unwrap().unwrap();

        assert_eq!(proxy.id, "id2");
        assert!(proxy.tcp);
        assert!(!proxy.udp);
        assert!(!proxy.http);
        assert!(!proxy.socks5);
        assert!(proxy.datacenter);
        assert!(!proxy.residential);
        assert!(!proxy.mobile);
        assert_eq!(proxy.authority, "authority2");
        assert_eq!(proxy.pool_id, Some("pool_id2".into()));
        assert_eq!(proxy.country, Some("country2".into()));
        assert_eq!(proxy.city, Some("city2".into()));
        assert_eq!(proxy.carrier, Some("carrier2".into()));
        assert!(proxy.credentials.is_none());

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
            id: "id".into(),
            tcp: true,
            udp: false,
            http: true,
            socks5: false,
            datacenter: true,
            residential: false,
            mobile: true,
            authority: "authority".into(),
            pool_id: Some("pool_id".into()),
            country: Some("country".into()),
            city: Some("city".into()),
            carrier: Some("carrier".into()),
            credentials: None,
        };

        let ctx = RequestContext {
            http_version: Version::HTTP_2,
            scheme: crate::uri::Scheme::Https,
            host: Some("localhost".to_owned()),
            port: None,
        };

        let filter = ProxyFilter {
            id: Some("id".into()),
            country: Some("country".into()),
            city: Some("city".into()),
            pool_id: Some("pool_id".into()),
            carrier: Some("carrier".into()),
            datacenter: Some(true),
            residential: Some(false),
            mobile: Some(true),
        };

        assert!(proxy.is_match(&ctx, &filter));
    }

    #[test]
    fn test_proxy_is_match_failure_tcp_explicit_h2() {
        let proxy = Proxy {
            id: "id".into(),
            tcp: false,
            udp: false,
            http: true,
            socks5: false,
            datacenter: true,
            residential: false,
            mobile: true,
            authority: "authority".into(),
            pool_id: Some("pool_id".into()),
            country: Some("country".into()),
            city: Some("city".into()),
            carrier: Some("carrier".into()),
            credentials: None,
        };

        let ctx = RequestContext {
            http_version: Version::HTTP_2,
            scheme: crate::uri::Scheme::Https,
            host: Some("localhost".to_owned()),
            port: None,
        };

        let filter = ProxyFilter {
            id: Some("id".into()),
            country: Some("country".into()),
            city: Some("city".into()),
            pool_id: Some("pool_id".into()),
            carrier: Some("carrier".into()),
            datacenter: Some(true),
            residential: Some(false),
            mobile: Some(true),
        };

        assert!(!proxy.is_match(&ctx, &filter));
    }

    #[test]
    fn test_proxy_is_match_happy_path_explicit_h3() {
        let proxy = Proxy {
            id: "id".into(),
            tcp: false,
            udp: true,
            http: false,
            socks5: true,
            datacenter: true,
            residential: false,
            mobile: true,
            authority: "authority".into(),
            pool_id: Some("pool_id".into()),
            country: Some("country".into()),
            city: Some("city".into()),
            carrier: Some("carrier".into()),
            credentials: None,
        };

        let ctx = RequestContext {
            http_version: Version::HTTP_3,
            scheme: crate::uri::Scheme::Https,
            host: Some("localhost".to_owned()),
            port: None,
        };

        let filter = ProxyFilter {
            id: Some("id".into()),
            country: Some("country".into()),
            city: Some("city".into()),
            pool_id: Some("pool_id".into()),
            carrier: Some("carrier".into()),
            datacenter: Some(true),
            residential: Some(false),
            mobile: Some(true),
        };

        assert!(proxy.is_match(&ctx, &filter));
    }

    #[test]
    fn test_proxy_is_match_failure_udp_explicit_h3() {
        let proxy = Proxy {
            id: "id".into(),
            tcp: false,
            udp: false,
            http: false,
            socks5: true,
            datacenter: true,
            residential: false,
            mobile: true,
            authority: "authority".into(),
            pool_id: Some("pool_id".into()),
            country: Some("country".into()),
            city: Some("city".into()),
            carrier: Some("carrier".into()),
            credentials: None,
        };

        let ctx = RequestContext {
            http_version: Version::HTTP_3,
            scheme: crate::uri::Scheme::Https,
            host: Some("localhost".to_owned()),
            port: None,
        };

        let filter = ProxyFilter {
            id: Some("id".into()),
            country: Some("country".into()),
            city: Some("city".into()),
            pool_id: Some("pool_id".into()),
            carrier: Some("carrier".into()),
            datacenter: Some(true),
            residential: Some(false),
            mobile: Some(true),
        };

        assert!(!proxy.is_match(&ctx, &filter));
    }

    #[test]
    fn test_proxy_is_match_failure_socks5_explicit_h3() {
        let proxy = Proxy {
            id: "id".into(),
            tcp: false,
            udp: true,
            http: false,
            socks5: false,
            datacenter: true,
            residential: false,
            mobile: true,
            authority: "authority".into(),
            pool_id: Some("pool_id".into()),
            country: Some("country".into()),
            city: Some("city".into()),
            carrier: Some("carrier".into()),
            credentials: None,
        };

        let ctx = RequestContext {
            http_version: Version::HTTP_3,
            scheme: crate::uri::Scheme::Https,
            host: Some("localhost".to_owned()),
            port: None,
        };

        let filter = ProxyFilter {
            id: Some("id".into()),
            country: Some("country".into()),
            city: Some("city".into()),
            pool_id: Some("pool_id".into()),
            carrier: Some("carrier".into()),
            datacenter: Some(true),
            residential: Some(false),
            mobile: Some(true),
        };

        assert!(!proxy.is_match(&ctx, &filter));
    }

    #[test]
    fn test_proxy_is_match_happy_path_filter_cases() {
        for (proxy_csv, filter) in [
            ("id,1,,1,,,,,authority,,,,,", ProxyFilter::default()),
            (
                "id,1,,1,,,,,authority,,,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: None,
                    residential: None,
                    mobile: None,
                    pool_id: None,
                    country: None,
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,,,,authority,,,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: Some(false),
                    residential: Some(false),
                    mobile: Some(false),
                    pool_id: None,
                    country: None,
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,1,,,authority,,,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: Some(true),
                    residential: None,
                    mobile: None,
                    pool_id: None,
                    country: None,
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,1,,,authority,,,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: Some(true),
                    residential: Some(false),
                    mobile: Some(false),
                    pool_id: None,
                    country: None,
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,,1,,authority,,,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: None,
                    residential: Some(true),
                    mobile: None,
                    pool_id: None,
                    country: None,
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,,1,,authority,,,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: Some(false),
                    residential: Some(true),
                    mobile: Some(false),
                    pool_id: None,
                    country: None,
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,,,1,authority,,,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: None,
                    residential: None,
                    mobile: Some(true),
                    pool_id: None,
                    country: None,
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,,,1,authority,,,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: Some(false),
                    residential: Some(false),
                    mobile: Some(true),
                    pool_id: None,
                    country: None,
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,,,,authority,FooBAR,,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: None,
                    residential: None,
                    mobile: None,
                    pool_id: Some(" FooBar".into()),
                    country: None,
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,,,,authority,,FooBAR,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: None,
                    residential: None,
                    mobile: None,
                    pool_id: None,
                    country: Some(" FooBar".into()),
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,,,,authority,,,FooBAR,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: None,
                    residential: None,
                    mobile: None,
                    pool_id: None,
                    country: None,
                    city: Some(" FooBar".into()),
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,,,,authority,,,,FooBAR,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: None,
                    residential: None,
                    mobile: None,
                    pool_id: None,
                    country: None,
                    city: None,
                    carrier: Some(" FooBar".into()),
                },
            ),
        ] {
            let proxy = parse_csv_row(proxy_csv).unwrap();
            let ctx = RequestContext {
                http_version: Version::HTTP_2,
                scheme: crate::uri::Scheme::Https,
                host: Some("localhost".to_owned()),
                port: None,
            };

            assert!(proxy.is_match(&ctx, &filter), "filter: {:?}", filter);
        }
    }

    #[test]
    fn test_proxy_is_match_failure_filter_cases() {
        for (proxy_csv, filter) in [
            (
                "id,1,,1,,,,,authority,,,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: Some(true),
                    residential: None,
                    mobile: None,
                    pool_id: None,
                    country: None,
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,,,,authority,,,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: None,
                    residential: Some(true),
                    mobile: Some(true),
                    pool_id: None,
                    country: None,
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,1,,,authority,,,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: Some(false),
                    residential: None,
                    mobile: None,
                    pool_id: None,
                    country: None,
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,,1,,authority,,,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: None,
                    residential: Some(false),
                    mobile: None,
                    pool_id: None,
                    country: None,
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,,,1,authority,,,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: None,
                    residential: None,
                    mobile: Some(false),
                    pool_id: None,
                    country: None,
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,,,1,authority,,,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: Some(false),
                    residential: Some(true),
                    mobile: Some(true),
                    pool_id: None,
                    country: None,
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,,,,authority,FooBAR,,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: None,
                    residential: None,
                    mobile: None,
                    pool_id: Some("baz".into()),
                    country: None,
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,,,,authority,,FooBAR,,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: None,
                    residential: None,
                    mobile: None,
                    pool_id: None,
                    country: Some("baz".into()),
                    city: None,
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,,,,authority,,,FooBAR,,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: None,
                    residential: None,
                    mobile: None,
                    pool_id: None,
                    country: None,
                    city: Some("baz".into()),
                    carrier: None,
                },
            ),
            (
                "id,1,,1,,,,,authority,,,,FooBAR,",
                ProxyFilter {
                    id: Some("id".into()),
                    datacenter: None,
                    residential: None,
                    mobile: None,
                    pool_id: None,
                    country: None,
                    city: None,
                    carrier: Some("baz".into()),
                },
            ),
        ] {
            let proxy = parse_csv_row(proxy_csv).unwrap();
            let ctx = RequestContext {
                http_version: Version::HTTP_2,
                scheme: crate::uri::Scheme::Https,
                host: Some("localhost".to_owned()),
                port: None,
            };

            assert!(!proxy.is_match(&ctx, &filter), "filter: {:?}", filter);
        }
    }

    #[test]
    fn test_proxy_is_match_happy_path_proxy_with_any_filter_string_cases() {
        let proxy = parse_csv_row("id,1,,1,,,,,authority,*,*,*,*").unwrap();
        let ctx = RequestContext {
            http_version: Version::HTTP_2,
            scheme: crate::uri::Scheme::Https,
            host: Some("localhost".to_owned()),
            port: None,
        };

        for filter in [
            ProxyFilter {
                id: None,
                datacenter: None,
                residential: None,
                mobile: None,
                pool_id: None,
                country: None,
                city: None,
                carrier: None,
            },
            ProxyFilter {
                id: None,
                datacenter: None,
                residential: None,
                mobile: None,
                pool_id: Some("pool_a".into()),
                country: Some("country_a".into()),
                city: Some("city_a".into()),
                carrier: Some("carrier_a".into()),
            },
            ProxyFilter {
                id: None,
                datacenter: None,
                residential: None,
                mobile: None,
                pool_id: Some("pool_a".into()),
                country: None,
                city: None,
                carrier: None,
            },
            ProxyFilter {
                id: None,
                datacenter: None,
                residential: None,
                mobile: None,
                pool_id: None,
                country: Some("country_a".into()),
                city: None,
                carrier: None,
            },
            ProxyFilter {
                id: None,
                datacenter: None,
                residential: None,
                mobile: None,
                pool_id: None,
                country: None,
                city: Some("city_a".into()),
                carrier: Some("carrier_a".into()),
            },
            ProxyFilter {
                id: None,
                datacenter: None,
                residential: None,
                mobile: None,
                pool_id: None,
                country: None,
                city: None,
                carrier: Some("carrier_a".into()),
            },
        ] {
            assert!(proxy.is_match(&ctx, &filter), "filter: {:?}", filter);
        }
    }

    #[test]
    fn test_proxy_is_match_happy_path_proxy_with_any_filters_cases() {
        let proxy = parse_csv_row("id,1,,1,,,,,authority,pool,country,city,carrier").unwrap();
        let ctx = RequestContext {
            http_version: Version::HTTP_2,
            scheme: crate::uri::Scheme::Https,
            host: Some("localhost".to_owned()),
            port: None,
        };

        for filter in [
            ProxyFilter {
                id: None,
                datacenter: None,
                residential: None,
                mobile: None,
                pool_id: None,
                country: None,
                city: None,
                carrier: None,
            },
            ProxyFilter {
                id: None,
                datacenter: None,
                residential: None,
                mobile: None,
                pool_id: Some("*".into()),
                country: None,
                city: None,
                carrier: None,
            },
            ProxyFilter {
                id: None,
                datacenter: None,
                residential: None,
                mobile: None,
                pool_id: None,
                country: Some("*".into()),
                city: None,
                carrier: None,
            },
            ProxyFilter {
                id: None,
                datacenter: None,
                residential: None,
                mobile: None,
                pool_id: None,
                country: None,
                city: Some("*".into()),
                carrier: None,
            },
            ProxyFilter {
                id: None,
                datacenter: None,
                residential: None,
                mobile: None,
                pool_id: None,
                country: None,
                city: None,
                carrier: Some("*".into()),
            },
            ProxyFilter {
                id: None,
                datacenter: None,
                residential: None,
                mobile: None,
                pool_id: Some("pool".into()),
                country: Some("country".into()),
                city: Some("city".into()),
                carrier: Some("carrier".into()),
            },
            ProxyFilter {
                id: None,
                datacenter: None,
                residential: None,
                mobile: None,
                pool_id: Some("*".into()),
                country: Some("country".into()),
                city: Some("city".into()),
                carrier: Some("carrier".into()),
            },
            ProxyFilter {
                id: None,
                datacenter: None,
                residential: None,
                mobile: None,
                pool_id: Some("pool".into()),
                country: Some("*".into()),
                city: Some("city".into()),
                carrier: Some("carrier".into()),
            },
            ProxyFilter {
                id: None,
                datacenter: None,
                residential: None,
                mobile: None,
                pool_id: Some("pool".into()),
                country: Some("country".into()),
                city: Some("*".into()),
                carrier: Some("carrier".into()),
            },
            ProxyFilter {
                id: None,
                datacenter: None,
                residential: None,
                mobile: None,
                pool_id: Some("pool".into()),
                country: Some("country".into()),
                city: Some("city".into()),
                carrier: Some("*".into()),
            },
            ProxyFilter {
                id: None,
                datacenter: None,
                residential: None,
                mobile: None,
                pool_id: Some("*".into()),
                country: Some("*".into()),
                city: Some("*".into()),
                carrier: Some("*".into()),
            },
        ] {
            assert!(proxy.is_match(&ctx, &filter), "filter: {:?}", filter);
        }
    }

    #[test]
    fn test_proxy_db_happy_path_basic() {
        let mut db = ProxyDB::new();
        let proxy = parse_csv_row("id,1,,1,,1,,,authority,,,,,").unwrap();
        db.append(proxy).unwrap();

        let mut query = db.query();
        query.tcp(true).http(true);

        let proxy = query.execute().unwrap().any();
        assert_eq!(proxy.id, "id");
    }

    #[tokio::test]
    async fn test_proxy_db_happy_path_any_country() {
        let mut db = ProxyDB::new();
        let mut reader =
            ProxyCsvRowReader::raw("1,1,,1,,1,,,authority,,US,,,\n2,1,,1,,1,,,authority,,*,,,");
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
            "1,1,,1,,1,,,authority,,US,New York,,\n2,1,,1,,1,,,authority,,*,*,,",
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
    async fn test_proxy_db_invalid_row_cases() {
        let mut db = ProxyDB::new();
        let mut reader = ProxyCsvRowReader::raw("id1,1,,,,,,,authority,,,,\nid2,,1,,,,,,authority,,,,\nid3,,1,1,,,,,authority,,,,\nid4,,1,1,,,1,,authority,,,,\nid5,,1,1,,,1,,authority,,,,");
        while let Some(proxy) = reader.next().await.unwrap() {
            assert_eq!(
                ProxyDBErrorKind::InvalidRow,
                db.append(proxy).unwrap_err().kind
            );
        }
    }
}
