use super::{Proxy, StringFilter};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as ENGINE;
use rama_net::{
    address::ProxyAddress,
    asn::{Asn, InvalidAsn},
    user::ProxyCredential,
};
use std::path::Path;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader, Lines},
};

#[derive(Debug)]
/// A CSV Reader that can be used to create a [`Proxy`] database from a CSV file or raw data.
pub struct ProxyCsvRowReader {
    data: ProxyCsvRowReaderData,
}

impl ProxyCsvRowReader {
    /// Create a new [`ProxyCsvRowReader`] from the given CSV file.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, ProxyCsvRowReaderError> {
        let file = tokio::fs::File::open(path).await?;
        let reader = BufReader::new(file);
        let lines = reader.lines();
        Ok(Self {
            data: ProxyCsvRowReaderData::File(lines),
        })
    }

    /// Create a new [`ProxyCsvRowReader`] from the given CSV data.
    pub fn raw(data: impl AsRef<str>) -> Self {
        let lines: Vec<_> = data.as_ref().lines().rev().map(str::to_owned).collect();
        Self {
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

pub(crate) fn parse_csv_row(row: &str) -> Option<Proxy> {
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
    if let Some(value) = iter.next()
        && !value.is_empty()
    {
        address.credential = Some(match value.split_once(' ') {
            Some((t, v)) => {
                if t.eq_ignore_ascii_case("basic") {
                    let bytes = ENGINE.decode(v).ok()?;
                    let decoded = String::from_utf8(bytes).ok()?;
                    ProxyCredential::Basic(decoded.parse().ok()?)
                } else if t.eq_ignore_ascii_case("bearer") {
                    ProxyCredential::Bearer(v.parse().ok()?)
                } else {
                    ProxyCredential::Basic(value.parse().ok()?)
                }
            }
            None => ProxyCredential::Basic(value.parse().ok()?),
        });
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
    rama_utils::macros::match_ignore_ascii_case_str! {
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
            ProxyCsvRowReaderErrorKind::IoError(err) => write!(f, "I/O error: {err}"),
            ProxyCsvRowReaderErrorKind::InvalidRow(row) => write!(f, "Invalid row: {row}"),
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
    use super::*;
    use crate::{ProxyFilter, proxydb::ProxyContext};
    use rama_net::transport::TransportProtocol;
    use rama_utils::str::NonEmptyString;
    use std::str::FromStr;

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
            assert!(parse_csv_row(input).is_none(), "input: {input}");
        }
    }

    #[tokio::test]
    async fn test_proxy_csv_row_reader_happy_one_row() {
        let mut reader = ProxyCsvRowReader::raw(
            "id,true,false,true,,false,,true,false,true,authority,pool_id,continent,country,state,city,carrier,13335,Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
        );
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
        let mut reader = ProxyCsvRowReader::raw(
            "id,true,false,false,true,true,false,true,false,true,authority,pool_id,continent,country,state,city,carrier,42,Basic dXNlcm5hbWU6cGFzc3dvcmQ=\nid2,1,0,0,0,0,0,1,0,0,authority2,pool_id2,continent2,country2,state2,city2,carrier2,1",
        );

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
    fn test_proxy_is_match_happy_path_proxy_with_any_filter_string_cases() {
        let proxy = parse_csv_row("id,1,,1,,,,,,,authority,*,*,*,*,*,*,0").unwrap();
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
    fn test_proxy_is_match_happy_path_proxy_with_any_filters_cases() {
        let proxy =
            parse_csv_row("id,1,,1,,,,,,,authority,pool,continent,country,state,city,carrier,42")
                .unwrap();
        let ctx = ProxyContext {
            protocol: TransportProtocol::Tcp,
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
            assert!(proxy.is_match(&ctx, &filter), "filter: {filter:?}");
        }
    }
}
