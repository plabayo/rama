use super::{ProxyCredentials, ProxyFilter, StringFilter};
use crate::http::{RequestContext, Version};
use std::path::Path;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader, Lines},
};
use venndb::VennDB;

#[derive(Debug, Clone, VennDB)]
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

impl Proxy {
    /// Check if the proxy is a match for the given[`RequestContext`] and [`ProxyFilter`].
    ///
    /// TODO: add unit tests for this?!
    pub fn is_match(&self, ctx: &RequestContext, filter: &ProxyFilter) -> bool {
        if (ctx.http_version == Version::HTTP_3 && !self.socks5 && !self.udp)
            || (ctx.http_version != Version::HTTP_3 && !self.tcp)
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
    pub fn raw(data: String) -> Self {
        let lines: Vec<_> = data.lines().rev().map(str::to_owned).collect();
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

    fn read_opt_string_filter(value: &str) -> Option<StringFilter> {
        if value.is_empty() {
            None
        } else {
            Some(StringFilter::from(value))
        }
    }

    let id = iter.next().map(str::to_owned)?;
    let tcp = iter.next().and_then(parse_csv_bool)?;
    let udp = iter.next().and_then(parse_csv_bool)?;
    let http = iter.next().and_then(parse_csv_bool)?;
    let socks5 = iter.next().and_then(parse_csv_bool)?;
    let datacenter = iter.next().and_then(parse_csv_bool)?;
    let residential = iter.next().and_then(parse_csv_bool)?;
    let mobile = iter.next().and_then(parse_csv_bool)?;
    let authority = iter.next().map(str::to_owned)?;
    let pool_id = read_opt_string_filter(iter.next()?);
    let country = read_opt_string_filter(iter.next()?);
    let city = read_opt_string_filter(iter.next()?);
    let carrier = read_opt_string_filter(iter.next()?);

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
            "1" | "true" => Some(true),
            "" | "0" | "false" => Some(false),
            _ => None,
        }
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
    // TODO: add tests for ProxyCsvRowReader + Proxy::is_match
}
