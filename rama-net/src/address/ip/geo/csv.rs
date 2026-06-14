//! Compile range-based geolocation CSV into an in-memory MaxMind DB.
//!
//! Many free databases ship as CSV with one row per `(ip_from, ip_to, …)`
//! range (notably the IP2Location LITE editions). This module parses such a
//! file and compiles it — via [`MmdbBuilder`] — into an [`MmdbReader`] that the
//! rest of this crate can query like any other `.mmdb`.
//!
//! [`compile_ip2location_lite`] handles the IP2Location LITE country / city /
//! ASN layouts; [`compile_csv`] takes a custom row mapper for any other
//! range-based format.
//!
//! No third-party dependencies: the CSV parser is a small std-only reader that
//! handles `"`-quoted fields with doubled-quote escaping (the IP2Location
//! dialect). Fields may not contain embedded newlines.
//!
//! The underlying writer encodes records inline (no pointer dedup), so the
//! compiled image is larger than a hand-optimised `.mmdb`; this is a deliberate
//! simplicity trade-off — see [`MmdbBuilder`].

use std::fmt;
use std::io::{self, BufRead};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::mmdb::{IpVersion, MmdbBuilder, MmdbValue, MmdbWriteError};
use super::{GeoIpError, MmdbReader};

/// Error while compiling CSV into a MaxMind DB.
#[derive(Debug)]
#[non_exhaustive]
pub enum CsvError {
    /// Failed to read from the input.
    Io(io::Error),
    /// A row could not be parsed; carries the 1-based line number and reason.
    Parse {
        /// 1-based line number of the offending row.
        line: usize,
        /// Why the row could not be parsed.
        reason: Box<str>,
    },
    /// The in-memory database could not be written (e.g. overlapping ranges).
    Write(MmdbWriteError),
    /// The compiled bytes could not be read back as a database.
    Build(GeoIpError),
}

impl fmt::Display for CsvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "csv: i/o error: {err}"),
            Self::Parse { line, reason } => write!(f, "csv: line {line}: {reason}"),
            Self::Write(err) => write!(f, "csv: {err}"),
            Self::Build(err) => write!(f, "csv: {err}"),
        }
    }
}

impl std::error::Error for CsvError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Write(err) => Some(err),
            Self::Build(err) => Some(err),
            Self::Parse { .. } => None,
        }
    }
}

/// A CSV row mapped to an inclusive IP range and its record value.
#[derive(Debug, Clone)]
pub struct CsvGeoRecord {
    /// First address of the range (inclusive).
    pub start: IpAddr,
    /// Last address of the range (inclusive).
    pub end: IpAddr,
    /// The record stored for every address in the range.
    pub value: MmdbValue,
}

/// Compile range-based CSV into an in-memory [`MmdbReader`].
///
/// `map_row` receives the parsed fields of each non-empty line and returns
/// `Ok(Some(record))` to store a range, `Ok(None)` to skip the row, or
/// `Err(reason)` to fail with a [`CsvError::Parse`] carrying the line number.
///
/// # Errors
///
/// Returns [`CsvError`] on I/O failure, a row the mapper rejects, overlapping
/// ranges, or if the compiled image is not a valid database.
pub fn compile_csv<R, F>(
    read: R,
    ip_version: IpVersion,
    database_type: impl Into<String>,
    languages: &[&str],
    mut map_row: F,
) -> Result<MmdbReader, CsvError>
where
    R: BufRead,
    F: FnMut(&[&str]) -> Result<Option<CsvGeoRecord>, Box<str>>,
{
    let mut builder = MmdbBuilder::new(ip_version, database_type);
    if !languages.is_empty() {
        builder = builder.with_languages(languages.iter().copied());
    }
    for (idx, line) in read.lines().enumerate() {
        let line = line.map_err(CsvError::Io)?;
        if line.trim().is_empty() {
            continue;
        }
        let fields = parse_csv_line(&line);
        let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
        match map_row(&refs) {
            Ok(Some(record)) => {
                insert_record(&mut builder, ip_version, &record).map_err(|reason| {
                    CsvError::Parse {
                        line: idx + 1,
                        reason,
                    }
                })?
            }
            Ok(None) => {}
            Err(reason) => {
                return Err(CsvError::Parse {
                    line: idx + 1,
                    reason,
                });
            }
        }
    }
    let bytes = builder.build().map_err(CsvError::Write)?;
    MmdbReader::from_bytes(bytes).map_err(CsvError::Build)
}

/// Split a record's range into CIDR blocks and insert each into the builder.
fn insert_record(
    builder: &mut MmdbBuilder,
    ip_version: IpVersion,
    record: &CsvGeoRecord,
) -> Result<(), Box<str>> {
    let (start, end, bits) = match (ip_version, record.start, record.end) {
        (IpVersion::V4, IpAddr::V4(a), IpAddr::V4(b)) => {
            (u128::from(u32::from(a)), u128::from(u32::from(b)), 32u32)
        }
        (IpVersion::V6, IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b), 128u32),
        _ => return Err("range endpoints do not match the database ip version".into()),
    };
    if start > end {
        return Err("range start is greater than range end".into());
    }
    for (addr, prefix) in range_to_cidrs(start, end, bits) {
        let ip = if bits == 32 {
            IpAddr::V4(Ipv4Addr::from(addr as u32))
        } else {
            IpAddr::V6(Ipv6Addr::from(addr))
        };
        builder
            .insert(ip, prefix, &record.value)
            .map_err(|e| e.to_string().into_boxed_str())?;
    }
    Ok(())
}

/// Split an inclusive `[start, end]` range into aligned CIDR blocks.
///
/// `bits` is the address width (32 or 128). The largest emitted block is a
/// `/1` (the `/0` whole-space case is split into two `/1`s) so the result is
/// always insertable.
fn range_to_cidrs(start: u128, end: u128, bits: u32) -> Vec<(u128, u8)> {
    let mut out = Vec::new();
    let mut cur = start;
    loop {
        // largest power-of-two block that can start at `cur` (alignment)…
        let align = if cur == 0 {
            bits
        } else {
            cur.trailing_zeros().min(bits)
        };
        // …and the largest that still fits in the remaining count.
        let remaining = end - cur; // inclusive count is remaining + 1
        let size_bits = if remaining == u128::MAX {
            128
        } else {
            floor_log2(remaining + 1)
        };
        // never emit a /0; cap at /1 so every block is insertable
        let n = align.min(size_bits).min(bits - 1);
        out.push((cur, (bits - n) as u8));
        let block = 1u128 << n;
        match cur.checked_add(block) {
            Some(next) if next <= end => cur = next,
            _ => break,
        }
    }
    out
}

/// `floor(log2(x))` for `x >= 1`.
fn floor_log2(x: u128) -> u32 {
    127 - x.leading_zeros()
}

/// Parse a single CSV line into fields, honouring `"`-quoted fields with
/// doubled-quote (`""`) escaping. Embedded newlines are not supported.
fn parse_csv_line(line: &str) -> Vec<String> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                cur.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => fields.push(std::mem::take(&mut cur)),
                _ => cur.push(c),
            }
        }
    }
    fields.push(cur);
    fields
}

/// IP2Location LITE database layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ip2LocationLite {
    /// DB1: `ip_from, ip_to, country_code, country_name`.
    Country,
    /// DB3/DB5/DB11: country + region + city, optionally lat/lon, zip, time
    /// zone. Columns beyond what a row provides are simply omitted.
    City,
    /// ASN: `ip_from, ip_to, cidr, asn, as_name`.
    Asn,
}

/// Compile an IP2Location LITE CSV export into an [`MmdbReader`].
///
/// The records are written with MaxMind-style field names, so the resulting
/// database is queried through the usual [`MmdbReader::lookup`] path. Rows with
/// no usable data (e.g. country code `-`) are skipped. `ip_version` selects how
/// the decimal `ip_from`/`ip_to` columns are interpreted (`u32` vs `u128`).
///
/// # Errors
///
/// Returns [`CsvError`] on I/O failure, a malformed row, or an invalid image.
pub fn compile_ip2location_lite<R: BufRead>(
    read: R,
    ip_version: IpVersion,
    kind: Ip2LocationLite,
) -> Result<MmdbReader, CsvError> {
    match kind {
        Ip2LocationLite::Country => {
            compile_csv(read, ip_version, "IP2LOCATION-LITE-DB1", &["en"], |f| {
                map_country(f, ip_version)
            })
        }
        Ip2LocationLite::City => {
            compile_csv(read, ip_version, "IP2LOCATION-LITE-DB11", &["en"], |f| {
                map_city(f, ip_version)
            })
        }
        Ip2LocationLite::Asn => compile_csv(read, ip_version, "IP2LOCATION-LITE-ASN", &[], |f| {
            map_asn(f, ip_version)
        }),
    }
}

/// Parse an IP2Location decimal address column into an [`IpAddr`].
fn parse_ip(field: &str, ip_version: IpVersion) -> Result<IpAddr, Box<str>> {
    let field = field.trim();
    match ip_version {
        IpVersion::V4 => field
            .parse::<u32>()
            .map(|n| IpAddr::V4(Ipv4Addr::from(n)))
            .map_err(|e| format!("invalid ipv4 decimal {field:?}: {e}").into_boxed_str()),
        IpVersion::V6 => field
            .parse::<u128>()
            .map(|n| IpAddr::V6(Ipv6Addr::from(n)))
            .map_err(|e| format!("invalid ipv6 decimal {field:?}: {e}").into_boxed_str()),
    }
}

/// `None` for an empty or `-` placeholder cell.
fn cell<'a>(s: Option<&&'a str>) -> Option<&'a str> {
    s.map(|s| s.trim()).filter(|s| !s.is_empty() && *s != "-")
}

/// A localised-names map `{ "en": name }` (used as a record's `names` value).
fn en_names(name: &str) -> MmdbValue {
    MmdbValue::map([("en", MmdbValue::string(name))])
}

/// A container holding only localised names, `{ "names": { "en": name } }`
/// (the shape the reader expects for city / subdivision entries).
fn names_container(name: &str) -> MmdbValue {
    MmdbValue::map([("names", en_names(name))])
}

fn map_country(fields: &[&str], ip_version: IpVersion) -> Result<Option<CsvGeoRecord>, Box<str>> {
    if fields.len() < 4 {
        return Err("expected at least 4 columns (ip_from, ip_to, code, name)".into());
    }
    let start = parse_ip(fields[0], ip_version)?;
    let end = parse_ip(fields[1], ip_version)?;
    let Some(code) = cell(fields.get(2)) else {
        return Ok(None);
    };
    let mut country = vec![("iso_code".to_owned(), MmdbValue::string(code))];
    if let Some(name) = cell(fields.get(3)) {
        country.push(("names".to_owned(), en_names(name)));
    }
    let value = MmdbValue::map([("country", MmdbValue::Map(country))]);
    Ok(Some(CsvGeoRecord { start, end, value }))
}

fn map_city(fields: &[&str], ip_version: IpVersion) -> Result<Option<CsvGeoRecord>, Box<str>> {
    if fields.len() < 6 {
        return Err("expected at least 6 columns for a city layout".into());
    }
    let start = parse_ip(fields[0], ip_version)?;
    let end = parse_ip(fields[1], ip_version)?;

    let mut record: Vec<(String, MmdbValue)> = Vec::new();
    if let Some(code) = cell(fields.get(2)) {
        let mut country = vec![("iso_code".to_owned(), MmdbValue::string(code))];
        if let Some(name) = cell(fields.get(3)) {
            country.push(("names".to_owned(), en_names(name)));
        }
        record.push(("country".to_owned(), MmdbValue::Map(country)));
    }
    if let Some(region) = cell(fields.get(4)) {
        record.push((
            "subdivisions".to_owned(),
            MmdbValue::Array(vec![names_container(region)]),
        ));
    }
    if let Some(city) = cell(fields.get(5)) {
        record.push(("city".to_owned(), names_container(city)));
    }
    if let Some(zip) = cell(fields.get(8)) {
        record.push((
            "postal".to_owned(),
            MmdbValue::map([("code", MmdbValue::string(zip))]),
        ));
    }
    let mut location: Vec<(String, MmdbValue)> = Vec::new();
    if let (Some(lat), Some(lon)) = (cell(fields.get(6)), cell(fields.get(7)))
        && let (Ok(lat), Ok(lon)) = (lat.parse::<f64>(), lon.parse::<f64>())
    {
        location.push(("latitude".to_owned(), MmdbValue::Double(lat)));
        location.push(("longitude".to_owned(), MmdbValue::Double(lon)));
    }
    if let Some(tz) = cell(fields.get(9)) {
        location.push(("time_zone".to_owned(), MmdbValue::string(tz)));
    }
    if !location.is_empty() {
        record.push(("location".to_owned(), MmdbValue::Map(location)));
    }

    if record.is_empty() {
        return Ok(None);
    }
    Ok(Some(CsvGeoRecord {
        start,
        end,
        value: MmdbValue::Map(record),
    }))
}

fn map_asn(fields: &[&str], ip_version: IpVersion) -> Result<Option<CsvGeoRecord>, Box<str>> {
    if fields.len() < 5 {
        return Err("expected at least 5 columns (ip_from, ip_to, cidr, asn, name)".into());
    }
    let start = parse_ip(fields[0], ip_version)?;
    let end = parse_ip(fields[1], ip_version)?;
    let mut record: Vec<(String, MmdbValue)> = Vec::new();
    if let Some(asn) = cell(fields.get(3)).and_then(|s| s.parse::<u32>().ok())
        && asn != 0
    {
        record.push(("autonomous_system_number".to_owned(), MmdbValue::U32(asn)));
    }
    if let Some(name) = cell(fields.get(4)) {
        record.push((
            "autonomous_system_organization".to_owned(),
            MmdbValue::string(name),
        ));
    }
    if record.is_empty() {
        return Ok(None);
    }
    Ok(Some(CsvGeoRecord {
        start,
        end,
        value: MmdbValue::Map(record),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::geo::Country;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn csv_line_parsing() {
        assert_eq!(parse_csv_line("a,b,c"), vec!["a", "b", "c"]);
        assert_eq!(
            parse_csv_line(r#""16777216","16777471","US","United States""#),
            vec!["16777216", "16777471", "US", "United States"]
        );
        // doubled-quote escape inside a quoted field
        assert_eq!(
            parse_csv_line(r#""x","a ""b"" c""#),
            vec!["x", r#"a "b" c"#]
        );
        assert_eq!(parse_csv_line("a,,c"), vec!["a", "", "c"]);
    }

    #[test]
    fn range_to_cidrs_cases() {
        // one aligned /24
        assert_eq!(
            range_to_cidrs(0x0102_0300, 0x0102_03ff, 32),
            vec![(0x0102_0300, 24)]
        );
        // non-aligned 0..=9 -> /29 (0..7) + /31 (8..9)
        assert_eq!(range_to_cidrs(0, 9, 32), vec![(0, 29), (8, 31)]);
        // whole v4 space splits into two /1 (never a /0)
        assert_eq!(
            range_to_cidrs(0, u128::from(u32::MAX), 32),
            vec![(0, 1), (0x8000_0000, 1)]
        );
    }

    #[test]
    fn range_to_cidrs_covers_exactly() {
        for (start, end) in [(0u128, 0u128), (5, 5), (10, 37), (256, 1000), (0, 255)] {
            let blocks = range_to_cidrs(start, end, 32);
            // contiguous, aligned, and summing to the inclusive count
            let mut next = start;
            let mut count = 0u128;
            for (addr, prefix) in &blocks {
                assert_eq!(*addr, next, "blocks must be contiguous");
                let size = 1u128 << (32 - u32::from(*prefix));
                assert_eq!(addr % size, 0, "block must be aligned");
                next += size;
                count += size;
            }
            assert_eq!(count, end - start + 1);
            assert_eq!(next, end + 1);
        }
    }

    #[test]
    fn compile_ip2location_country_db1() {
        let csv = "\"16777216\",\"16777471\",\"US\",\"United States of America\"\n\
                   \"16777472\",\"16777727\",\"CN\",\"China\"\n\
                   \"16777728\",\"16777983\",\"-\",\"-\"\n";
        let reader =
            compile_ip2location_lite(csv.as_bytes(), IpVersion::V4, Ip2LocationLite::Country)
                .unwrap();
        // 16777216 == 1.0.0.0
        let us = reader.lookup(ip("1.0.0.5")).unwrap();
        assert_eq!(us.country().unwrap().to_owned(), Country::UnitedStates);
        assert_eq!(us.country().unwrap().name(), Some("United States"));
        let cn = reader.lookup(ip("1.0.1.5")).unwrap();
        assert_eq!(cn.country().unwrap().to_owned(), Country::China);
        // the "-" placeholder row was skipped
        assert!(reader.lookup(ip("1.0.2.5")).is_none());
    }

    #[test]
    fn compile_ip2location_city_db11() {
        // ip_from, ip_to, cc, country, region, city, lat, lon, zip, tz
        let csv = "\"16777216\",\"16777471\",\"US\",\"United States\",\"New York\",\"Buffalo\",\"42.886\",\"-78.878\",\"14202\",\"-05:00\"\n";
        let reader =
            compile_ip2location_lite(csv.as_bytes(), IpVersion::V4, Ip2LocationLite::City).unwrap();
        let loc = reader.lookup(ip("1.0.0.5")).unwrap();
        assert_eq!(loc.country().unwrap().to_owned(), Country::UnitedStates);
        assert_eq!(loc.city(), Some("Buffalo"));
        assert_eq!(loc.postal_code(), Some("14202"));
        assert_eq!(loc.latitude(), Some(42.886));
        assert_eq!(loc.time_zone(), Some("-05:00"));
        let owned = loc.to_owned();
        assert_eq!(owned.subdivisions.len(), 1);
        assert_eq!(owned.subdivisions[0].name.as_deref(), Some("New York"));
    }

    #[test]
    fn compile_ip2location_asn() {
        let csv = "\"16777216\",\"16777471\",\"1.0.0.0/24\",\"13335\",\"Cloudflare, Inc.\"\n";
        let reader =
            compile_ip2location_lite(csv.as_bytes(), IpVersion::V4, Ip2LocationLite::Asn).unwrap();
        let loc = reader.lookup(ip("1.0.0.5")).unwrap();
        assert_eq!(loc.asn().map(|a| a.as_u32()), Some(13335));
        assert_eq!(loc.as_organization(), Some("Cloudflare, Inc."));
    }

    #[test]
    fn generic_compile_csv_with_custom_mapper() {
        let csv = "1.0.0.0,1.0.0.255,BE\n";
        let reader = compile_csv(
            csv.as_bytes(),
            IpVersion::V4,
            "Custom-Country",
            &["en"],
            |f| {
                if f.len() < 3 {
                    return Err("need 3 cols".into());
                }
                let start: IpAddr = f[0]
                    .parse()
                    .map_err(|e| format!("bad ip {:?}: {e}", f[0]).into_boxed_str())?;
                let end: IpAddr = f[1]
                    .parse()
                    .map_err(|e| format!("bad ip {:?}: {e}", f[1]).into_boxed_str())?;
                let value = MmdbValue::map([(
                    "country",
                    MmdbValue::map([("iso_code", MmdbValue::string(f[2]))]),
                )]);
                Ok(Some(CsvGeoRecord { start, end, value }))
            },
        )
        .unwrap();
        assert_eq!(
            reader
                .lookup(ip("1.0.0.42"))
                .unwrap()
                .country()
                .unwrap()
                .to_owned(),
            Country::Belgium
        );
    }
}
