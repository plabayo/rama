//! Compile range-based geolocation CSV into a MaxMind DB.
//!
//! Many free databases ship as CSV with one row per `(ip_from, ip_to, …)`
//! range (notably the IP2Location LITE editions). This compiles such a file
//! via [`MmdbBuilder`] into a database queryable like any other `.mmdb`.
//!
//! - [`compile_ip2location_lite`] / [`compile_ip2location_lite_to_file`] handle
//!   the IP2Location LITE country / city / ASN layouts.
//! - [`compile_csv`] / [`compile_csv_into`] take a custom row mapper for any
//!   other range-based format.
//!
//! The input is read incrementally; the `*_into` / `*_to_file` variants stream
//! the result to disk without buffering a second copy.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use std::io::{self, Read};
use std::path::Path;

use super::mmdb::{IpVersion, MmdbBuilder, MmdbWriteError};
use super::{AsOrg, Coordinates, GeoIpError, GeoLocation, MmdbReader, Subdivision, TimeZoneName};
use crate::asn::LossyAsn;

use rama_core::geo::Country;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// Error while compiling CSV into a MaxMind DB.
#[derive(Debug)]
#[non_exhaustive]
pub enum CsvError {
    /// Failed to read from the input.
    Io(io::Error),
    /// A row could not be parsed; carries the 1-based record number and reason.
    Parse {
        /// 1-based record number of the offending row (records, not physical
        /// lines — a quoted field may span several lines).
        record: usize,
        /// Why the row could not be parsed.
        reason: Box<str>,
    },
    /// The in-memory database could not be written (e.g. overlapping ranges).
    Write(MmdbWriteError),
    /// The compiled bytes could not be read back as a database.
    Build(GeoIpError),
}

impl core::fmt::Display for CsvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "csv: i/o error: {err}"),
            Self::Parse { record, reason } => write!(f, "csv: record {record}: {reason}"),
            Self::Write(err) => write!(f, "csv: {err}"),
            Self::Build(err) => write!(f, "csv: {err}"),
        }
    }
}

impl core::error::Error for CsvError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Write(err) => Some(err),
            Self::Build(err) => Some(err),
            Self::Parse { .. } => None,
        }
    }
}

/// A CSV row mapped to an inclusive IP range and its geolocation.
#[derive(Debug, Clone)]
pub struct CsvGeoRecord {
    /// First address of the range (inclusive).
    pub start: IpAddr,
    /// Last address of the range (inclusive).
    pub end: IpAddr,
    /// The geolocation stored for every address in the range.
    pub location: GeoLocation,
}

/// Compile range-based CSV into an existing [`MmdbBuilder`].
///
/// This is the lowest-level entry point: you own the builder, so you choose how
/// to finish — [`MmdbBuilder::build`] for an in-memory image,
/// [`MmdbReader::from_bytes`] for a live reader, or
/// [`MmdbBuilder::write_to_file`] to stream it to disk.
///
/// `map_row` receives the parsed fields of each row and returns
/// `Ok(Some(record))` to store a range, `Ok(None)` to skip the row, or
/// `Err(reason)` to fail with a [`CsvError::Parse`] carrying the record number.
///
/// # Errors
///
/// Returns [`CsvError`] on I/O failure, a row the mapper rejects, or
/// overlapping ranges.
pub fn compile_csv_into<R, F>(
    read: R,
    builder: &mut MmdbBuilder,
    mut map_row: F,
) -> Result<(), CsvError>
where
    R: Read,
    F: FnMut(&[&str]) -> Result<Option<CsvGeoRecord>, Box<str>>,
{
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(read);
    let mut record = csv::StringRecord::new();
    let mut record_num = 0usize;
    let mut cidrs: Vec<(u128, u8)> = Vec::new();
    loop {
        match reader.read_record(&mut record) {
            Ok(true) => {}
            Ok(false) => break,
            Err(err) => return Err(map_csv_err(err, record_num + 1)),
        }
        record_num += 1;
        if record.iter().all(str::is_empty) {
            continue;
        }
        let fields: Vec<&str> = record.iter().collect();
        match map_row(&fields) {
            Ok(Some(rec)) => {
                insert_record(builder, &rec, &mut cidrs).map_err(|reason| CsvError::Parse {
                    record: record_num,
                    reason,
                })?
            }
            Ok(None) => {}
            Err(reason) => {
                return Err(CsvError::Parse {
                    record: record_num,
                    reason,
                });
            }
        }
    }
    Ok(())
}

/// Compile range-based CSV into an in-memory [`MmdbReader`].
///
/// A convenience wrapper over [`compile_csv_into`] for the common case; see it
/// for the `map_row` contract. Use [`compile_csv_into`] + [`MmdbBuilder::write_to_file`]
/// to stream a large database to disk instead.
///
/// # Errors
///
/// Returns [`CsvError`] on I/O failure, a rejected row, overlapping ranges, or
/// if the compiled image is not a valid database.
pub fn compile_csv<R, F>(
    read: R,
    ip_version: IpVersion,
    database_type: impl Into<String>,
    languages: &[&str],
    map_row: F,
) -> Result<MmdbReader, CsvError>
where
    R: Read,
    F: FnMut(&[&str]) -> Result<Option<CsvGeoRecord>, Box<str>>,
{
    let mut builder = make_builder(ip_version, database_type, languages);
    compile_csv_into(read, &mut builder, map_row)?;
    let bytes = builder.build().map_err(CsvError::Write)?;
    MmdbReader::from_bytes(bytes).map_err(CsvError::Build)
}

fn make_builder(
    ip_version: IpVersion,
    database_type: impl Into<String>,
    languages: &[&str],
) -> MmdbBuilder {
    let builder = MmdbBuilder::new(ip_version, database_type);
    if languages.is_empty() {
        builder
    } else {
        builder.with_languages(languages.iter().copied())
    }
}

/// Map a row-read error onto a [`CsvError`].
fn map_csv_err(err: csv::Error, record: usize) -> CsvError {
    if err.is_io_error() {
        match err.into_kind() {
            csv::ErrorKind::Io(io) => CsvError::Io(io),
            other => CsvError::Parse {
                record,
                reason: format!("{other:?}").into_boxed_str(),
            },
        }
    } else {
        CsvError::Parse {
            record,
            reason: err.to_string().into_boxed_str(),
        }
    }
}

/// Split a record's range into CIDR blocks and insert each into the builder.
/// `cidrs` is a reusable scratch buffer (cleared on entry).
fn insert_record(
    builder: &mut MmdbBuilder,
    record: &CsvGeoRecord,
    cidrs: &mut Vec<(u128, u8)>,
) -> Result<(), Box<str>> {
    let (start, end, bits) = match (record.start, record.end) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            (u128::from(u32::from(a)), u128::from(u32::from(b)), 32u32)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b), 128u32),
        _ => return Err("range endpoints mix IPv4 and IPv6".into()),
    };
    if start > end {
        return Err("range start is greater than range end".into());
    }
    let to_box = |e: ipnet::PrefixLenError| e.to_string().into_boxed_str();
    range_to_cidrs_into(start, end, bits, cidrs);
    for &(addr, prefix) in cidrs.iter() {
        let net = if bits == 32 {
            IpNet::V4(Ipv4Net::new(Ipv4Addr::from(addr as u32), prefix).map_err(to_box)?)
        } else {
            IpNet::V6(Ipv6Net::new(Ipv6Addr::from(addr), prefix).map_err(to_box)?)
        };
        builder
            .insert(net, &record.location)
            .map_err(|e| e.to_string().into_boxed_str())?;
    }
    Ok(())
}

/// Split an inclusive `[start, end]` range into aligned CIDR blocks.
///
/// `bits` is the address width (32 or 128). The largest emitted block is a
/// `/1` (the `/0` whole-space case is split into two `/1`s) so the result is
/// always insertable.
#[cfg(test)]
fn range_to_cidrs(start: u128, end: u128, bits: u32) -> Vec<(u128, u8)> {
    let mut out = Vec::new();
    range_to_cidrs_into(start, end, bits, &mut out);
    out
}

/// As [`range_to_cidrs`], but fills a caller-owned buffer (cleared first) so it
/// can be reused across rows instead of allocating a fresh `Vec` per record.
fn range_to_cidrs_into(start: u128, end: u128, bits: u32, out: &mut Vec<(u128, u8)>) {
    out.clear();
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
}

/// `floor(log2(x))` for `x >= 1`.
fn floor_log2(x: u128) -> u32 {
    127 - x.leading_zeros()
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

/// Compile an IP2Location LITE CSV export into an in-memory [`MmdbReader`].
///
/// The records are written with MaxMind-style field names, so the resulting
/// database is queried through the usual [`MmdbReader::lookup`] path. Rows with
/// no usable data (e.g. country code `-`) are skipped. `ip_version` selects how
/// the decimal `ip_from`/`ip_to` columns are interpreted (`u32` vs `u128`).
///
/// Use [`compile_ip2location_lite_to_file`] to stream a large database straight
/// to disk instead of materialising it.
///
/// # Errors
///
/// Returns [`CsvError`] on I/O failure, a malformed row, or an invalid image.
pub fn compile_ip2location_lite<R: Read>(
    read: R,
    ip_version: IpVersion,
    kind: Ip2LocationLite,
) -> Result<MmdbReader, CsvError> {
    let (database_type, languages) = ip2location_meta(kind);
    let mut builder = make_builder(ip_version, database_type, languages);
    fill_ip2location(read, ip_version, kind, &mut builder)?;
    let bytes = builder.build().map_err(CsvError::Write)?;
    MmdbReader::from_bytes(bytes).map_err(CsvError::Build)
}

/// Compile an IP2Location LITE CSV export and write the database to `path`,
/// streaming it to disk.
///
/// See [`compile_ip2location_lite`] for the layout and row handling.
///
/// # Errors
///
/// Returns [`CsvError`] on I/O failure, a malformed row, or a write failure.
pub fn compile_ip2location_lite_to_file<R: Read>(
    read: R,
    ip_version: IpVersion,
    kind: Ip2LocationLite,
    path: impl AsRef<Path>,
) -> Result<(), CsvError> {
    let (database_type, languages) = ip2location_meta(kind);
    let mut builder = make_builder(ip_version, database_type, languages);
    fill_ip2location(read, ip_version, kind, &mut builder)?;
    builder.write_to_file(path).map_err(CsvError::Write)
}

fn ip2location_meta(kind: Ip2LocationLite) -> (&'static str, &'static [&'static str]) {
    match kind {
        Ip2LocationLite::Country => ("IP2LOCATION-LITE-DB1", &["en"]),
        Ip2LocationLite::City => ("IP2LOCATION-LITE-DB11", &["en"]),
        Ip2LocationLite::Asn => ("IP2LOCATION-LITE-ASN", &[]),
    }
}

fn fill_ip2location<R: Read>(
    read: R,
    ip_version: IpVersion,
    kind: Ip2LocationLite,
    builder: &mut MmdbBuilder,
) -> Result<(), CsvError> {
    match kind {
        Ip2LocationLite::Country => compile_csv_into(read, builder, |f| map_country(f, ip_version)),
        Ip2LocationLite::City => compile_csv_into(read, builder, |f| map_city(f, ip_version)),
        Ip2LocationLite::Asn => compile_csv_into(read, builder, |f| map_asn(f, ip_version)),
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

/// Wrap a typed [`GeoLocation`] for a parsed range, or skip it if empty.
fn record(start: IpAddr, end: IpAddr, location: GeoLocation) -> Option<CsvGeoRecord> {
    (!location.is_empty()).then_some(CsvGeoRecord {
        start,
        end,
        location,
    })
}

fn map_country(fields: &[&str], ip_version: IpVersion) -> Result<Option<CsvGeoRecord>, Box<str>> {
    if fields.len() < 4 {
        return Err("expected at least 4 columns (ip_from, ip_to, code, name)".into());
    }
    let start = parse_ip(fields[0], ip_version)?;
    let end = parse_ip(fields[1], ip_version)?;
    let loc = GeoLocation {
        country: cell(fields.get(2)).map(Country::from_code),
        ..Default::default()
    };
    Ok(record(start, end, loc))
}

fn map_city(fields: &[&str], ip_version: IpVersion) -> Result<Option<CsvGeoRecord>, Box<str>> {
    if fields.len() < 6 {
        return Err("expected at least 6 columns for a city layout".into());
    }
    let start = parse_ip(fields[0], ip_version)?;
    let end = parse_ip(fields[1], ip_version)?;

    let mut loc = GeoLocation {
        country: cell(fields.get(2)).map(Country::from_code),
        city: cell(fields.get(5)).map(Box::from),
        postal_code: cell(fields.get(8)).map(Box::from),
        ..Default::default()
    };
    if let Some(region) = cell(fields.get(4)) {
        loc.subdivisions.push(Subdivision {
            iso_code: None,
            name: Some(region.into()),
        });
    }
    // DB11 always pairs a time zone with coordinates; a bare time zone (no
    // lat/lon) has nowhere to live in the typed record and is dropped.
    // IP2Location emits 0,0 ("null island") for unknown coordinates — treat that
    // as absent rather than a real point in the Gulf of Guinea.
    if let (Some(lat), Some(lon)) = (cell(fields.get(6)), cell(fields.get(7)))
        && let (Ok(latitude), Ok(longitude)) = (lat.parse::<f64>(), lon.parse::<f64>())
        && !(latitude == 0.0 && longitude == 0.0)
    {
        loc.location = Some(Coordinates {
            latitude,
            longitude,
            accuracy_radius_km: None,
            time_zone: cell(fields.get(9)).map(TimeZoneName::from),
        });
    }
    Ok(record(start, end, loc))
}

fn map_asn(fields: &[&str], ip_version: IpVersion) -> Result<Option<CsvGeoRecord>, Box<str>> {
    if fields.len() < 5 {
        return Err("expected at least 5 columns (ip_from, ip_to, cidr, asn, name)".into());
    }
    let start = parse_ip(fields[0], ip_version)?;
    let end = parse_ip(fields[1], ip_version)?;
    let asn = cell(fields.get(3))
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|n| *n != 0);
    let organization = cell(fields.get(4)).map(Box::from);
    let loc = GeoLocation {
        autonomous_system: (asn.is_some() || organization.is_some()).then(|| AsOrg {
            asn: asn.map(LossyAsn::from),
            organization,
        }),
        ..Default::default()
    };
    Ok(record(start, end, loc))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
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
        // quoted fields
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
    fn compile_csv_into_streams_with_custom_mapper() {
        // exercise the lowest-level streaming entry point directly
        let mut builder = MmdbBuilder::new(IpVersion::V4, "Test-Country");
        let csv = "16777216,16777471,BE\n16777472,16777727,FR\n";
        compile_csv_into(csv.as_bytes(), &mut builder, |f| {
            let start = parse_ip(f[0], IpVersion::V4)?;
            let end = parse_ip(f[1], IpVersion::V4)?;
            let loc = GeoLocation {
                country: Some(Country::from_code(f[2])),
                ..Default::default()
            };
            Ok(record(start, end, loc))
        })
        .unwrap();
        let reader = MmdbReader::from_bytes(builder.build().unwrap()).unwrap();
        assert_eq!(
            reader
                .lookup(ip("1.0.0.5"))
                .unwrap()
                .country()
                .unwrap()
                .code(),
            "BE"
        );
        assert_eq!(
            reader
                .lookup(ip("1.0.1.5"))
                .unwrap()
                .country()
                .unwrap()
                .code(),
            "FR"
        );
    }

    #[test]
    fn compile_city_skips_null_island_coords() {
        // a 0,0 row (IP2Location's "unknown" coordinates) keeps country but
        // stores no location; a real row keeps its coordinates
        let csv = "\"16777216\",\"16777471\",\"US\",\"United States\",\"\",\"\",\"0.000000\",\"0.000000\",\"\",\"\"\n\
                   \"16777472\",\"16777727\",\"US\",\"United States\",\"NY\",\"Buffalo\",\"42.886\",\"-78.878\",\"14202\",\"-05:00\"\n";
        let reader =
            compile_ip2location_lite(csv.as_bytes(), IpVersion::V4, Ip2LocationLite::City).unwrap();
        let null = reader.lookup(ip("1.0.0.5")).unwrap();
        assert_eq!(null.country().unwrap().code(), "US");
        assert_eq!(null.latitude(), None);
        let real = reader.lookup(ip("1.0.1.5")).unwrap();
        assert_eq!(real.latitude(), Some(42.886));
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
    fn compile_to_file_streams_and_loads() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("country.mmdb");
        let csv = "\"16777216\",\"16777471\",\"BE\",\"Belgium\"\n";
        compile_ip2location_lite_to_file(
            csv.as_bytes(),
            IpVersion::V4,
            Ip2LocationLite::Country,
            &path,
        )
        .unwrap();
        // the streamed-to-disk database loads and queries like any other
        let reader = MmdbReader::open(&path).unwrap();
        assert_eq!(
            reader
                .lookup(ip("1.0.0.5"))
                .unwrap()
                .country()
                .unwrap()
                .to_owned(),
            Country::Belgium
        );
    }

    #[test]
    fn generic_compile_csv_with_custom_mapper() {
        // a plain unquoted row + custom mapper
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
                let location = GeoLocation {
                    country: Some(Country::from_code(f[2])),
                    ..Default::default()
                };
                Ok(Some(CsvGeoRecord {
                    start,
                    end,
                    location,
                }))
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

    /// Property: for any `[start, end]`, `range_to_cidrs` yields contiguous,
    /// aligned blocks with valid prefixes that cover the range exactly.
    #[quickcheck_macros::quickcheck]
    fn prop_range_to_cidrs_covers_v4(a: u32, b: u32) -> bool {
        let (start, end) = if a <= b { (a, b) } else { (b, a) };
        let (start, end) = (u128::from(start), u128::from(end));
        let blocks = range_to_cidrs(start, end, 32);
        if blocks.is_empty() {
            return false;
        }
        let mut next = start;
        for (addr, prefix) in &blocks {
            let p = u32::from(*prefix);
            if *addr != next || !(1..=32).contains(&p) {
                return false;
            }
            let size = 1u128 << (32 - p);
            if addr % size != 0 {
                return false; // block must be aligned to its own size
            }
            next += size;
        }
        next == end + 1
    }

    #[test]
    fn compile_ipv6_country() {
        // 42540766411282592856903984951653826560 == 2001:db8:: ; the row spans
        // the /48 below it, so the v6 path of parse_ip + range_to_cidrs(.,.,128)
        // is exercised.
        let from: u128 = u128::from(ip6("2001:db8::"));
        let to: u128 = u128::from(ip6("2001:db8:0:ffff:ffff:ffff:ffff:ffff"));
        let csv = format!("\"{from}\",\"{to}\",\"BE\",\"Belgium\"\n");
        let reader =
            compile_ip2location_lite(csv.as_bytes(), IpVersion::V6, Ip2LocationLite::Country)
                .unwrap();
        assert_eq!(
            reader
                .lookup(ip("2001:db8:0:1234::1"))
                .unwrap()
                .country()
                .unwrap()
                .to_owned(),
            Country::Belgium
        );
        assert!(reader.lookup(ip("2001:db9::1")).is_none());
    }

    #[test]
    fn malformed_rows_report_line_and_range_errors() {
        // a too-short row carries its 1-based line number
        let err = compile_ip2location_lite(
            "\"1\",\"2\",\"US\",\"x\"\n\"oops\"\n".as_bytes(),
            IpVersion::V4,
            Ip2LocationLite::Country,
        )
        .unwrap_err();
        assert!(matches!(err, CsvError::Parse { record: 2, .. }));

        // ip_from > ip_to is rejected as a range error
        let err = compile_ip2location_lite(
            "\"100\",\"50\",\"US\",\"x\"\n".as_bytes(),
            IpVersion::V4,
            Ip2LocationLite::Country,
        )
        .unwrap_err();
        assert!(
            matches!(&err, CsvError::Parse { reason, .. } if reason.contains("greater than")),
            "unexpected error: {err}"
        );
    }

    fn ip6(s: &str) -> core::net::Ipv6Addr {
        s.parse().unwrap()
    }
}
