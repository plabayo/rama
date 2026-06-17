//! IP geolocation: map an [`IpAddr`] to location data.
//!
//! This module provides a dependency-free, zero-copy reader for the
//! MaxMind DB (`.mmdb`) binary format — the de-facto standard shipped by
//! MaxMind (GeoLite2 / GeoIP2), DB-IP and others — together with a minimal
//! writer used to synthesise test fixtures (and, in a later phase, to
//! compile other inputs such as CSV into the same in-memory representation).
//!
//! The on-disk format is documented in
//! [`rama-net/specifications/geoip/MaxMind-DB-spec.md`].
//!
//! # Design
//!
//! - **Zero-copy by default.** [`MmdbReader::lookup`] returns an opaque
//!   borrowing view ([`GeoLocationRef`]) that decodes fields lazily from the
//!   backing buffer without allocating. Call [`GeoLocationRef::to_owned`] to
//!   obtain an owned, `'static` [`GeoLocation`] suitable for storing in
//!   [`rama_core::extensions`] or serialising.
//! - **Minimal memory.** The database is held once as a shared buffer and
//!   never fully materialised; a lookup walks a handful of tree nodes and
//!   decodes only the matched record.
//! - **No third-party dependencies.** The reader and writer use `std` only.
//!
//! [`IpAddr`]: std::net::IpAddr
//! [`rama-net/specifications/geoip/MaxMind-DB-spec.md`]: https://github.com/plabayo/rama/blob/main/rama-net/specifications/geoip/MaxMind-DB-spec.md

mod csv;
pub use csv::{
    CsvError, CsvGeoRecord, Ip2LocationLite, compile_csv, compile_csv_into,
    compile_ip2location_lite, compile_ip2location_lite_to_file,
};

mod db;
pub use db::{IpGeoDb, IpGeoDbBuilder, IpGeoInfo, IpGeoSourceResult, RAMA_IP_GEO_DB_ENV};

mod location;
pub use location::{AsOrg, Coordinates, GeoLocation, GeoLocationRef, Subdivision, TimeZoneName};

pub mod mmdb;
pub use mmdb::{IpVersion, Metadata, MmdbBuilder, MmdbReader, MmdbWriteError, RecordSize};

use std::fmt;

/// Error returned while loading or querying an IP geolocation database.
#[derive(Debug)]
#[non_exhaustive]
pub enum GeoIpError {
    /// The MaxMind DB metadata marker could not be located: the bytes are not
    /// a MaxMind DB, or the file is truncated.
    MissingMetadataMarker,
    /// The database bytes are structurally invalid (out-of-bounds offset,
    /// unexpected data type, truncated field, pointer cycle, ...).
    Corrupt(&'static str),
    /// The database is well-formed but uses a feature this reader does not
    /// support (e.g. an unexpected record size or binary format version).
    Unsupported(&'static str),
    /// Failed to read the database from disk.
    Io(std::io::Error),
    /// A geolocation database configuration string (e.g. the value of the
    /// `RAMA_IP_GEO_DB` environment variable) was malformed.
    InvalidConfig(Box<str>),
    /// A configured database source could not be loaded; carries the offending
    /// path and the underlying error.
    Source {
        /// The configured filesystem path that failed to load.
        path: Box<str>,
        /// The underlying load error.
        error: Box<Self>,
    },
}

impl fmt::Display for GeoIpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMetadataMarker => {
                f.write_str("mmdb: metadata marker not found (not a MaxMind DB or truncated)")
            }
            Self::Corrupt(why) => write!(f, "mmdb: corrupt database: {why}"),
            Self::Unsupported(why) => write!(f, "mmdb: unsupported database: {why}"),
            Self::Io(err) => write!(f, "mmdb: i/o error: {err}"),
            Self::InvalidConfig(why) => write!(f, "geoip: invalid configuration: {why}"),
            Self::Source { path, error } => {
                write!(f, "geoip: failed to load source {path:?}: {error}")
            }
        }
    }
}

impl std::error::Error for GeoIpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Source { error, .. } => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for GeoIpError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}
