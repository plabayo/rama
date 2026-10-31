use std::ffi::OsStr;
use std::sync::Arc;

use rama::io::BlockCacheConfig;
use rama::net::address::ip::geo::{GeoIpError, IpGeoDb, MmdbFileConfig};
use rama::telemetry::tracing;
use rama::utils::octets::mib;

/// Selects how the databases named by `RAMA_IP_GEO_DB` are read.
const RAMA_IP_GEO_DB_MODE_ENV: &str = "RAMA_IP_GEO_DB_MODE";

/// Block cache per database file in `pread` mode; most of the gain of a
/// larger cache in the lookup benchmark, about 12 MiB for the usual three files.
const PREAD_CACHE_BYTES: usize = mib(4);

/// How the configured databases are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GeoDbMode {
    /// Memory-map each file.
    Mmap,
    /// Read each file with positional reads and follow file replacements.
    Pread,
    /// Read each file into memory.
    Memory,
}

impl GeoDbMode {
    fn from_env() -> Self {
        let value = std::env::var_os(RAMA_IP_GEO_DB_MODE_ENV);
        let value = value.as_deref();
        Self::parse(value).unwrap_or_else(|| {
            let value = value.unwrap_or_default();
            tracing::warn!(
                "{RAMA_IP_GEO_DB_MODE_ENV}={value:?} is not one of mmap, pread or memory; using mmap"
            );
            Self::Mmap
        })
    }

    /// The mode named by `value`, unset or empty meaning mmap; `None` for
    /// any other value, including one that is not valid Unicode.
    fn parse(value: Option<&OsStr>) -> Option<Self> {
        let Some(value) = value else {
            return Some(Self::Mmap);
        };
        match value.to_str()?.trim() {
            "" | "mmap" => Some(Self::Mmap),
            "pread" => Some(Self::Pread),
            "memory" => Some(Self::Memory),
            _ => None,
        }
    }
}

/// Load the opt-in IP geolocation database configured via `RAMA_IP_GEO_DB`.
///
/// `RAMA_IP_GEO_DB_MODE` selects how the files are read: `mmap` (default)
/// maps them, `pread` reads them with positional reads and picks up files
/// replaced by rename while running, `memory` reads them into memory.
///
/// In `mmap` mode deployments must replace the files by rename (as
/// `geoipupdate` does) and never write into them in place.
///
/// Geolocation enriches responses but is not required to serve them: if the
/// variable is set yet the database fails to load (e.g. a volume not synced
/// yet), warn and continue without it rather than refuse to start.
pub fn load_geo_db_from_env() -> Option<Arc<IpGeoDb>> {
    match load(GeoDbMode::from_env()) {
        Ok(db) => db.map(Arc::new),
        Err(err) => {
            tracing::warn!(
                "RAMA_IP_GEO_DB set but failed to load; continuing without IP geolocation: {err}"
            );
            None
        }
    }
}

fn load(mode: GeoDbMode) -> Result<Option<IpGeoDb>, GeoIpError> {
    match mode {
        // SAFETY: `from_env_mmap` needs the configured files left unmodified
        // while the database lives. Deployments replace them by rename only
        // (the "IP geolocation" section of rama-fp/infra/README.md, done by
        // scripts/geoip_sync.sh); a rename leaves the mapped file intact until
        // it is unmapped (POSIX `rename`, `mmap`).
        GeoDbMode::Mmap => unsafe { IpGeoDb::from_env_mmap() },
        GeoDbMode::Pread => IpGeoDb::from_env_positional(
            &MmdbFileConfig::default().with_cache(BlockCacheConfig::new(PREAD_CACHE_BYTES)),
        ),
        GeoDbMode::Memory => IpGeoDb::from_env(),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt as _;

    use super::*;

    #[test]
    fn parses_modes() {
        let parse = |value: &str| GeoDbMode::parse(Some(OsStr::new(value)));
        assert_eq!(GeoDbMode::parse(None), Some(GeoDbMode::Mmap));
        assert_eq!(parse(""), Some(GeoDbMode::Mmap));
        assert_eq!(parse("mmap"), Some(GeoDbMode::Mmap));
        assert_eq!(parse(" pread "), Some(GeoDbMode::Pread));
        assert_eq!(parse("memory"), Some(GeoDbMode::Memory));
        assert_eq!(parse("PREAD"), None);
        assert_eq!(parse("disk"), None);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_unicode_mode() {
        let value = OsStr::from_bytes(b"pr\xffead");
        assert_eq!(GeoDbMode::parse(Some(value)), None);
    }
}
