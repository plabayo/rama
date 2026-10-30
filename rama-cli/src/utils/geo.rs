use std::sync::Arc;

use rama::net::address::ip::geo::IpGeoDb;
use rama::telemetry::tracing;

/// Load the opt-in IP geolocation database configured via `RAMA_IP_GEO_DB`.
///
/// The configured files are memory-mapped, so deployments must replace them
/// by rename (as `geoipupdate` does) and never write into them in place.
///
/// Geolocation enriches responses but is not required to serve them: if the
/// variable is set yet the database fails to load (e.g. a volume not synced
/// yet), warn and continue without it rather than refuse to start.
pub fn load_geo_db_from_env() -> Option<Arc<IpGeoDb>> {
    // SAFETY: `from_env_mmap` needs the configured files left unmodified while
    // the database lives. Deployments replace them by rename only (the "IP
    // geolocation" section of rama-fp/infra/README.md, done by
    // scripts/geoip_sync.sh); a rename leaves the mapped file intact until it is
    // unmapped (POSIX `rename`, `mmap`).
    match unsafe { IpGeoDb::from_env_mmap() } {
        Ok(db) => db.map(Arc::new),
        Err(err) => {
            tracing::warn!(
                "RAMA_IP_GEO_DB set but failed to load; continuing without IP geolocation: {err}"
            );
            None
        }
    }
}
