use std::sync::Arc;

use rama::net::address::ip::geo::IpGeoDb;
use rama::telemetry::tracing;

/// Load the opt-in IP geolocation database configured via `RAMA_IP_GEO_DB`.
///
/// Geolocation enriches responses but is not required to serve them: if the
/// variable is set yet the database fails to load (e.g. a volume not synced
/// yet), warn and continue without it rather than refuse to start.
pub fn load_geo_db_from_env() -> Option<Arc<IpGeoDb>> {
    match IpGeoDb::from_env() {
        Ok(db) => db.map(Arc::new),
        Err(err) => {
            tracing::warn!(
                "RAMA_IP_GEO_DB set but failed to load; continuing without IP geolocation: {err}"
            );
            None
        }
    }
}
