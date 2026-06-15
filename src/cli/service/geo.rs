//! Shared bits for enriching CLI service responses with IP geolocation.

use crate::http::layer::set_header::SetResponseHeaderLayer;
use crate::http::{HeaderName, HeaderValue};

/// Attribution required by the free geolocation databases the CLI demos target.
///
/// GeoLite2 (MaxMind) and IP2Location LITE both require their attribution
/// notice to be shown wherever their data is surfaced. We surface it
/// out-of-band — the `x-geo-attribution` response header and an HTML comment —
/// never in the structured (JSON) data.
pub const GEO_ATTRIBUTION: [&str; 2] = [
    "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com",
    "This site or product includes IP2Location LITE data available from https://lite.ip2location.com",
];

/// The response header carrying the geolocation attribution (one value per
/// notice).
const GEO_ATTRIBUTION_HEADER: &str = "x-geo-attribution";

/// Layers that append the attribution notices to every response (one
/// `x-geo-attribution` value each). Add to a service's layer stack only when a
/// geo database is configured.
#[must_use]
pub fn geo_attribution_layers() -> (
    SetResponseHeaderLayer<HeaderValue>,
    SetResponseHeaderLayer<HeaderValue>,
) {
    let name = || HeaderName::from_static(GEO_ATTRIBUTION_HEADER);
    (
        SetResponseHeaderLayer::appending(name(), HeaderValue::from_static(GEO_ATTRIBUTION[0])),
        SetResponseHeaderLayer::appending(name(), HeaderValue::from_static(GEO_ATTRIBUTION[1])),
    )
}

/// The attribution rendered as an HTML comment for embedding in HTML pages.
/// (The notices contain no `--`, so this is a well-formed comment.)
#[must_use]
pub fn geo_attribution_html_comment() -> String {
    format!("<!-- {} -->", GEO_ATTRIBUTION.join(" | "))
}
