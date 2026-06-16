//! Shared bits for enriching CLI service responses with IP geolocation.

use crate::http::{HeaderName, HeaderValue, Response};
use crate::layer::MapOutputLayer;
use crate::net::address::ip::geo::GeoLocation;

/// The response header carrying the geolocation attribution (one value per
/// notice). The notices themselves come from the loaded databases — see
/// [`IpGeoDb::attributions`](crate::net::address::ip::geo::IpGeoDb::attributions).
const GEO_ATTRIBUTION_HEADER: &str = "x-geo-attribution";

/// A layer that appends each attribution `notice` to every response as an
/// `x-geo-attribution` header value. Pass the loaded databases' notices
/// (`IpGeoDb::attributions()`); add the layer only when that list is non-empty.
pub fn geo_attribution_layer(
    notices: Vec<&'static str>,
) -> MapOutputLayer<impl Fn(Response) -> Response + Clone + Send + Sync + 'static> {
    let name = HeaderName::from_static(GEO_ATTRIBUTION_HEADER);
    MapOutputLayer::new(move |mut resp: Response| {
        for notice in &notices {
            resp.headers_mut()
                .append(name.clone(), HeaderValue::from_static(notice));
        }
        resp
    })
}

/// The attribution notices as a single HTML comment, or `None` when empty.
/// (The notices contain no `--`, so this is a well-formed comment.)
#[must_use]
pub fn geo_attribution_html_comment(notices: &[&str]) -> Option<String> {
    (!notices.is_empty()).then(|| format!("<!-- {} -->", notices.join(" | ")))
}

/// Human-readable `(label, value)` rows for a resolved [`GeoLocation`], shared
/// by the HTML renderers (the `serve ip` page panel and the `serve fp` report
/// table). Empty fields are omitted.
#[must_use]
pub fn geo_location_rows(loc: &GeoLocation) -> Vec<(&'static str, String)> {
    let mut rows = Vec::new();
    if let Some(c) = &loc.country {
        let name = c
            .name()
            .map(str::to_owned)
            .unwrap_or_else(|| c.code().to_owned());
        rows.push(("Country", format!("{name} ({})", c.code())));
    }
    if let Some(c) = &loc.continent {
        rows.push((
            "Continent",
            c.name()
                .map(str::to_owned)
                .unwrap_or_else(|| c.code().to_owned()),
        ));
    }
    if let Some(region) = loc.subdivisions.first().and_then(|s| s.name.as_deref()) {
        rows.push(("Region", region.to_owned()));
    }
    if let Some(city) = &loc.city {
        rows.push(("City", city.to_string()));
    }
    if let Some(postal) = &loc.postal_code {
        rows.push(("Postal", postal.to_string()));
    }
    if let Some(l) = &loc.location {
        rows.push((
            "Coordinates",
            format!("{:.4}, {:.4}", l.latitude, l.longitude),
        ));
        if let Some(tz) = &l.time_zone {
            rows.push(("Time Zone", tz.to_string()));
        }
    }
    if let Some(asys) = &loc.autonomous_system {
        if let Some(asn) = asys.asn {
            rows.push(("ASN", format!("AS{}", asn.as_u32())));
        }
        if let Some(org) = &asys.organization {
            rows.push(("Network", org.to_string()));
        }
    }
    rows
}
