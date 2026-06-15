//! Shared bits for enriching CLI service responses with IP geolocation.

/// Attribution required by the free geolocation databases the CLI demos target.
///
/// GeoLite2 (MaxMind) and IP2Location LITE both require their attribution
/// notice to be shown wherever their data is surfaced; the `serve` commands
/// include this alongside any resolved location.
pub const GEO_ATTRIBUTION: [&str; 2] = [
    "This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com",
    "This site or product includes IP2Location LITE data available from https://lite.ip2location.com",
];
