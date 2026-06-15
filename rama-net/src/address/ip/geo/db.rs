//! Multi-source IP geolocation: query several MaxMind databases together and
//! merge their results.
//!
//! [`IpGeoDb`] holds any number of labelled *sources*, each a set of
//! [`MmdbReader`]s (e.g. a country DB + a city DB + an ASN DB from one
//! provider). A lookup merges every source into a single [`GeoLocation`] —
//! earlier sources take precedence, later ones only fill the gaps — while
//! [`IpGeoDb::lookup_all`] keeps the per-source breakdown for side-by-side use.
//!
//! Construct one programmatically via [`IpGeoDb::builder`], or from the
//! [`RAMA_IP_GEO_DB_ENV`] environment variable via [`IpGeoDb::from_env`].

use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::location::GeoLocation;
use super::{GeoIpError, MmdbReader};

/// Name of the environment variable parsed by [`IpGeoDb::from_env`].
pub const RAMA_IP_GEO_DB_ENV: &str = "RAMA_IP_GEO_DB";

/// One labelled source: a set of readers queried and merged together.
#[derive(Debug, Clone)]
struct GeoSource {
    label: Box<str>,
    readers: Vec<MmdbReader>,
}

impl GeoSource {
    fn lookup(&self, ip: IpAddr) -> Option<GeoLocation> {
        merge_readers(&self.readers, ip)
    }
}

/// Merge every reader's record for `ip`, earlier readers winning.
fn merge_readers(readers: &[MmdbReader], ip: IpAddr) -> Option<GeoLocation> {
    let mut merged: Option<GeoLocation> = None;
    for reader in readers {
        let Some(loc) = reader.lookup(ip).map(|view| view.to_owned()) else {
            continue;
        };
        if loc.is_empty() {
            continue;
        }
        match &mut merged {
            None => merged = Some(loc),
            Some(m) => m.fill_gaps_from(&loc),
        }
    }
    merged
}

/// A collection of labelled IP geolocation sources, queried together.
///
/// Cheap to clone and safe to query concurrently, so it suits shared
/// application state.
#[derive(Debug, Clone, Default)]
pub struct IpGeoDb {
    sources: Vec<GeoSource>,
}

impl IpGeoDb {
    /// Start building an [`IpGeoDb`].
    #[must_use]
    pub fn builder() -> IpGeoDbBuilder {
        IpGeoDbBuilder::default()
    }

    /// Number of labelled sources.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// Whether there are no sources.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// The source labels, in precedence order.
    pub fn labels(&self) -> impl Iterator<Item = &str> {
        self.sources.iter().map(|s| s.label.as_ref())
    }

    /// Look up `ip` across every source and merge into a single
    /// [`GeoLocation`], earlier sources taking precedence. Returns `None` if
    /// no source carries data for `ip`.
    #[must_use]
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoLocation> {
        let mut merged: Option<GeoLocation> = None;
        for source in &self.sources {
            if let Some(loc) = source.lookup(ip) {
                match &mut merged {
                    None => merged = Some(loc),
                    Some(m) => m.fill_gaps_from(&loc),
                }
            }
        }
        merged
    }

    /// Look up `ip` in each source separately, returning the per-source
    /// (merged-within-source) results in precedence order. Sources without
    /// data for `ip` are omitted.
    #[must_use]
    pub fn lookup_all(&self, ip: IpAddr) -> Vec<IpGeoSourceResult> {
        self.sources
            .iter()
            .filter_map(|s| {
                s.lookup(ip).map(|location| IpGeoSourceResult {
                    label: s.label.clone(),
                    location,
                })
            })
            .collect()
    }

    /// Resolve `ip` into an [`IpGeoInfo`] (the merged location plus the
    /// per-source breakdown), or `None` if no source has data for it.
    #[must_use]
    pub fn resolve(&self, ip: IpAddr) -> Option<IpGeoInfo> {
        let by_source = self.lookup_all(ip);
        let (first, rest) = by_source.split_first()?;
        let mut location = first.location.clone();
        for r in rest {
            location.fill_gaps_from(&r.location);
        }
        Some(IpGeoInfo {
            ip,
            location,
            by_source,
        })
    }

    /// Build from the [`RAMA_IP_GEO_DB_ENV`] environment variable.
    ///
    /// Returns `Ok(None)` when the variable is unset or empty.
    ///
    /// # Errors
    ///
    /// Returns [`GeoIpError`] if the value is malformed or a configured file
    /// cannot be loaded.
    pub fn from_env() -> Result<Option<Self>, GeoIpError> {
        match std::env::var(RAMA_IP_GEO_DB_ENV) {
            Ok(spec) if !spec.trim().is_empty() => Self::parse_spec(&spec).map(Some),
            _ => Ok(None),
        }
    }

    /// Parse a configuration string of the form
    /// `label=file[+file...][;label=file[+file...]...]`.
    ///
    /// `;` separates sources; `+` joins several files under one label (queried
    /// and merged together). An entry without a `label=` prefix is labelled by
    /// the first file's stem.
    ///
    /// # Errors
    ///
    /// Returns [`GeoIpError::InvalidConfig`] for a malformed string, or
    /// [`GeoIpError::Source`] if a configured file cannot be loaded.
    pub fn parse_spec(spec: &str) -> Result<Self, GeoIpError> {
        let invalid = |why: String| GeoIpError::InvalidConfig(why.into_boxed_str());
        let mut builder = Self::builder();
        for entry in spec.split(';') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (label, paths_str) = match entry.split_once('=') {
                Some((label, paths)) => (label.trim(), paths),
                None => ("", entry),
            };
            let paths: Vec<&str> = paths_str.split('+').map(str::trim).collect();
            if paths.iter().any(|p| p.is_empty()) {
                return Err(invalid(format!("empty path in entry {entry:?}")));
            }
            let label: Box<str> = if label.is_empty() {
                default_label(paths[0]).into()
            } else {
                label.into()
            };
            let mut readers = Vec::with_capacity(paths.len());
            for path in paths {
                let reader = MmdbReader::open(path).map_err(|error| GeoIpError::Source {
                    path: path.into(),
                    error: Box::new(error),
                })?;
                readers.push(reader);
            }
            builder = builder.source(label, readers);
        }
        let db = builder.build();
        if db.is_empty() {
            return Err(invalid(format!("no sources parsed from {spec:?}")));
        }
        Ok(db)
    }
}

/// Label for a path-only entry: the file stem, falling back to the raw path.
fn default_label(path: &str) -> &str {
    Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
}

/// Builder for [`IpGeoDb`].
#[derive(Debug, Default)]
pub struct IpGeoDbBuilder {
    sources: Vec<GeoSource>,
}

impl IpGeoDbBuilder {
    /// Add a labelled source from one or more readers, queried and merged
    /// together (earlier readers winning). A source with no readers is ignored.
    #[must_use]
    pub fn source(
        mut self,
        label: impl Into<Box<str>>,
        readers: impl IntoIterator<Item = MmdbReader>,
    ) -> Self {
        let readers: Vec<_> = readers.into_iter().collect();
        if !readers.is_empty() {
            self.sources.push(GeoSource {
                label: label.into(),
                readers,
            });
        }
        self
    }

    /// Add a labelled source from a single reader.
    #[must_use]
    pub fn reader(self, label: impl Into<Box<str>>, reader: MmdbReader) -> Self {
        self.source(label, [reader])
    }

    /// Finalise the [`IpGeoDb`].
    #[must_use]
    pub fn build(self) -> IpGeoDb {
        IpGeoDb {
            sources: self.sources,
        }
    }
}

/// A single source's merged geolocation result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IpGeoSourceResult {
    /// The source label (e.g. `"geolite2"`).
    pub label: Box<str>,
    /// The merged geolocation reported by this source.
    pub location: GeoLocation,
}

/// Resolved IP geolocation, suitable for storing in [`rama_core::extensions`].
///
/// Carries the geolocated [`IpAddr`], the merged [`GeoLocation`] across all
/// sources, and the per-source breakdown (for side-by-side display).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, rama_core::extensions::Extension)]
#[extension(tags(net))]
pub struct IpGeoInfo {
    /// The IP address that was geolocated.
    pub ip: IpAddr,
    /// The merged geolocation across all sources (earlier sources win).
    pub location: GeoLocation,
    /// Per-source results, in precedence order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub by_source: Vec<IpGeoSourceResult>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::ip::geo::mmdb::{IpVersion, MmdbBuilder, MmdbValue};
    use rama_core::geo::Country;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn country_reader(code: &str) -> MmdbReader {
        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-Country");
        let rec = MmdbValue::map([(
            "country",
            MmdbValue::map([("iso_code", MmdbValue::string(code))]),
        )]);
        b.insert(ip("1.2.3.0"), 24, &rec).unwrap();
        MmdbReader::from_bytes(b.build().unwrap()).unwrap()
    }

    fn asn_reader(asn: u32, org: &str) -> MmdbReader {
        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-ASN");
        let rec = MmdbValue::map([
            ("autonomous_system_number", MmdbValue::U32(asn)),
            ("autonomous_system_organization", MmdbValue::string(org)),
        ]);
        b.insert(ip("1.2.3.0"), 24, &rec).unwrap();
        MmdbReader::from_bytes(b.build().unwrap()).unwrap()
    }

    #[test]
    fn merges_readers_within_a_source() {
        // a country DB + an ASN DB under one label merge into one location
        let db = IpGeoDb::builder()
            .source(
                "geolite2",
                [country_reader("BE"), asn_reader(15169, "Google LLC")],
            )
            .build();
        let loc = db.lookup(ip("1.2.3.4")).expect("data present");
        assert_eq!(loc.country, Some(Country::Belgium));
        assert_eq!(
            loc.autonomous_system
                .as_ref()
                .unwrap()
                .asn
                .unwrap()
                .as_u32(),
            15169
        );
        assert!(db.lookup(ip("9.9.9.9")).is_none());
    }

    #[test]
    fn earlier_sources_win_on_conflict() {
        let db = IpGeoDb::builder()
            .reader("primary", country_reader("BE"))
            .reader("secondary", country_reader("DE"))
            .build();
        // primary wins the merged country
        assert_eq!(
            db.lookup(ip("1.2.3.4")).unwrap().country,
            Some(Country::Belgium)
        );
        // but both are visible per-source, in order
        let all = db.lookup_all(ip("1.2.3.4"));
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].label.as_ref(), "primary");
        assert_eq!(all[0].location.country, Some(Country::Belgium));
        assert_eq!(all[1].label.as_ref(), "secondary");
        assert_eq!(all[1].location.country, Some(Country::Germany));
    }

    #[test]
    fn resolve_bundles_ip_merged_and_breakdown() {
        let db = IpGeoDb::builder()
            .reader("geo", country_reader("BE"))
            .reader("asn", asn_reader(15169, "Google LLC"))
            .build();
        let info = db.resolve(ip("1.2.3.4")).expect("data present");
        assert_eq!(info.ip, ip("1.2.3.4"));
        assert_eq!(info.location.country, Some(Country::Belgium));
        assert_eq!(info.by_source.len(), 2);
        // round-trips through serde (as an extension payload would)
        let json = serde_json::to_string(&info).unwrap();
        let back: IpGeoInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, back);
        assert!(db.resolve(ip("9.9.9.9")).is_none());
    }

    #[test]
    fn parse_spec_validation() {
        // empty / malformed values are rejected, missing files surface a Source error
        assert!(matches!(
            IpGeoDb::parse_spec("   "),
            Err(GeoIpError::InvalidConfig(_))
        ));
        assert!(matches!(
            IpGeoDb::parse_spec("label=a.mmdb+"),
            Err(GeoIpError::InvalidConfig(_))
        ));
        assert!(matches!(
            IpGeoDb::parse_spec("label=/nonexistent/does-not-exist.mmdb"),
            Err(GeoIpError::Source { .. })
        ));
    }

    #[test]
    fn parse_spec_loads_files() {
        // TempDir cleans itself up on drop.
        let dir = tempfile::tempdir().expect("tempdir");
        let country = dir.path().join("country.mmdb");
        let asn = dir.path().join("asn.mmdb");

        let mut b = MmdbBuilder::new(IpVersion::V4, "GeoLite2-Country");
        b.insert(
            ip("1.2.3.0"),
            24,
            &MmdbValue::map([(
                "country",
                MmdbValue::map([("iso_code", MmdbValue::string("BE"))]),
            )]),
        )
        .unwrap();
        b.write_to_file(&country).unwrap();
        let mut a = MmdbBuilder::new(IpVersion::V4, "GeoLite2-ASN");
        a.insert(
            ip("1.2.3.0"),
            24,
            &MmdbValue::map([("autonomous_system_number", MmdbValue::U32(15169))]),
        )
        .unwrap();
        a.write_to_file(&asn).unwrap();

        let spec = format!(
            "geolite2={}+{};other={}",
            country.display(),
            asn.display(),
            country.display()
        );
        let db = IpGeoDb::parse_spec(&spec).unwrap();
        assert_eq!(db.len(), 2);
        assert_eq!(db.labels().collect::<Vec<_>>(), vec!["geolite2", "other"]);
        let loc = db.lookup(ip("1.2.3.4")).unwrap();
        assert_eq!(loc.country, Some(Country::Belgium));
        assert_eq!(loc.autonomous_system.unwrap().asn.unwrap().as_u32(), 15169);

        // a label-less entry is named by the file stem
        let db2 = IpGeoDb::parse_spec(&country.display().to_string()).unwrap();
        assert_eq!(db2.labels().collect::<Vec<_>>(), vec!["country"]);
    }
}
