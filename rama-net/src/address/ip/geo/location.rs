//! Geolocation result types: an owned [`GeoLocation`] and a borrowing,
//! zero-copy [`GeoLocationRef`] view over a MaxMind DB record.
//!
//! Bounded fields use the shared typed enums from [`rama_core::geo`]
//! ([`Continent`], [`Country`]); free-form fields use `std` string types.

use core::fmt;

use crate::std::boxed::Box;
use crate::std::string::String;
use crate::std::vec::Vec;

use super::mmdb::decoder::Decoder;
#[cfg(feature = "std")]
use super::mmdb::{MmdbBuilder, MmdbValue, MmdbWriteError};
use crate::asn::LossyAsn;

use rama_core::geo::{Continent, ContinentRef, Country, CountryRef};

#[cfg(feature = "std")]
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// MaxMind-DB record field names, shared by the reader and the [`MmdbValue`]
/// encoder below so the two can never drift.
mod keys {
    pub(super) const CONTINENT: &str = "continent";
    pub(super) const COUNTRY: &str = "country";
    pub(super) const REGISTERED_COUNTRY: &str = "registered_country";
    pub(super) const SUBDIVISIONS: &str = "subdivisions";
    pub(super) const CITY: &str = "city";
    pub(super) const POSTAL: &str = "postal";
    pub(super) const LOCATION: &str = "location";
    pub(super) const ISO_CODE: &str = "iso_code";
    pub(super) const CODE: &str = "code";
    pub(super) const NAMES: &str = "names";
    pub(super) const EN: &str = "en";
    pub(super) const LATITUDE: &str = "latitude";
    pub(super) const LONGITUDE: &str = "longitude";
    pub(super) const ACCURACY_RADIUS: &str = "accuracy_radius";
    pub(super) const TIME_ZONE: &str = "time_zone";
    pub(super) const ASN_NUMBER: &str = "autonomous_system_number";
    pub(super) const ASN_ORG: &str = "autonomous_system_organization";
}

/// A time-zone value as recorded by the geolocation provider, stored verbatim.
///
/// The format is provider-dependent: an IANA identifier (e.g.
/// `"Europe/Brussels"`, as emitted by GeoLite2) or a fixed UTC offset (e.g.
/// `"-05:00"`, as emitted by IP2Location LITE). It carries no time-zone-database
/// cost and no third-party dependency; interpret it according to your source —
/// IANA names resolve via e.g. `jiff::tz::TimeZone::get(tz.as_str())`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct TimeZoneName(Box<str>);

impl TimeZoneName {
    /// The IANA identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for TimeZoneName {
    fn from(s: &str) -> Self {
        Self(s.into())
    }
}

impl From<String> for TimeZoneName {
    fn from(s: String) -> Self {
        Self(s.into_boxed_str())
    }
}

impl fmt::Display for TimeZoneName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TimeZoneName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <Box<str>>::deserialize(deserializer)?;
        Ok(Self(s))
    }
}

/// A subdivision (state / region / province) as recorded in a database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subdivision {
    /// ISO 3166-2 subdivision code, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iso_code: Option<Box<str>>,
    /// Localised subdivision name in the requested language, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<Box<str>>,
}

/// Geographic coordinates and associated location metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Coordinates {
    /// Approximate latitude in degrees.
    pub latitude: f64,
    /// Approximate longitude in degrees.
    pub longitude: f64,
    /// Radius in kilometres within which the coordinates are likely correct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accuracy_radius_km: Option<u16>,
    /// IANA time zone identifier, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_zone: Option<TimeZoneName>,
}

/// Autonomous system information (typically from an ASN database).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsOrg {
    /// The autonomous system number, preserved verbatim (it may fall outside
    /// the assignable ranges; convert with [`LossyAsn::to_asn`] when needed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<LossyAsn>,
    /// The organisation that registered the autonomous system, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<Box<str>>,
}

/// Owned, `'static` geolocation data for a single IP address.
///
/// Obtain one from [`GeoLocationRef::to_owned`]. Suitable for storing in
/// [`rama_core::extensions`] and for serialisation. Every field is optional:
/// different database editions (country / city / ASN) populate different
/// subsets. EU membership is available via [`Country::is_in_eu`].
#[derive(
    Debug, Clone, Default, PartialEq, Serialize, Deserialize, rama_core::extensions::Extension,
)]
#[extension(tags(net))]
pub struct GeoLocation {
    /// Continent of the IP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continent: Option<Continent>,
    /// Country of the IP address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<Country>,
    /// Country in which the IP address is registered (may differ from
    /// [`Self::country`] for e.g. satellite or anycast ranges).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered_country: Option<Country>,
    /// Subdivisions, ordered from largest (e.g. state) to smallest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subdivisions: Vec<Subdivision>,
    /// Localised city name in the requested language, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<Box<str>>,
    /// Postal / ZIP code, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<Box<str>>,
    /// Approximate geographic coordinates, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Coordinates>,
    /// Autonomous system information, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autonomous_system: Option<AsOrg>,
}

impl GeoLocation {
    /// Returns `true` if no field carries any information.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.continent.is_none()
            && self.country.is_none()
            && self.registered_country.is_none()
            && self.subdivisions.is_empty()
            && self.city.is_none()
            && self.postal_code.is_none()
            && self.location.is_none()
            && self.autonomous_system.is_none()
    }

    /// Fill any field that is empty in `self` with the corresponding value
    /// from `other`; already-populated fields are left untouched. The composite
    /// `autonomous_system` and `location` are merged field-wise, so a partial
    /// value in `self` (e.g. an org without an ASN) is completed from `other`
    /// rather than blocking the merge.
    pub fn fill_gaps_from(&mut self, other: &Self) {
        // Clone `other.$field` into `self.$field` only when `self`'s is empty.
        macro_rules! fill {
            ($dst:expr, $src:expr) => {
                if $dst.is_none() {
                    $dst.clone_from(&$src);
                }
            };
        }

        fill!(self.continent, other.continent);
        fill!(self.country, other.country);
        fill!(self.registered_country, other.registered_country);
        if self.subdivisions.is_empty() {
            self.subdivisions.clone_from(&other.subdivisions);
        }
        fill!(self.city, other.city);
        fill!(self.postal_code, other.postal_code);
        if self.location.is_none() {
            self.location.clone_from(&other.location);
        } else if let (Some(mine), Some(theirs)) = (&mut self.location, &other.location) {
            if mine.accuracy_radius_km.is_none() {
                mine.accuracy_radius_km = theirs.accuracy_radius_km;
            }
            fill!(mine.time_zone, theirs.time_zone);
        }
        if self.autonomous_system.is_none() {
            self.autonomous_system.clone_from(&other.autonomous_system);
        } else if let (Some(mine), Some(theirs)) =
            (&mut self.autonomous_system, &other.autonomous_system)
        {
            fill!(mine.asn, theirs.asn);
            fill!(mine.organization, theirs.organization);
        }
    }
}

/// Encode a [`GeoLocation`] into a MaxMind-DB record, using the same field
/// layout the reader expects — so building a database from typed values
/// round-trips through [`GeoLocationRef`].
#[cfg(feature = "std")]
impl From<&GeoLocation> for MmdbValue {
    fn from(loc: &GeoLocation) -> Self {
        // A `{ sub_key: code }` map: the shared shape of continent/country
        // records, which differ only in the sub-key (`code` vs `iso_code`).
        let code_map = |sub_key: &str, code: &str| Self::map([(sub_key, Self::string(code))]);
        // A localised `{ en: name }` names sub-map.
        let en_names = |name: &str| Self::map([(keys::EN, Self::string(name))]);

        let mut record: Vec<(String, Self)> = Vec::new();
        if let Some(continent) = &loc.continent {
            record.push((
                keys::CONTINENT.to_owned(),
                code_map(keys::CODE, continent.code()),
            ));
        }
        if let Some(country) = &loc.country {
            record.push((
                keys::COUNTRY.to_owned(),
                code_map(keys::ISO_CODE, country.code()),
            ));
        }
        if let Some(country) = &loc.registered_country {
            record.push((
                keys::REGISTERED_COUNTRY.to_owned(),
                code_map(keys::ISO_CODE, country.code()),
            ));
        }
        if !loc.subdivisions.is_empty() {
            let subs = loc
                .subdivisions
                .iter()
                .map(|sd| {
                    let mut m: Vec<(String, Self)> = Vec::new();
                    if let Some(code) = &sd.iso_code {
                        m.push((keys::ISO_CODE.to_owned(), Self::string(&**code)));
                    }
                    if let Some(name) = &sd.name {
                        m.push((keys::NAMES.to_owned(), en_names(name)));
                    }
                    Self::Map(m)
                })
                .collect();
            record.push((keys::SUBDIVISIONS.to_owned(), Self::Array(subs)));
        }
        if let Some(city) = &loc.city {
            record.push((
                keys::CITY.to_owned(),
                Self::map([(keys::NAMES, en_names(city))]),
            ));
        }
        if let Some(postal) = &loc.postal_code {
            record.push((
                keys::POSTAL.to_owned(),
                Self::map([(keys::CODE, Self::string(&**postal))]),
            ));
        }
        if let Some(c) = &loc.location {
            let mut m: Vec<(String, Self)> = vec![
                (keys::LATITUDE.to_owned(), Self::Double(c.latitude)),
                (keys::LONGITUDE.to_owned(), Self::Double(c.longitude)),
            ];
            if let Some(radius) = c.accuracy_radius_km {
                m.push((keys::ACCURACY_RADIUS.to_owned(), Self::U16(radius)));
            }
            if let Some(tz) = &c.time_zone {
                m.push((keys::TIME_ZONE.to_owned(), Self::string(tz.as_str())));
            }
            record.push((keys::LOCATION.to_owned(), Self::Map(m)));
        }
        if let Some(asys) = &loc.autonomous_system {
            if let Some(asn) = asys.asn {
                record.push((keys::ASN_NUMBER.to_owned(), Self::U32(asn.as_u32())));
            }
            if let Some(org) = &asys.organization {
                record.push((keys::ASN_ORG.to_owned(), Self::string(&**org)));
            }
        }
        Self::Map(record)
    }
}

#[cfg(feature = "std")]
impl MmdbBuilder {
    /// Insert a typed [`GeoLocation`] for a network into the database.
    ///
    /// For an IPv6 database an IPv4 `net` is placed in the `::/96` range so the
    /// reader's IPv4-in-IPv6 traversal finds it.
    ///
    /// # Errors
    ///
    /// Returns [`MmdbWriteError`] if `net`'s family does not match the
    /// database, it overlaps an existing entry, or the data section grows
    /// beyond 4 GiB.
    pub fn insert(&mut self, net: IpNet, location: &GeoLocation) -> Result<(), MmdbWriteError> {
        self.insert_value(net, location)
    }
}

/// A borrowing, zero-copy view over a single decoded geolocation record.
///
/// Returned by [`MmdbReader::lookup`]. Field accessors decode lazily from the
/// backing database buffer; bounded fields are returned as `Copy` `*Ref`
/// enums and free-form fields as borrowed `&str`, so no allocation happens
/// until you call [`Self::to_owned`].
///
/// [`MmdbReader::lookup`]: super::MmdbReader::lookup
#[derive(Debug, Clone)]
pub struct GeoLocationRef<'a> {
    decoder: Decoder<'a>,
    record: usize,
    lang: &'a str,
}

impl<'a> GeoLocationRef<'a> {
    pub(crate) fn new(decoder: Decoder<'a>, record: usize, lang: &'a str) -> Self {
        Self {
            decoder,
            record,
            lang,
        }
    }

    /// The language code used to resolve localised names for this view.
    #[must_use]
    pub fn language(&self) -> &'a str {
        self.lang
    }

    /// Offset (into the record map) of the value for `key`, if present.
    fn field(&self, key: &str) -> Option<usize> {
        self.decoder.map_get(self.record, key).ok().flatten()
    }

    /// Read a string value at `container`'s `key`.
    fn sub_str(&self, container: usize, key: &str) -> Option<&'a str> {
        let off = self.decoder.map_get(container, key).ok().flatten()?;
        self.decoder.read_str(off).ok()
    }

    /// Read a string at `sub_key` within the top-level field `field_key`.
    fn field_sub_str(&self, field_key: &str, sub_key: &str) -> Option<&'a str> {
        self.sub_str(self.field(field_key)?, sub_key)
    }

    /// Offset of `key` within the `location` sub-map, if present.
    fn loc_off(&self, key: &str) -> Option<usize> {
        self.decoder
            .map_get(self.field(keys::LOCATION)?, key)
            .ok()
            .flatten()
    }

    /// Resolve a localised name from the `names` sub-map of `container`,
    /// preferring the configured language and falling back to English.
    fn pick_name(&self, container: usize) -> Option<&'a str> {
        let names = self
            .decoder
            .map_get(container, keys::NAMES)
            .ok()
            .flatten()?;
        if let Some(off) = self.decoder.map_get(names, self.lang).ok().flatten()
            && let Ok(s) = self.decoder.read_str(off)
        {
            return Some(s);
        }
        let off = self.decoder.map_get(names, keys::EN).ok().flatten()?;
        self.decoder.read_str(off).ok()
    }

    /// Continent of the IP address, if recorded.
    #[must_use]
    pub fn continent(&self) -> Option<ContinentRef<'a>> {
        Some(ContinentRef::from_code(
            self.field_sub_str(keys::CONTINENT, keys::CODE)?,
        ))
    }

    /// Country of the IP address, if recorded.
    #[must_use]
    pub fn country(&self) -> Option<CountryRef<'a>> {
        Some(CountryRef::from_code(
            self.field_sub_str(keys::COUNTRY, keys::ISO_CODE)?,
        ))
    }

    /// Registered country of the IP address, if recorded.
    #[must_use]
    pub fn registered_country(&self) -> Option<CountryRef<'a>> {
        Some(CountryRef::from_code(
            self.field_sub_str(keys::REGISTERED_COUNTRY, keys::ISO_CODE)?,
        ))
    }

    /// Localised city name, if available.
    #[must_use]
    pub fn city(&self) -> Option<&'a str> {
        self.pick_name(self.field(keys::CITY)?)
    }

    /// Postal / ZIP code, if available.
    #[must_use]
    pub fn postal_code(&self) -> Option<&'a str> {
        self.field_sub_str(keys::POSTAL, keys::CODE)
    }

    /// Approximate latitude in degrees, if available.
    #[must_use]
    pub fn latitude(&self) -> Option<f64> {
        self.decoder.read_f64(self.loc_off(keys::LATITUDE)?).ok()
    }

    /// Approximate longitude in degrees, if available.
    #[must_use]
    pub fn longitude(&self) -> Option<f64> {
        self.decoder.read_f64(self.loc_off(keys::LONGITUDE)?).ok()
    }

    /// Accuracy radius in kilometres, if available.
    #[must_use]
    pub fn accuracy_radius_km(&self) -> Option<u16> {
        self.decoder
            .read_u16(self.loc_off(keys::ACCURACY_RADIUS)?)
            .ok()
    }

    /// IANA time zone identifier, if available.
    #[must_use]
    pub fn time_zone(&self) -> Option<&'a str> {
        self.field_sub_str(keys::LOCATION, keys::TIME_ZONE)
    }

    /// Autonomous system number, if available, preserved verbatim as a
    /// [`LossyAsn`] (the value may be outside the assignable ranges).
    #[must_use]
    pub fn asn(&self) -> Option<LossyAsn> {
        let off = self.field(keys::ASN_NUMBER)?;
        self.decoder.read_u32(off).ok().map(LossyAsn::from)
    }

    /// Autonomous system organisation, if available.
    #[must_use]
    pub fn as_organization(&self) -> Option<&'a str> {
        let off = self.field(keys::ASN_ORG)?;
        self.decoder.read_str(off).ok()
    }

    fn subdivisions_owned(&self) -> Vec<Subdivision> {
        let Some(arr) = self.field(keys::SUBDIVISIONS) else {
            return Vec::new();
        };
        let Ok(elements) = self.decoder.array_offsets(arr) else {
            return Vec::new();
        };
        elements
            .into_iter()
            .filter_map(|off| {
                let iso_code = self.sub_str(off, keys::ISO_CODE).map(Box::from);
                let name = self.pick_name(off).map(Box::from);
                if iso_code.is_none() && name.is_none() {
                    None
                } else {
                    Some(Subdivision { iso_code, name })
                }
            })
            .collect()
    }

    /// Materialise this view into an owned, `'static` [`GeoLocation`].
    #[must_use]
    pub fn to_owned(&self) -> GeoLocation {
        // Resolve the location submap once and read every coordinate field from
        // it, rather than re-scanning the top-level record map per accessor.
        let location = self.field(keys::LOCATION).and_then(|loc| {
            let read_f64 = |key: &str| {
                self.decoder
                    .map_get(loc, key)
                    .ok()
                    .flatten()
                    .and_then(|o| self.decoder.read_f64(o).ok())
            };
            match (read_f64(keys::LATITUDE), read_f64(keys::LONGITUDE)) {
                (Some(latitude), Some(longitude)) => Some(Coordinates {
                    latitude,
                    longitude,
                    accuracy_radius_km: self
                        .decoder
                        .map_get(loc, keys::ACCURACY_RADIUS)
                        .ok()
                        .flatten()
                        .and_then(|o| self.decoder.read_u16(o).ok()),
                    time_zone: self.sub_str(loc, keys::TIME_ZONE).map(TimeZoneName::from),
                }),
                _ => None,
            }
        });
        // Build the AS record whenever a number OR an organisation is present;
        // `LossyAsn` preserves the number verbatim, so nothing is dropped.
        let autonomous_system = {
            let asn = self.asn();
            let organization = self.as_organization().map(Box::from);
            (asn.is_some() || organization.is_some()).then_some(AsOrg { asn, organization })
        };
        GeoLocation {
            continent: self.continent().map(|c| c.to_owned()),
            country: self.country().map(|c| c.to_owned()),
            registered_country: self.registered_country().map(|c| c.to_owned()),
            subdivisions: self.subdivisions_owned(),
            city: self.city().map(Box::from),
            postal_code: self.postal_code().map(Box::from),
            location,
            autonomous_system,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_empty_tracks_every_field() {
        assert!(GeoLocation::default().is_empty());
        let loc = GeoLocation {
            registered_country: Some(Country::France),
            ..Default::default()
        };
        assert!(!loc.is_empty(), "registered_country alone is not empty");
    }

    #[test]
    fn fill_gaps_keeps_populated_and_fills_empty() {
        let mut a = GeoLocation {
            country: Some(Country::Belgium),
            ..Default::default()
        };
        let b = GeoLocation {
            country: Some(Country::Germany),
            registered_country: Some(Country::France),
            ..Default::default()
        };
        a.fill_gaps_from(&b);
        assert_eq!(a.country, Some(Country::Belgium)); // not overwritten
        assert_eq!(a.registered_country, Some(Country::France)); // filled
    }

    #[test]
    fn fill_gaps_does_not_merge_subdivisions_elementwise() {
        let mut a = GeoLocation {
            subdivisions: vec![Subdivision {
                iso_code: Some("X".into()),
                name: None,
            }],
            ..Default::default()
        };
        let b = GeoLocation {
            subdivisions: vec![Subdivision {
                iso_code: Some("Y".into()),
                name: None,
            }],
            ..Default::default()
        };
        a.fill_gaps_from(&b);
        // self already had subdivisions, so other's are not appended
        assert_eq!(a.subdivisions.len(), 1);
        assert_eq!(a.subdivisions[0].iso_code.as_deref(), Some("X"));
    }

    #[test]
    fn fill_gaps_merges_asorg_and_coords_fieldwise() {
        let mut a = GeoLocation {
            autonomous_system: Some(AsOrg {
                asn: None,
                organization: Some("Org A".into()),
            }),
            location: Some(Coordinates {
                latitude: 1.0,
                longitude: 2.0,
                accuracy_radius_km: None,
                time_zone: None,
            }),
            ..Default::default()
        };
        let b = GeoLocation {
            autonomous_system: Some(AsOrg {
                asn: Some(LossyAsn::from(15169)),
                organization: Some("Org B".into()),
            }),
            location: Some(Coordinates {
                latitude: 9.0,
                longitude: 9.0,
                accuracy_radius_km: Some(50),
                time_zone: Some(TimeZoneName::from("Europe/Brussels")),
            }),
            ..Default::default()
        };
        a.fill_gaps_from(&b);
        let asorg = a.autonomous_system.unwrap();
        assert_eq!(asorg.asn, Some(LossyAsn::from(15169))); // filled from b
        assert_eq!(asorg.organization.as_deref(), Some("Org A")); // a's kept
        let coords = a.location.unwrap();
        assert!(coords.latitude < 5.0); // a's coordinates kept, not replaced by b's
        assert_eq!(coords.accuracy_radius_km, Some(50)); // filled from b
        assert_eq!(
            coords.time_zone,
            Some(TimeZoneName::from("Europe/Brussels"))
        ); // filled from b
    }
}
