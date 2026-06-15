//! Geolocation result types: an owned [`GeoLocation`] and a borrowing,
//! zero-copy [`GeoLocationRef`] view over a MaxMind DB record.
//!
//! Bounded fields use the shared typed enums from [`rama_core::geo`]
//! ([`Continent`], [`Country`]); free-form fields use `std` string types.

use std::fmt;

use rama_core::geo::{Continent, ContinentRef, Country, CountryRef};
use serde::{Deserialize, Serialize};

use crate::asn::LossyAsn;

use super::mmdb::decoder::Decoder;

/// An IANA time-zone identifier (e.g. `"Europe/Brussels"`), stored verbatim.
///
/// This carries no time-zone-database cost and no third-party dependency;
/// resolve it to a live zone yourself when needed, e.g. with
/// `jiff::tz::TimeZone::get(tz.as_str())`.
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, rama_core::extensions::Extension)]
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
    /// from `other`; already-populated fields are left untouched.
    pub fn fill_gaps_from(&mut self, other: &Self) {
        if self.continent.is_none() {
            self.continent.clone_from(&other.continent);
        }
        if self.country.is_none() {
            self.country.clone_from(&other.country);
        }
        if self.registered_country.is_none() {
            self.registered_country
                .clone_from(&other.registered_country);
        }
        if self.subdivisions.is_empty() {
            self.subdivisions.clone_from(&other.subdivisions);
        }
        if self.city.is_none() {
            self.city.clone_from(&other.city);
        }
        if self.postal_code.is_none() {
            self.postal_code.clone_from(&other.postal_code);
        }
        if self.location.is_none() {
            self.location.clone_from(&other.location);
        }
        if self.autonomous_system.is_none() {
            self.autonomous_system.clone_from(&other.autonomous_system);
        }
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

    /// Resolve a localised name from the `names` sub-map of `container`,
    /// preferring the configured language and falling back to English.
    fn pick_name(&self, container: usize) -> Option<&'a str> {
        let names = self.decoder.map_get(container, "names").ok().flatten()?;
        if let Some(off) = self.decoder.map_get(names, self.lang).ok().flatten()
            && let Ok(s) = self.decoder.read_str(off)
        {
            return Some(s);
        }
        let off = self.decoder.map_get(names, "en").ok().flatten()?;
        self.decoder.read_str(off).ok()
    }

    /// Continent of the IP address, if recorded.
    #[must_use]
    pub fn continent(&self) -> Option<ContinentRef<'a>> {
        let code = self.sub_str(self.field("continent")?, "code")?;
        Some(ContinentRef::from_code(code))
    }

    /// Country of the IP address, if recorded.
    #[must_use]
    pub fn country(&self) -> Option<CountryRef<'a>> {
        let code = self.sub_str(self.field("country")?, "iso_code")?;
        Some(CountryRef::from_code(code))
    }

    /// Registered country of the IP address, if recorded.
    #[must_use]
    pub fn registered_country(&self) -> Option<CountryRef<'a>> {
        let code = self.sub_str(self.field("registered_country")?, "iso_code")?;
        Some(CountryRef::from_code(code))
    }

    /// Localised city name, if available.
    #[must_use]
    pub fn city(&self) -> Option<&'a str> {
        self.pick_name(self.field("city")?)
    }

    /// Postal / ZIP code, if available.
    #[must_use]
    pub fn postal_code(&self) -> Option<&'a str> {
        self.sub_str(self.field("postal")?, "code")
    }

    /// Approximate latitude in degrees, if available.
    #[must_use]
    pub fn latitude(&self) -> Option<f64> {
        let loc = self.field("location")?;
        let off = self.decoder.map_get(loc, "latitude").ok().flatten()?;
        self.decoder.read_f64(off).ok()
    }

    /// Approximate longitude in degrees, if available.
    #[must_use]
    pub fn longitude(&self) -> Option<f64> {
        let loc = self.field("location")?;
        let off = self.decoder.map_get(loc, "longitude").ok().flatten()?;
        self.decoder.read_f64(off).ok()
    }

    /// Accuracy radius in kilometres, if available.
    #[must_use]
    pub fn accuracy_radius_km(&self) -> Option<u16> {
        let loc = self.field("location")?;
        let off = self
            .decoder
            .map_get(loc, "accuracy_radius")
            .ok()
            .flatten()?;
        self.decoder.read_u16(off).ok()
    }

    /// IANA time zone identifier, if available.
    #[must_use]
    pub fn time_zone(&self) -> Option<&'a str> {
        self.sub_str(self.field("location")?, "time_zone")
    }

    /// Autonomous system number, if available, preserved verbatim as a
    /// [`LossyAsn`] (the value may be outside the assignable ranges).
    #[must_use]
    pub fn asn(&self) -> Option<LossyAsn> {
        let off = self.field("autonomous_system_number")?;
        self.decoder.read_u32(off).ok().map(LossyAsn::from)
    }

    /// Autonomous system organisation, if available.
    #[must_use]
    pub fn as_organization(&self) -> Option<&'a str> {
        let off = self.field("autonomous_system_organization")?;
        self.decoder.read_str(off).ok()
    }

    fn subdivisions_owned(&self) -> Vec<Subdivision> {
        let Some(arr) = self.field("subdivisions") else {
            return Vec::new();
        };
        let Ok(elements) = self.decoder.array_offsets(arr) else {
            return Vec::new();
        };
        elements
            .into_iter()
            .filter_map(|off| {
                let iso_code = self.sub_str(off, "iso_code").map(Box::from);
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
        let location = match (self.latitude(), self.longitude()) {
            (Some(latitude), Some(longitude)) => Some(Coordinates {
                latitude,
                longitude,
                accuracy_radius_km: self.accuracy_radius_km(),
                time_zone: self.time_zone().map(TimeZoneName::from),
            }),
            _ => None,
        };
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
