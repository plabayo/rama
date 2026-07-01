//! Continent identity, keyed by the two-letter codes used by common
//! geolocation databases.
//!
//! Source: the continent codes used by MaxMind GeoIP2 / GeoLite2 and
//! DB-IP (`AF`, `AN`, `AS`, `EU`, `NA`, `OC`, `SA`).

use super::builder::geo_enum;

geo_enum! {
    /// A continent, identified by its two-letter geolocation code.
    ///
    /// The owned form encodes identity only; the database's localised name is
    /// not retained. Use [`Continent::name`] for the canonical English name.
    pub enum Continent / ContinentRef {
        Africa => "AF", "Africa",
        Antarctica => "AN", "Antarctica",
        Asia => "AS", "Asia",
        Europe => "EU", "Europe",
        NorthAmerica => "NA", "North America",
        Oceania => "OC", "Oceania",
        SouthAmerica => "SA", "South America",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_and_unknown() {
        assert_eq!(Continent::from_code("EU"), Continent::Europe);
        assert_eq!(Continent::Europe.code(), "EU");
        assert_eq!(Continent::Europe.name(), Some("Europe"));
        assert!(Continent::Europe.is_known());

        let unknown = Continent::from_code("ZZ");
        assert_eq!(unknown, Continent::Unknown("ZZ".into()));
        assert_eq!(unknown.code(), "ZZ");
        assert_eq!(unknown.name(), None);
        assert!(!unknown.is_known());
    }

    #[cfg(feature = "std")]
    #[test]
    fn ref_roundtrip_and_serde() {
        let r = ContinentRef::from_code("NA");
        assert_eq!(r, ContinentRef::NorthAmerica);
        assert_eq!(r.code(), "NA");
        assert_eq!(r.to_owned(), Continent::NorthAmerica);

        let json = serde_json::to_string(&Continent::Africa).unwrap();
        assert_eq!(json, "\"AF\"");
        let back: Continent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Continent::Africa);
    }
}
