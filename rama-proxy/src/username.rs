use super::ProxyFilter;
use rama_core::{
    error::{OpaqueError, error},
    extensions::Extensions,
    telemetry::tracing,
    username::{UsernameLabelParser, UsernameLabelState, UsernameLabelWriter},
};
use rama_utils::macros::match_ignore_ascii_case_str;

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// A parser which parses [`ProxyFilter`]s from username labels
/// and adds it to the input [`Extensions`].
///
/// [`Extensions`]: rama_core::extensions::Extensions
pub struct ProxyFilterUsernameParser {
    key: Option<ProxyFilterKey>,
    proxy_filter: ProxyFilter,
}

#[derive(Debug, Clone)]
enum ProxyFilterKey {
    Id,
    Pool,
    Continent,
    Country,
    State,
    City,
    Carrier,
    Asn,
}

impl ProxyFilterUsernameParser {
    /// Create a new [`ProxyFilterUsernameParser`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl UsernameLabelParser for ProxyFilterUsernameParser {
    type Error = OpaqueError;

    fn parse_label(&mut self, label: &str) -> UsernameLabelState {
        if let Some(key) = self.key.take() {
            match key {
                ProxyFilterKey::Id => {
                    self.proxy_filter.id = Some(match label.try_into() {
                        Ok(id) => id,
                        Err(err) => {
                            tracing::trace!(
                                "abort username label parsing: invalid parse label: {err:?}"
                            );
                            return UsernameLabelState::Abort;
                        }
                    })
                }
                ProxyFilterKey::Pool => {
                    self.proxy_filter.pool_id = match self.proxy_filter.pool_id.take() {
                        Some(mut pool_ids) => {
                            pool_ids.push(label.into());
                            Some(pool_ids)
                        }
                        None => Some(vec![label.into()]),
                    }
                }
                ProxyFilterKey::Continent => {
                    self.proxy_filter.continent = match self.proxy_filter.continent.take() {
                        Some(mut continents) => {
                            continents.push(label.into());
                            Some(continents)
                        }
                        None => Some(vec![label.into()]),
                    }
                }
                ProxyFilterKey::Country => {
                    self.proxy_filter.country = match self.proxy_filter.country.take() {
                        Some(mut countries) => {
                            countries.push(label.into());
                            Some(countries)
                        }
                        None => Some(vec![label.into()]),
                    }
                }
                ProxyFilterKey::State => {
                    self.proxy_filter.state = match self.proxy_filter.state.take() {
                        Some(mut states) => {
                            states.push(label.into());
                            Some(states)
                        }
                        None => Some(vec![label.into()]),
                    }
                }
                ProxyFilterKey::City => {
                    self.proxy_filter.city = match self.proxy_filter.city.take() {
                        Some(mut cities) => {
                            cities.push(label.into());
                            Some(cities)
                        }
                        None => Some(vec![label.into()]),
                    }
                }
                ProxyFilterKey::Carrier => {
                    self.proxy_filter.carrier = match self.proxy_filter.carrier.take() {
                        Some(mut carriers) => {
                            carriers.push(label.into());
                            Some(carriers)
                        }
                        None => Some(vec![label.into()]),
                    }
                }
                ProxyFilterKey::Asn => {
                    let asn = match label.try_into() {
                        Ok(asn) => asn,
                        Err(err) => {
                            tracing::trace!(
                                "failed to parse asn username label; abort username parsing: {err:?}"
                            );
                            return UsernameLabelState::Abort;
                        }
                    };
                    self.proxy_filter.asn = match self.proxy_filter.asn.take() {
                        Some(mut asns) => {
                            asns.push(asn);
                            Some(asns)
                        }
                        None => Some(vec![asn]),
                    }
                }
            }
        } else {
            // allow bool-keys to be negated
            let (key, bval) = if let Some(key) = label.strip_prefix('!') {
                (key, false)
            } else {
                (label, true)
            };

            match_ignore_ascii_case_str! {
                match(key) {
                    "datacenter" => self.proxy_filter.datacenter = Some(bval),
                    "residential" => self.proxy_filter.residential = Some(bval),
                    "mobile" => self.proxy_filter.mobile = Some(bval),
                    "id" => self.key = Some(ProxyFilterKey::Id),
                    "pool" => self.key = Some(ProxyFilterKey::Pool),
                    "continent" => self.key = Some(ProxyFilterKey::Continent),
                    "country" => self.key = Some(ProxyFilterKey::Country),
                    "state" => self.key = Some(ProxyFilterKey::State),
                    "city" => self.key = Some(ProxyFilterKey::City),
                    "carrier" => self.key = Some(ProxyFilterKey::Carrier),
                    "asn" => self.key = Some(ProxyFilterKey::Asn),
                    _ => return UsernameLabelState::Ignored,
                }
            }

            if !bval && self.key.take().is_some() {
                // negation only possible for standalone labels
                return UsernameLabelState::Ignored;
            }
        }

        UsernameLabelState::Used
    }

    fn build(self, ext: &mut Extensions) -> Result<(), Self::Error> {
        if let Some(key) = self.key {
            return Err(error!("unused proxy filter username key: {:?}", key));
        }
        if self.proxy_filter != ProxyFilter::default() {
            ext.insert(self.proxy_filter);
        }
        Ok(())
    }
}

impl<const SEPARATOR: char> UsernameLabelWriter<SEPARATOR> for ProxyFilter {
    fn write_labels(
        &self,
        composer: &mut rama_core::username::Composer<SEPARATOR>,
    ) -> Result<(), rama_core::username::ComposeError> {
        if let Some(id) = &self.id {
            composer.write_label("id")?;
            composer.write_label(id)?;
        }

        if let Some(pool_id_vec) = &self.pool_id {
            for pool_id in pool_id_vec {
                composer.write_label("pool")?;
                composer.write_label(pool_id.as_ref())?;
            }
        }

        if let Some(continent_vec) = &self.continent {
            for continent in continent_vec {
                composer.write_label("continent")?;
                composer.write_label(continent.as_ref())?;
            }
        }

        if let Some(country_vec) = &self.country {
            for country in country_vec {
                composer.write_label("country")?;
                composer.write_label(country.as_ref())?;
            }
        }

        if let Some(state_vec) = &self.state {
            for state in state_vec {
                composer.write_label("state")?;
                composer.write_label(state.as_ref())?;
            }
        }

        if let Some(city_vec) = &self.city {
            for city in city_vec {
                composer.write_label("city")?;
                composer.write_label(city.as_ref())?;
            }
        }

        if let Some(datacenter) = &self.datacenter {
            if *datacenter {
                composer.write_label("datacenter")?;
            } else {
                composer.write_label("!datacenter")?;
            }
        }

        if let Some(residential) = &self.residential {
            if *residential {
                composer.write_label("residential")?;
            } else {
                composer.write_label("!residential")?;
            }
        }

        if let Some(mobile) = &self.mobile {
            if *mobile {
                composer.write_label("mobile")?;
            } else {
                composer.write_label("!mobile")?;
            }
        }

        if let Some(carrier_vec) = &self.carrier {
            for carrier in carrier_vec {
                composer.write_label("carrier")?;
                composer.write_label(carrier.as_ref())?;
            }
        }

        if let Some(asn_vec) = &self.asn {
            for asn in asn_vec {
                composer.write_label("asn")?;
                composer.write_label(asn.as_u32().to_string())?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StringFilter;
    use rama_core::username::{compose_username, parse_username};
    use rama_net::asn::Asn;
    use rama_utils::str::non_empty_str;

    #[test]
    fn test_username_config() {
        let test_cases = [
            ("john", String::from("john"), None),
            (
                "john-datacenter",
                String::from("john"),
                Some(ProxyFilter {
                    datacenter: Some(true),
                    ..Default::default()
                }),
            ),
            (
                "john-!datacenter",
                String::from("john"),
                Some(ProxyFilter {
                    datacenter: Some(false),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter",
                String::from("john"),
                Some(ProxyFilter {
                    country: Some(vec!["us".into()]),
                    datacenter: Some(true),
                    ..Default::default()
                }),
            ),
            (
                "john-city-tokyo-residential",
                String::from("john"),
                Some(ProxyFilter {
                    city: Some(vec!["tokyo".into()]),
                    residential: Some(true),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter-pool-1",
                String::from("john"),
                Some(ProxyFilter {
                    pool_id: Some(vec![StringFilter::from("1")]),
                    country: Some(vec![StringFilter::from("us")]),
                    datacenter: Some(true),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential",
                String::from("john"),
                Some(ProxyFilter {
                    pool_id: Some(vec![StringFilter::from("1")]),
                    country: Some(vec![StringFilter::from("us")]),
                    datacenter: Some(true),
                    residential: Some(true),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile",
                String::from("john"),
                Some(ProxyFilter {
                    pool_id: Some(vec![StringFilter::from("1")]),
                    country: Some(vec![StringFilter::from("us")]),
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(true),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-!mobile",
                String::from("john"),
                Some(ProxyFilter {
                    pool_id: Some(vec![StringFilter::from("1")]),
                    country: Some(vec![StringFilter::from("us")]),
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(false),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-city-california-datacenter-pool-1-!residential-mobile",
                String::from("john"),
                Some(ProxyFilter {
                    pool_id: Some(vec![StringFilter::from("1")]),
                    country: Some(vec![StringFilter::from("us")]),
                    city: Some(vec![StringFilter::from("california")]),
                    datacenter: Some(true),
                    residential: Some(false),
                    mobile: Some(true),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile-id-1",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(non_empty_str!("1")),
                    pool_id: Some(vec![StringFilter::from("1")]),
                    country: Some(vec![StringFilter::from("us")]),
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(true),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile-carrier-bar-id-1",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(non_empty_str!("1")),
                    pool_id: Some(vec![StringFilter::from("1")]),
                    country: Some(vec![StringFilter::from("us")]),
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(true),
                    carrier: Some(vec![StringFilter::from("bar")]),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile-id-1-country-uk",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(non_empty_str!("1")),
                    pool_id: Some(vec![StringFilter::from("1")]),
                    country: Some(vec![StringFilter::from("us"), StringFilter::from("uk")]),
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(true),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-!datacenter-pool-1-residential-mobile-id-1-country-uk",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(non_empty_str!("1")),
                    pool_id: Some(vec![StringFilter::from("1")]),
                    country: Some(vec![StringFilter::from("us"), StringFilter::from("uk")]),
                    datacenter: Some(false),
                    residential: Some(true),
                    mobile: Some(true),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile-id-1-country-uk-pool-2",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(non_empty_str!("1")),
                    pool_id: Some(vec![StringFilter::from("1"), StringFilter::from("2")]),
                    country: Some(vec![StringFilter::from("us"), StringFilter::from("uk")]),
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(true),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-!residential-mobile-id-1-country-uk-pool-2",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(non_empty_str!("1")),
                    pool_id: Some(vec![StringFilter::from("1"), StringFilter::from("2")]),
                    country: Some(vec![StringFilter::from("us"), StringFilter::from("uk")]),
                    datacenter: Some(true),
                    residential: Some(false),
                    mobile: Some(true),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile-id-1-country-uk-pool-2-datacenter",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(non_empty_str!("1")),
                    pool_id: Some(vec![StringFilter::from("1"), StringFilter::from("2")]),
                    country: Some(vec![StringFilter::from("us"), StringFilter::from("uk")]),
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(true),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile-id-1-country-uk-pool-2-datacenter-residential",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(non_empty_str!("1")),
                    pool_id: Some(vec![StringFilter::from("1"), StringFilter::from("2")]),
                    country: Some(vec![StringFilter::from("us"), StringFilter::from("uk")]),
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(true),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile-id-1-country-uk-pool-2-datacenter-residential-mobile",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(non_empty_str!("1")),
                    pool_id: Some(vec![StringFilter::from("1"), StringFilter::from("2")]),
                    country: Some(vec![StringFilter::from("us"), StringFilter::from("uk")]),
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(true),
                    ..Default::default()
                }),
            ),
            (
                "john-continent-americas-country-us-state-NY-city-ny-asn-7018",
                String::from("john"),
                Some(ProxyFilter {
                    continent: Some(vec![StringFilter::from("americas")]),
                    country: Some(vec![StringFilter::from("us")]),
                    state: Some(vec![StringFilter::from("ny")]),
                    city: Some(vec![StringFilter::from("ny")]),
                    asn: Some(vec![Asn::from_static(7018)]),
                    ..Default::default()
                }),
            ),
            (
                "john-continent-europe-continent-asia",
                String::from("john"),
                Some(ProxyFilter {
                    continent: Some(vec![
                        StringFilter::from("europe"),
                        StringFilter::from("asia"),
                    ]),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile-id-1-country-uk-pool-2-!datacenter-!residential-!mobile",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(non_empty_str!("1")),
                    pool_id: Some(vec![StringFilter::from("1"), StringFilter::from("2")]),
                    country: Some(vec![StringFilter::from("us"), StringFilter::from("uk")]),
                    datacenter: Some(false),
                    residential: Some(false),
                    mobile: Some(false),
                    ..Default::default()
                }),
            ),
        ];

        for (username, expected_username, expected_filter) in test_cases.into_iter() {
            let mut ext = Extensions::default();

            let parser = ProxyFilterUsernameParser::default();

            let username = parse_username(&mut ext, parser, username).unwrap();
            let filter = ext.get::<ProxyFilter>().cloned();
            assert_eq!(
                username, expected_username,
                "username = '{username}' ; expected_username = '{expected_username}'",
            );
            assert_eq!(
                filter, expected_filter,
                "username = '{username}' ; expected_username = '{expected_username}'",
            );
        }
    }

    #[test]
    fn test_username_config_error() {
        for username in [
            "john-country-us-datacenter-",
            "",
            "-",
            "john-country-us-datacenter-pool",
            "john-foo",
            "john-foo-country",
            "john-country",
            "john-id-", // empty id is invalid
        ] {
            let mut ext = Extensions::default();

            let parser = ProxyFilterUsernameParser::default();

            assert!(
                parse_username(&mut ext, parser, username).is_err(),
                "username = {username}",
            );
        }
    }

    #[test]
    fn test_username_negation_key_failures() {
        for username in [
            "john-!id-a",
            "john-!pool-b",
            "john-!country-us",
            "john-!city-ny",
            "john-!carrier-c",
        ] {
            let mut ext = Extensions::default();

            let parser = ProxyFilterUsernameParser::default();

            assert!(
                parse_username(&mut ext, parser, username).is_err(),
                "username = {username}",
            );
        }
    }

    #[test]
    fn test_username_compose_parser_proxy_filter() {
        let test_cases = [
            ProxyFilter::default(),
            ProxyFilter {
                id: Some(non_empty_str!("p42")),
                ..Default::default()
            },
            ProxyFilter {
                id: Some(non_empty_str!("1")),
                pool_id: Some(vec![StringFilter::from("1")]),
                country: Some(vec![StringFilter::from("us"), StringFilter::from("uk")]),
                datacenter: Some(false),
                residential: Some(true),
                mobile: Some(true),
                ..Default::default()
            },
            ProxyFilter {
                id: Some(non_empty_str!("1")),
                pool_id: Some(vec![StringFilter::from("1"), StringFilter::from("2")]),
                country: Some(vec![StringFilter::from("us"), StringFilter::from("uk")]),
                datacenter: Some(false),
                residential: Some(false),
                mobile: Some(false),
                ..Default::default()
            },
            ProxyFilter {
                id: Some(non_empty_str!("a")),
                pool_id: Some(vec![StringFilter::from("1"), StringFilter::from("2")]),
                continent: Some(vec![StringFilter::from("na"), StringFilter::from("eu")]),
                country: Some(vec![StringFilter::from("us"), StringFilter::from("be")]),
                state: Some(vec![
                    StringFilter::from("ca"),
                    StringFilter::from("ny"),
                    StringFilter::from("ovl"),
                ]),
                city: Some(vec![
                    StringFilter::from("berkeley"),
                    StringFilter::from("bruxelles"),
                    StringFilter::from("gent"),
                ]),
                datacenter: Some(false),
                residential: Some(true),
                mobile: Some(true),
                carrier: Some(vec![
                    StringFilter::from("at&t"),
                    StringFilter::from("orange"),
                ]),
                asn: Some(vec![Asn::from_static(7018), Asn::from_static(1)]),
            },
        ];

        for test_case in test_cases {
            let fmt_username = compose_username("john".to_owned(), &test_case).unwrap();
            let mut ext = Extensions::new();
            let username = parse_username(
                &mut ext,
                ProxyFilterUsernameParser::default(),
                &fmt_username,
            )
            .unwrap_or_else(|_| panic!("to be ok: {fmt_username}"));
            assert_eq!("john", username);
            if test_case == Default::default() {
                assert!(!ext.contains::<ProxyFilter>());
            } else {
                let result = ext.get::<ProxyFilter>().unwrap();
                assert_eq!(test_case, *result);
            }
        }
    }
}
