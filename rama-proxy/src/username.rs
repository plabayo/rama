use super::{ProxyFilter, ProxyType};
use rama_core::error::BoxErrorExt as _;
use rama_core::{
    error::{BoxError, ErrorExt},
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
    type Error = BoxError;

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
            let key = match_ignore_ascii_case_str! {
                match(label) {
                    "id" => ProxyFilterKey::Id,
                    "pool" => ProxyFilterKey::Pool,
                    "continent" => ProxyFilterKey::Continent,
                    "country" => ProxyFilterKey::Country,
                    "state" => ProxyFilterKey::State,
                    "city" => ProxyFilterKey::City,
                    "carrier" => ProxyFilterKey::Carrier,
                    "asn" => ProxyFilterKey::Asn,
                    _ => {
                        let Ok(kind) = label.parse::<ProxyType>() else {
                            return UsernameLabelState::Ignored;
                        };
                        self.proxy_filter.kind.get_or_insert_default().push(kind);
                        return UsernameLabelState::Used;
                    }
                }
            };
            self.key = Some(key);
        }

        UsernameLabelState::Used
    }

    fn build(self, ext: &Extensions) -> Result<(), Self::Error> {
        if let Some(key) = self.key {
            return Err(
                BoxError::from_static_str("unused proxy filter username key")
                    .context_debug_field("key", key),
            );
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

        if let Some(kinds) = &self.kind {
            for kind in kinds {
                composer.write_label(kind.as_str())?;
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
                    kind: Some(vec![ProxyType::Datacenter]),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter",
                String::from("john"),
                Some(ProxyFilter {
                    country: Some(vec!["us".into()]),
                    kind: Some(vec![ProxyType::Datacenter]),
                    ..Default::default()
                }),
            ),
            (
                "john-city-tokyo-residential",
                String::from("john"),
                Some(ProxyFilter {
                    city: Some(vec!["tokyo".into()]),
                    kind: Some(vec![ProxyType::Residential]),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter-pool-1",
                String::from("john"),
                Some(ProxyFilter {
                    pool_id: Some(vec![StringFilter::from("1")]),
                    country: Some(vec![StringFilter::from("us")]),
                    kind: Some(vec![ProxyType::Datacenter]),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential",
                String::from("john"),
                Some(ProxyFilter {
                    pool_id: Some(vec![StringFilter::from("1")]),
                    country: Some(vec![StringFilter::from("us")]),
                    kind: Some(vec![ProxyType::Datacenter, ProxyType::Residential]),
                    ..Default::default()
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile",
                String::from("john"),
                Some(ProxyFilter {
                    pool_id: Some(vec![StringFilter::from("1")]),
                    country: Some(vec![StringFilter::from("us")]),
                    kind: Some(vec![
                        ProxyType::Datacenter,
                        ProxyType::Residential,
                        ProxyType::Mobile,
                    ]),
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
                    kind: Some(vec![
                        ProxyType::Datacenter,
                        ProxyType::Residential,
                        ProxyType::Mobile,
                    ]),
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
                    kind: Some(vec![
                        ProxyType::Datacenter,
                        ProxyType::Residential,
                        ProxyType::Mobile,
                    ]),
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
                    kind: Some(vec![
                        ProxyType::Datacenter,
                        ProxyType::Residential,
                        ProxyType::Mobile,
                    ]),
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
                    kind: Some(vec![
                        ProxyType::Datacenter,
                        ProxyType::Residential,
                        ProxyType::Mobile,
                    ]),
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
                    kind: Some(vec![
                        ProxyType::Datacenter,
                        ProxyType::Residential,
                        ProxyType::Mobile,
                        ProxyType::Datacenter,
                    ]),
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
                    kind: Some(vec![
                        ProxyType::Datacenter,
                        ProxyType::Residential,
                        ProxyType::Mobile,
                        ProxyType::Datacenter,
                        ProxyType::Residential,
                    ]),
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
                    kind: Some(vec![
                        ProxyType::Datacenter,
                        ProxyType::Residential,
                        ProxyType::Mobile,
                        ProxyType::Datacenter,
                        ProxyType::Residential,
                        ProxyType::Mobile,
                    ]),
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
        ];

        for (username, expected_username, expected_filter) in test_cases.into_iter() {
            let ext = Extensions::default();

            let parser = ProxyFilterUsernameParser::default();

            let username = parse_username(&ext, parser, username).unwrap();
            let filter = ext.get_ref::<ProxyFilter>().cloned();
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
            "john-!datacenter",
            "john-foo",
            "john-foo-country",
            "john-country",
            "john-id-", // empty id is invalid
        ] {
            let ext = Extensions::default();

            let parser = ProxyFilterUsernameParser::default();

            assert!(
                parse_username(&ext, parser, username).is_err(),
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
            let ext = Extensions::default();

            let parser = ProxyFilterUsernameParser::default();

            assert!(
                parse_username(&ext, parser, username).is_err(),
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
                kind: Some(vec![ProxyType::Residential, ProxyType::Mobile]),
                ..Default::default()
            },
            ProxyFilter {
                id: Some(non_empty_str!("1")),
                pool_id: Some(vec![StringFilter::from("1"), StringFilter::from("2")]),
                country: Some(vec![StringFilter::from("us"), StringFilter::from("uk")]),
                kind: Some(vec![ProxyType::Isp]),
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
                kind: Some(vec![ProxyType::Residential, ProxyType::Mobile]),
                carrier: Some(vec![
                    StringFilter::from("at&t"),
                    StringFilter::from("orange"),
                ]),
                asn: Some(vec![Asn::from_static(7018), Asn::from_static(1)]),
            },
        ];

        for test_case in test_cases {
            let fmt_username = compose_username("john".to_owned(), &test_case).unwrap();
            let ext = Extensions::new();
            let username =
                parse_username(&ext, ProxyFilterUsernameParser::default(), &fmt_username)
                    .unwrap_or_else(|_| panic!("to be ok: {fmt_username}"));
            assert_eq!("john", username);
            if test_case == Default::default() {
                assert!(!ext.contains::<ProxyFilter>());
            } else {
                let result = ext.get_ref::<ProxyFilter>().unwrap();
                assert_eq!(test_case, *result);
            }
        }
    }
}
