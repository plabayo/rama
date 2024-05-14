use super::ProxyFilter;
use crate::{
    error::{error, OpaqueError},
    service::Context,
    utils::username::{UsernameLabelParser, UsernameLabelParserLayer, UsernameLabelState},
};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// A parser which parses [`ProxyFilter`]s from username labels
/// and adds it to the [`Context`]'s [`Extensions`].
///
/// [`Extensions`]: crate::service::context::Extensions
pub struct ProxyFilterUsernameParser {
    key: Option<ProxyFilterKey>,
    proxy_filter: ProxyFilter,
}

#[derive(Debug, Clone)]
enum ProxyFilterKey {
    Id,
    Pool,
    Country,
    City,
    Carrier,
}

impl ProxyFilterUsernameParser {
    /// Create a new [`ProxyFilterUsernameParser`].
    pub fn new() -> Self {
        Self::default()
    }
}

impl<State, Request> UsernameLabelParserLayer<State, Request> for ProxyFilterUsernameParser {
    type Parser = Self;

    fn create_parser(&self, _ctx: &Context<State>, _req: &Request) -> Self::Parser {
        Self::default()
    }
}

impl<State, Request> UsernameLabelParser<State, Request> for ProxyFilterUsernameParser {
    type Error = OpaqueError;

    fn parse_label(
        &mut self,
        _ctx: &Context<State>,
        _req: &Request,
        label: &str,
    ) -> UsernameLabelState {
        match self.key.take() {
            Some(key) => match key {
                ProxyFilterKey::Id => self.proxy_filter.id = Some(label.to_owned()),
                ProxyFilterKey::Pool => self.proxy_filter.pool_id = Some(label.into()),
                ProxyFilterKey::Country => self.proxy_filter.country = Some(label.into()),
                ProxyFilterKey::City => self.proxy_filter.city = Some(label.into()),
                ProxyFilterKey::Carrier => self.proxy_filter.carrier = Some(label.into()),
            },
            None => {
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
                        "country" => self.key = Some(ProxyFilterKey::Country),
                        "city" => self.key = Some(ProxyFilterKey::City),
                        "carrier" => self.key = Some(ProxyFilterKey::Carrier),
                        _ => return UsernameLabelState::Ignored,
                    }
                }

                if !bval && self.key.take().is_some() {
                    // negation only possible for standalone labels
                    return UsernameLabelState::Ignored;
                }
            }
        }

        UsernameLabelState::Used
    }

    fn build(self, ctx: &mut Context<State>, _req: &mut Request) -> Result<(), Self::Error> {
        if let Some(key) = self.key {
            return Err(error!("unused proxy filter username key: {:?}", key));
        }
        if self.proxy_filter != ProxyFilter::default() {
            ctx.insert(self.proxy_filter);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{proxy::StringFilter, utils::username::parse_username};

    #[test]
    fn test_username_config() {
        let test_cases = [
            (
                "john",
                String::from("john"),
                None,
            ),
            (
                "john-datacenter",
                String::from("john"),
                Some(ProxyFilter {
                    id: None,
                    pool_id: None,
                    country: None,
                    city: None,
                    datacenter: Some(true),
                    residential: None,
                    mobile: None,
                    carrier: None,
                })
            ),
            (
                "john-!datacenter",
                String::from("john"),
                Some(ProxyFilter {
                        id: None,
                        pool_id: None,
                        country: None,
                        city: None,
                        datacenter: Some(false),
                        residential: None,
                        mobile: None,
                        carrier: None,
                }),
            ),
            (
                "john-country-us-datacenter",
                String::from("john"),
                Some(ProxyFilter {
                    id: None,
                    pool_id: None,
                    country: Some(StringFilter::from("us")),
                    city: None,
                    datacenter: Some(true),
                    residential: None,
                    mobile: None,
                    carrier: None,
                }),
            ),
            (
                "john-city-tokyo-residential",
                String::from("john"),
                Some(ProxyFilter {
                    id: None,
                    pool_id: None,
                    country: None,
                    city: Some("tokyo".into()),
                    datacenter: None,
                    residential: Some(true),
                    mobile: None,
                    carrier: None,
                }),
            ),
            (
                "john-country-us-datacenter-pool-1",
                String::from("john"),
                Some(ProxyFilter {
                    id: None,
                    pool_id: Some(StringFilter::from("1")),
                    country: Some(StringFilter::from("us")),
                    city: None,
                    datacenter: Some(true),
                    residential: None,
                    mobile: None,
                    carrier: None,
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential",
                String::from("john"),
                Some(ProxyFilter {
                    id: None,
                    pool_id: Some(StringFilter::from("1")),
                    country: Some(StringFilter::from("us")),
                    city: None,
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: None,
                    carrier: None,
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile",
                String::from("john"),
                Some(ProxyFilter {
                    id: None,
                    pool_id: Some(StringFilter::from("1")),
                    country: Some(StringFilter::from("us")),
                    city: None,
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(true),
                    carrier: None,
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-!mobile",
                String::from("john"),
                Some(ProxyFilter {
                    id: None,
                    pool_id: Some(StringFilter::from("1")),
                    country: Some(StringFilter::from("us")),
                    city: None,
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(false),
                    carrier: None,
                }),
            ),
            (
                "john-country-us-city-california-datacenter-pool-1-!residential-mobile",
                String::from("john"),
                Some(ProxyFilter {
                    id: None,
                    pool_id: Some(StringFilter::from("1")),
                    country: Some(StringFilter::from("us")),
                    city: Some(StringFilter::from("california")),
                    datacenter: Some(true),
                    residential: Some(false),
                    mobile: Some(true),
                    carrier: None,
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile-id-1",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(String::from("1")),
                    pool_id: Some(StringFilter::from("1")),
                    country: Some(StringFilter::from("us")),
                    city: None,
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(true),
                    carrier: None,
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile-carrier-bar-id-1",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(String::from("1")),
                    pool_id: Some(StringFilter::from("1")),
                    country: Some(StringFilter::from("us")),
                    city: None,
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(true),
                    carrier: Some(StringFilter::from("bar")),
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile-id-1-country-uk",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(String::from("1")),
                    pool_id: Some(StringFilter::from("1")),
                    country: Some(StringFilter::from("uk")),
                    city: None,
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(true),
                    carrier: None,
                }),
            ),
            (
                "john-country-us-!datacenter-pool-1-residential-mobile-id-1-country-uk",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(String::from("1")),
                    pool_id: Some(StringFilter::from("1")),
                    country: Some(StringFilter::from("uk")),
                    city: None,
                    datacenter: Some(false),
                    residential: Some(true),
                    mobile: Some(true),
                    carrier: None,
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile-id-1-country-uk-pool-2",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(String::from("1")),
                    pool_id: Some(StringFilter::from("2")),
                    country: Some(StringFilter::from("uk")),
                    city: None,
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(true),
                    carrier: None,
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-!residential-mobile-id-1-country-uk-pool-2",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(String::from("1")),
                    pool_id: Some(StringFilter::from("2")),
                    country: Some(StringFilter::from("uk")),
                    city: None,
                    datacenter: Some(true),
                    residential: Some(false),
                    mobile: Some(true),
                    carrier: None,
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile-id-1-country-uk-pool-2-datacenter",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(String::from("1")),
                    pool_id: Some(StringFilter::from("2")),
                    country: Some(StringFilter::from("uk")),
                    city: None,
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(true),
                    carrier: None,
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile-id-1-country-uk-pool-2-datacenter-residential",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(String::from("1")),
                    pool_id: Some(StringFilter::from("2")),
                    country: Some(StringFilter::from("uk")),
                    city: None,
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(true),
                    carrier: None,
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile-id-1-country-uk-pool-2-datacenter-residential-mobile",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(String::from("1")),
                    pool_id: Some(StringFilter::from("2")),
                    country: Some(StringFilter::from("uk")),
                    city: None,
                    datacenter: Some(true),
                    residential: Some(true),
                    mobile: Some(true),
                    carrier: None,
                }),
            ),
            (
                "john-country-us-datacenter-pool-1-residential-mobile-id-1-country-uk-pool-2-!datacenter-!residential-!mobile",
                String::from("john"),
                Some(ProxyFilter {
                    id: Some(String::from("1")),
                    pool_id: Some(StringFilter::from("2")),
                    country: Some(StringFilter::from("uk")),
                    city: None,
                    datacenter: Some(false),
                    residential: Some(false),
                    mobile: Some(false),
                    carrier: None,
                }),
            ),
        ];

        for (username, expected_username, expected_filter) in test_cases.into_iter() {
            let mut ctx = Context::default();
            let mut req = ();

            let parser = ProxyFilterUsernameParser::default();

            let username = parse_username(&mut ctx, &mut req, parser, username, '-').unwrap();
            let filter = ctx.get::<ProxyFilter>().cloned();
            assert_eq!(
                username, expected_username,
                "username = '{}' ; expected_username = '{}'",
                username, expected_username
            );
            assert_eq!(
                filter, expected_filter,
                "username = '{}' ; expected_username = '{}'",
                username, expected_username
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
        ] {
            let mut ctx = Context::default();
            let mut req = ();

            let parser = ProxyFilterUsernameParser::default();

            assert!(
                parse_username(&mut ctx, &mut req, parser, username, '-').is_err(),
                "username = {}",
                username
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
            let mut ctx = Context::default();
            let mut req = ();

            let parser = ProxyFilterUsernameParser::default();

            assert!(
                parse_username(&mut ctx, &mut req, parser, username, '-').is_err(),
                "username = {}",
                username
            );
        }
    }
}
