//! Username configuration facility for transport-layer proxy authentication.

use std::{fmt, str::FromStr};

use super::ProxyFilter;

#[derive(Debug, Clone)]
/// A username from which the [`ProxyFilter`]` is extracted and parsed.
///
/// The username is expected to be in the following format:
///
/// ```text
/// username[-key1[-value1]][-key2[-value2]]...
/// ```
///
/// The keys and values are separated by the same character as the username parts.
/// By default the `-` character is used as separator, but this can be changed by setting the generic parameter `C`.
///
/// Following keys are recognized:
///
/// - `id`: The ID of the proxy to select, requires a value as ID;
/// - `cc` or `country`: The country of the proxy, requires a value as country;
/// - `pool`: The ID of the pool from which to select the proxy, requires a value as pool ID;
/// - `dc` or `datacenter`: no value paired, sets the datacenter flag to `true`;
/// - `residential`: no value paired, sets the residential flag to `true`;
/// - `mobile`: no value paired, sets the mobile flag to `true`.
///
/// The username part is required, while the keys are optional, and can be in any order.
/// In case of duplicate keys, the last value is used.
///
/// # Example
///
/// ```rust
/// use rama::proxy::UsernameConfig;
///
/// let username = String::from("john-cc-us-dc-!residential");
/// let username_cfg: UsernameConfig = username.parse().unwrap();
///
/// // properties can be referenced
/// assert_eq!(username_cfg.username(), "john");
/// assert!(username_cfg.proxy_filter().unwrap().id.is_none());
/// assert_eq!(username_cfg.proxy_filter().unwrap().country.as_deref(), Some("us"));
/// assert!(username_cfg.proxy_filter().unwrap().pool_id.is_none());
/// assert_eq!(username_cfg.proxy_filter().unwrap().datacenter, Some(true));
/// assert_eq!(username_cfg.proxy_filter().unwrap().residential, Some(false));
/// assert!(username_cfg.proxy_filter().unwrap().mobile.is_none());
///
/// // the parsed config can also be formatted into a username string once again
/// let username_str = username_cfg.to_string();
/// assert_eq!(username, username_str);
///
/// // you can also consume the config
/// let (username, filter) = username_cfg.into_parts();
/// assert_eq!(username, "john");
///
/// let filter = filter.unwrap();
/// assert!(filter.id.is_none());
/// assert_eq!(filter.country.as_deref(), Some("us"));
/// assert!(filter.pool_id.is_none());
/// assert_eq!(filter.datacenter, Some(true));
/// assert_eq!(filter.residential, Some(false));
/// assert!(filter.mobile.is_none());
/// ```
pub struct UsernameConfig<const C: char = '-'> {
    username: String,
    filter: Option<ProxyFilter>,
}

/// Parse a username configuration string into a username and a [`ProxyFilter`].
///
/// This function can be used for cases where the separator is not known in advance,
/// or where using a function like this is more convenient because you
/// anyway need direct access to the username and the [`ProxyFilter`].
///
/// See [`UsernameConfig`] for more information about the format and usage.
pub fn parse_username_config(
    username: impl AsRef<str>,
    separator: char,
) -> Result<(String, Option<ProxyFilter>), UsernameConfigError> {
    let username = username.as_ref();

    if username.is_empty() {
        return Err(UsernameConfigError::MissingUsername);
    }

    let mut proxy_filter: ProxyFilter = Default::default();

    let mut username_it = username.split(separator);
    let username = match username_it.next() {
        Some(username) => username,
        None => return Err(UsernameConfigError::MissingUsername),
    };
    if username.is_empty() {
        // e.g. '-'
        return Err(UsernameConfigError::MissingUsername);
    }

    // iterate per two:
    let mut ctx: Option<&str> = None;
    for item in username_it {
        match ctx.take() {
            Some(key) => {
                // handle the item as a value, which has to be matched to the previously read key
                match_ignore_ascii_case_str! {
                    match(key) {
                        "cc" | "country" => proxy_filter.country = Some(item.to_owned()),
                        "pool" => proxy_filter.pool_id = Some(item.to_owned()),
                        "id" => proxy_filter.id = Some(item.to_owned()),
                        _ => return Err(UsernameConfigError::UnexpectedKey(key.to_owned())),
                    }
                }
            }
            None => {
                // allow bool-keys to be negated
                let (key, bval) = if let Some(key) = item.strip_prefix('!') {
                    (key, false)
                } else {
                    (item, true)
                };

                // check for key-only flags first, and otherwise consider it as a key, requiring a matching value
                match_ignore_ascii_case_str! {
                    match(key) {
                        "dc" | "datacenter" => proxy_filter.datacenter = Some(bval),
                        "residential" => proxy_filter.residential = Some(bval),
                        "mobile" => proxy_filter.mobile = Some(bval),
                        _ => ctx = Some(item),
                    }
                }
            }
        }
    }

    // catch keys without values
    if let Some(key) = ctx {
        return Err(UsernameConfigError::UnexpectedKey(key.to_owned()));
    }

    // return the parsed username config, with or without a ProxyFilter
    Ok(if proxy_filter == ProxyFilter::default() {
        (username.to_owned(), None)
    } else {
        (username.to_owned(), Some(proxy_filter))
    })
}

impl<const C: char> UsernameConfig<C> {
    /// Reference to the username part.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Reference to the [`ProxyFilter`] part.
    pub fn proxy_filter(&self) -> Option<&ProxyFilter> {
        self.filter.as_ref()
    }

    /// Consumes the [`UsernameConfig`] and returns the username and the [`ProxyFilter`] parts.
    pub fn into_parts(self) -> (String, Option<ProxyFilter>) {
        (self.username, self.filter)
    }

    /// Consumes the [`UsernameConfig`] and return only the [`ProxyFilter`].
    pub fn into_proxy_filter(self) -> Option<ProxyFilter> {
        self.filter
    }
}

impl<const C: char> From<UsernameConfig<C>> for ProxyFilter {
    fn from(cfg: UsernameConfig<C>) -> Self {
        cfg.filter.unwrap_or_default()
    }
}

impl<const C: char> FromStr for UsernameConfig<C> {
    type Err = UsernameConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (username, filter) = parse_username_config(s, C)?;
        Ok(UsernameConfig::<C> { username, filter })
    }
}

impl<const C: char> fmt::Display for UsernameConfig<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.username)?;
        if let Some(filter) = &self.filter {
            if let Some(id) = &filter.id {
                write!(f, "{0}id{0}{1}", C, id)?;
            }
            if let Some(country) = &filter.country {
                write!(f, "{0}cc{0}{1}", C, country)?;
            }
            if let Some(pool_id) = &filter.pool_id {
                write!(f, "{0}pool{0}{1}", C, pool_id)?;
            }
            match filter.datacenter {
                Some(true) => write!(f, "{0}dc", C)?,
                Some(false) => write!(f, "{0}!dc", C)?,
                None => {}
            }
            match filter.residential {
                Some(true) => write!(f, "{0}residential", C)?,
                Some(false) => write!(f, "{0}!residential", C)?,
                None => {}
            }
            match filter.mobile {
                Some(true) => write!(f, "{0}mobile", C)?,
                Some(false) => write!(f, "{0}!mobile", C)?,
                None => {}
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
/// Error that can occur when parsing a [`UsernameConfig`].
pub enum UsernameConfigError {
    /// The username is missing.
    MissingUsername,
    /// An unexpected key was found.
    ///
    /// This can be because the key is not recognized,
    /// or because the key is not expected in the context.
    UnexpectedKey(String),
}

impl fmt::Display for UsernameConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsernameConfigError::MissingUsername => {
                write!(f, "UsernameConfigError: missing username")
            }
            UsernameConfigError::UnexpectedKey(key) => {
                write!(f, "UsernameConfigError: unexpected key: {}", key)
            }
        }
    }
}

impl std::error::Error for UsernameConfigError {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_username_config() {
        let test_cases = [
            (
                "john",
                UsernameConfig::<'-'> {
                    username: String::from("john"),
                    filter: None,
                },
            ),
            (
                "john-dc",
                UsernameConfig::<'-'> {
                    username: String::from("john"),
                    filter: Some(ProxyFilter {
                        id: None,
                        country: None,
                        pool_id: None,
                        datacenter: Some(true),
                        residential: None,
                        mobile: None,
                    }),
                },
            ),
            (
                "john-!dc",
                UsernameConfig::<'-'> {
                    username: String::from("john"),
                    filter: Some(ProxyFilter {
                        id: None,
                        country: None,
                        pool_id: None,
                        datacenter: Some(false),
                        residential: None,
                        mobile: None,
                    }),
                },
            ),
            (
                "john-cc-us-dc",
                UsernameConfig::<'-'> {
                    username: String::from("john"),
                    filter: Some(ProxyFilter {
                        id: None,
                        country: Some(String::from("us")),
                        pool_id: None,
                        datacenter: Some(true),
                        residential: None,
                        mobile: None,
                    }),
                },
            ),
            (
                "john-cc-us-dc-pool-1",
                UsernameConfig::<'-'> {
                    username: String::from("john"),
                    filter: Some(ProxyFilter {
                        id: None,
                        country: Some(String::from("us")),
                        pool_id: Some(String::from("1")),
                        datacenter: Some(true),
                        residential: None,
                        mobile: None,
                    }),
                },
            ),
            (
                "john-cc-us-dc-pool-1-residential",
                UsernameConfig::<'-'> {
                    username: String::from("john"),
                    filter: Some(ProxyFilter {
                        id: None,
                        country: Some(String::from("us")),
                        pool_id: Some(String::from("1")),
                        datacenter: Some(true),
                        residential: Some(true),
                        mobile: None,
                    }),
                },
            ),
            (
                "john-cc-us-dc-pool-1-residential-mobile",
                UsernameConfig::<'-'> {
                    username: String::from("john"),
                    filter: Some(ProxyFilter {
                        id: None,
                        country: Some(String::from("us")),
                        pool_id: Some(String::from("1")),
                        datacenter: Some(true),
                        residential: Some(true),
                        mobile: Some(true),
                    }),
                },
            ),
            (
                "john-cc-us-dc-pool-1-residential-!mobile",
                UsernameConfig::<'-'> {
                    username: String::from("john"),
                    filter: Some(ProxyFilter {
                        id: None,
                        country: Some(String::from("us")),
                        pool_id: Some(String::from("1")),
                        datacenter: Some(true),
                        residential: Some(true),
                        mobile: Some(false),
                    }),
                },
            ),
            (
                "john-cc-us-dc-pool-1-residential-mobile-id-1",
                UsernameConfig::<'-'> {
                    username: String::from("john"),
                    filter: Some(ProxyFilter {
                        id: Some(String::from("1")),
                        country: Some(String::from("us")),
                        pool_id: Some(String::from("1")),
                        datacenter: Some(true),
                        residential: Some(true),
                        mobile: Some(true),
                    }),
                },
            ),
            (
                "john-cc-us-dc-pool-1-residential-mobile-id-1-cc-uk",
                UsernameConfig::<'-'> {
                    username: String::from("john"),
                    filter: Some(ProxyFilter {
                        id: Some(String::from("1")),
                        country: Some(String::from("uk")),
                        pool_id: Some(String::from("1")),
                        datacenter: Some(true),
                        residential: Some(true),
                        mobile: Some(true),
                    }),
                },
            ),
            (
                "john-cc-us-!dc-pool-1-residential-mobile-id-1-cc-uk",
                UsernameConfig::<'-'> {
                    username: String::from("john"),
                    filter: Some(ProxyFilter {
                        id: Some(String::from("1")),
                        country: Some(String::from("uk")),
                        pool_id: Some(String::from("1")),
                        datacenter: Some(false),
                        residential: Some(true),
                        mobile: Some(true),
                    }),
                },
            ),
            (
                "john-cc-us-dc-pool-1-residential-mobile-id-1-cc-uk-pool-2",
                UsernameConfig::<'-'> {
                    username: String::from("john"),
                    filter: Some(ProxyFilter {
                        id: Some(String::from("1")),
                        country: Some(String::from("uk")),
                        pool_id: Some(String::from("2")),
                        datacenter: Some(true),
                        residential: Some(true),
                        mobile: Some(true),
                    }),
                },
            ),
            (
                "john-cc-us-dc-pool-1-!residential-mobile-id-1-cc-uk-pool-2",
                UsernameConfig::<'-'> {
                    username: String::from("john"),
                    filter: Some(ProxyFilter {
                        id: Some(String::from("1")),
                        country: Some(String::from("uk")),
                        pool_id: Some(String::from("2")),
                        datacenter: Some(true),
                        residential: Some(false),
                        mobile: Some(true),
                    }),
                },
            ),
            (
                "john-cc-us-dc-pool-1-residential-mobile-id-1-cc-uk-pool-2-dc",
                UsernameConfig::<'-'> {
                    username: String::from("john"),
                    filter: Some(ProxyFilter {
                        id: Some(String::from("1")),
                        country: Some(String::from("uk")),
                        pool_id: Some(String::from("2")),
                        datacenter: Some(true),
                        residential: Some(true),
                        mobile: Some(true),
                    }),
                },
            ),
            (
                "john-cc-us-dc-pool-1-residential-mobile-id-1-cc-uk-pool-2-dc-residential",
                UsernameConfig::<'-'> {
                    username: String::from("john"),
                    filter: Some(ProxyFilter {
                        id: Some(String::from("1")),
                        country: Some(String::from("uk")),
                        pool_id: Some(String::from("2")),
                        datacenter: Some(true),
                        residential: Some(true),
                        mobile: Some(true),
                    }),
                },
            ),
            (
                "john-cc-us-dc-pool-1-residential-mobile-id-1-cc-uk-pool-2-dc-residential-mobile",
                UsernameConfig::<'-'> {
                    username: String::from("john"),
                    filter: Some(ProxyFilter {
                        id: Some(String::from("1")),
                        country: Some(String::from("uk")),
                        pool_id: Some(String::from("2")),
                        datacenter: Some(true),
                        residential: Some(true),
                        mobile: Some(true),
                    }),
                },
            ),
            (
                "john-cc-us-dc-pool-1-residential-mobile-id-1-cc-uk-pool-2-!dc-!residential-!mobile",
                UsernameConfig::<'-'> {
                    username: String::from("john"),
                    filter: Some(ProxyFilter {
                        id: Some(String::from("1")),
                        country: Some(String::from("uk")),
                        pool_id: Some(String::from("2")),
                        datacenter: Some(false),
                        residential: Some(false),
                        mobile: Some(false),
                    }),
                },
            ),
        ];

        for (username, expected) in test_cases.into_iter() {
            let username_cfg: UsernameConfig = username.parse().unwrap();
            let (username, filter) = username_cfg.into_parts();
            let (expected_username, expected_filter) = expected.into_parts();
            assert_eq!(username, expected_username);
            assert_eq!(filter, expected_filter);
        }
    }

    #[test]
    fn test_username_config_error() {
        let username_cfg: Result<UsernameConfig, UsernameConfigError> = "john-cc-us-dc-".parse();
        assert_eq!(
            UsernameConfigError::UnexpectedKey("".to_owned()),
            username_cfg.unwrap_err()
        );

        let username_cfg: Result<UsernameConfig, UsernameConfigError> = "".parse();
        assert_eq!(
            UsernameConfigError::MissingUsername,
            username_cfg.unwrap_err()
        );

        let username_cfg: Result<UsernameConfig, UsernameConfigError> = "-".parse();
        assert_eq!(
            UsernameConfigError::MissingUsername,
            username_cfg.unwrap_err()
        );

        let username_cfg: Result<UsernameConfig, UsernameConfigError> =
            "john-cc-us-dc-pool".parse();
        assert_eq!(
            UsernameConfigError::UnexpectedKey("pool".to_owned()),
            username_cfg.unwrap_err()
        );

        let username_cfg: Result<UsernameConfig, UsernameConfigError> = "john-foo".parse();
        assert_eq!(
            UsernameConfigError::UnexpectedKey("foo".to_owned()),
            username_cfg.unwrap_err()
        );

        let username_cfg: Result<UsernameConfig, UsernameConfigError> = "john-foo-cc".parse();
        assert_eq!(
            UsernameConfigError::UnexpectedKey("foo".to_owned()),
            username_cfg.unwrap_err()
        );

        let username_cfg: Result<UsernameConfig, UsernameConfigError> = "john-cc".parse();
        assert_eq!(
            UsernameConfigError::UnexpectedKey("cc".to_owned()),
            username_cfg.unwrap_err()
        );
    }

    #[test]
    fn test_username_config_custom_separator() {
        let username =
            "john_cc_us_dc_pool_1_residential_mobile_id_1_cc_uk_pool_2_dc_residential_mobile";
        let username_cfg: UsernameConfig<'_'> = username.parse().unwrap();
        let (username, filter) = username_cfg.into_parts();

        assert_eq!(username, "john");
        assert_eq!(
            filter,
            Some(ProxyFilter {
                id: Some(String::from("1")),
                country: Some(String::from("uk")),
                pool_id: Some(String::from("2")),
                datacenter: Some(true),
                residential: Some(true),
                mobile: Some(true),
            })
        );
    }
}
