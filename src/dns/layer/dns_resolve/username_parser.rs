use crate::{
    __eq_ignore_ascii_case,
    error::{error, ErrorContext, OpaqueError},
    service::context::Extensions,
    utils::username::{UsernameLabelParser, UsernameLabelState},
};

use super::DnsResolveMode;

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// A parser which parses [`DnsResolveMode`]s from username labels
/// and adds it to the [`Context`]'s [`Extensions`].
///
/// [`Context`]: crate::service::Context
/// [`Extensions`]: crate::service::context::Extensions
pub struct DnsResolveModeUsernameParser {
    key_found: bool,
    mode: DnsResolveMode,
}

impl DnsResolveModeUsernameParser {
    /// Create a new [`DnsResolveModeUsernameParser`].
    pub fn new() -> Self {
        Self::default()
    }
}

impl UsernameLabelParser for DnsResolveModeUsernameParser {
    type Error = OpaqueError;

    fn parse_label(&mut self, label: &str) -> UsernameLabelState {
        if self.key_found {
            self.mode = match label
                .parse()
                .context("parse dns resolve mode username label")
            {
                Ok(mode) => mode,
                Err(err) => {
                    tracing::trace!(err = %err, "abort username label parsing: invalid parse label");
                    return UsernameLabelState::Abort;
                }
            };
            self.key_found = false;
            UsernameLabelState::Used
        } else if __eq_ignore_ascii_case!("dns", label) {
            self.key_found = true;
            UsernameLabelState::Used
        } else {
            UsernameLabelState::Ignored
        }
    }

    fn build(self, ext: &mut Extensions) -> Result<(), Self::Error> {
        if self.key_found {
            return Err(error!("unused dns resolve mode username key: dns"));
        }
        ext.insert(self.mode);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::username::{parse_username, DEFAULT_USERNAME_LABEL_SEPARATOR};

    #[test]
    fn test_username_dns_resolve_mod_config() {
        let test_cases = [
            ("john", String::from("john"), DnsResolveMode::default()),
            (
                "john-dns-eager",
                String::from("john"),
                DnsResolveMode::eager(),
            ),
            (
                "john-dns-lazy",
                String::from("john"),
                DnsResolveMode::lazy(),
            ),
            (
                "john-dns-eager-dns-lazy",
                String::from("john"),
                DnsResolveMode::lazy(),
            ),
            (
                "john-dns-lazy-dns-eager",
                String::from("john"),
                DnsResolveMode::eager(),
            ),
        ];

        for (username, expected_username, expected_mode) in test_cases.into_iter() {
            let mut ext = Extensions::default();

            let parser = DnsResolveModeUsernameParser::default();

            let username =
                parse_username(&mut ext, parser, username, DEFAULT_USERNAME_LABEL_SEPARATOR)
                    .unwrap();
            let mode = *ext.get::<DnsResolveMode>().unwrap();
            assert_eq!(
                username, expected_username,
                "username = '{}' ; expected_username = '{}'",
                username, expected_username
            );
            assert_eq!(
                mode, expected_mode,
                "username = '{}' ; expected_mode = '{}'",
                username, expected_mode
            );
        }
    }

    #[test]
    fn test_username_dns_resolve_mode_error() {
        for username in [
            "john-",
            "john-dns",
            "john-dns-eager-",
            "john-dns-eager-dns",
            "john-dns-foo",
        ] {
            let mut ext = Extensions::default();

            let parser = DnsResolveModeUsernameParser::default();

            assert!(
                parse_username(&mut ext, parser, username, DEFAULT_USERNAME_LABEL_SEPARATOR)
                    .is_err(),
                "username = {}",
                username
            );
        }
    }
}
