use super::UriMatchReplace;
use crate::{address::Domain, http::uri::match_replace::UriMatchError};
use rama_core::{
    error::{BoxError, ErrorContext as _},
    telemetry::tracing,
};
use rama_http_types::{Uri, uri::Authority};
use rama_utils::macros::generate_set_and_with;
use rama_utils::str::smol_str::format_smolstr;
use std::borrow::Cow;

#[derive(Debug, Clone)]
/// Replace or overwrite the existing [`Domain`].
pub struct UriMatchReplaceDomain {
    mode: Mode,
    port_mode: PortMode,
}

#[derive(Debug, Clone)]
enum Mode {
    SetAlways(Domain),
    ReplaceIfSub { root: Domain, new: Domain },
    ReplaceIfExact { old: Domain, new: Domain },
    DropPrefix(Domain),
}

#[derive(Debug, Clone, Default)]
enum PortMode {
    #[default]
    Preserve,
    Drop,
    Overwrite(u16),
}

impl UriMatchReplaceDomain {
    #[must_use]
    pub fn set_always(domain: Domain) -> Self {
        Self {
            mode: Mode::SetAlways(domain),
            port_mode: PortMode::default(),
        }
    }

    #[must_use]
    pub fn replace_exact(old: Domain, new: Domain) -> Self {
        Self {
            mode: Mode::ReplaceIfExact { old, new },
            port_mode: PortMode::default(),
        }
    }

    #[must_use]
    pub fn replace_sub(root: Domain, new: Domain) -> Self {
        Self {
            mode: Mode::ReplaceIfSub { root, new },
            port_mode: PortMode::default(),
        }
    }

    #[must_use]
    pub fn drop_prefix(prefix: Domain) -> Self {
        Self {
            mode: Mode::DropPrefix(prefix),
            port_mode: PortMode::default(),
        }
    }

    #[must_use]
    #[inline]
    pub fn drop_prefix_www() -> Self {
        Self::drop_prefix(Domain::from_static("www"))
    }

    generate_set_and_with! {
        /// Drop the port from the [`Uri`]'s authority,
        /// if it was available in the first place...
        pub fn drop_port(mut self) -> Self {
            self.port_mode = PortMode::Drop;
            self
        }
    }

    generate_set_and_with! {
        /// Overwrite the port with the given port, rergardless if it was available.
        pub fn overwrite_port(mut self, port: u16) -> Self {
            self.port_mode = PortMode::Overwrite(port);
            self
        }
    }

    fn write_new_uri(&self, domain: &Domain, og_port: Option<u16>) -> Result<Authority, BoxError> {
        match self.port_mode {
            PortMode::Preserve => {
                if let Some(port) = og_port {
                    format_smolstr!("{domain}:{port}")
                        .parse()
                        .context("write authority with new domain and with OG port preserved")
                } else {
                    domain.as_str().parse().context(
                        "write authority with new domain and without an OG port to preserve",
                    )
                }
            }
            PortMode::Drop => domain
                .as_str()
                .parse()
                .context("write authority with new domain and with OG port dropped (if any)"),
            PortMode::Overwrite(port) => format_smolstr!("{domain}:{port}")
                .parse()
                .context("write authority with new domain but with port overwritten"),
        }
    }
}

impl UriMatchReplace for UriMatchReplaceDomain {
    fn match_replace_uri<'a>(&self, uri: Cow<'a, Uri>) -> Result<Cow<'a, Uri>, UriMatchError<'a>> {
        let new_authority = match &self.mode {
            Mode::SetAlways(domain) => {
                match self.write_new_uri(
                    domain,
                    uri.authority().and_then(|authority| authority.port_u16()),
                ) {
                    Ok(authority) => authority,
                    Err(err) => {
                        tracing::debug!(
                            "failed to write new uri with hardcoded domain ({domain}); downgrade to no-match uri error: {err}; give someone else a shot"
                        );
                        return Err(UriMatchError::NoMatch(uri));
                    }
                }
            }
            Mode::ReplaceIfSub { root, new } => {
                if let Some((domain, og_port)) = uri.authority().and_then(|authority| {
                    authority
                        .as_str()
                        .parse::<Domain>()
                        .ok()
                        .map(|domain| (domain, authority.port_u16()))
                }) && root.is_parent_of(&domain)
                {
                    match self.write_new_uri(new, og_port) {
                        Ok(authority) => authority,
                        Err(err) => {
                            tracing::debug!(
                                "failed to write new uri with subdomain match ({root}); downgrade to no-match uri error: {err}; give someone else a shot"
                            );
                            return Err(UriMatchError::NoMatch(uri));
                        }
                    }
                } else {
                    return Err(UriMatchError::NoMatch(uri));
                }
            }
            Mode::ReplaceIfExact { old, new } => {
                if let Some((domain, og_port)) = uri.authority().and_then(|authority| {
                    authority
                        .as_str()
                        .parse::<Domain>()
                        .ok()
                        .map(|domain| (domain, authority.port_u16()))
                }) && old.eq(&domain)
                {
                    match self.write_new_uri(new, og_port) {
                        Ok(authority) => authority,
                        Err(err) => {
                            tracing::debug!(
                                "failed to write new uri with exact match ({old}); downgrade to no-match uri error: {err}; give someone else a shot"
                            );
                            return Err(UriMatchError::NoMatch(uri));
                        }
                    }
                } else {
                    return Err(UriMatchError::NoMatch(uri));
                }
            }
            Mode::DropPrefix(prefix) => {
                if let Some((domain, og_port)) = uri.authority().and_then(|authority| {
                    authority
                        .as_str()
                        .parse::<Domain>()
                        .ok()
                        .map(|domain| (domain, authority.port_u16()))
                }) && let Some(new) = domain.strip_sub(prefix)
                {
                    match self.write_new_uri(&new, og_port) {
                        Ok(authority) => authority,
                        Err(err) => {
                            tracing::debug!(
                                "failed to write new uri with prefix dropped (prefix); downgrade to no-match uri error: {err}; give someone else a shot"
                            );
                            return Err(UriMatchError::NoMatch(uri));
                        }
                    }
                } else {
                    return Err(UriMatchError::NoMatch(uri));
                }
            }
        };

        tracing::trace!(
            "UriMatchReplaceDomain: match found and resulted in new authority: {new_authority}"
        );

        let mut uri_parts = uri.into_owned().into_parts();
        uri_parts.authority = Some(new_authority);
        Uri::from_parts(uri_parts)
            .context("re-create uri with domain overwrite (always)")
            .map_err(UriMatchError::Unexpected)
            .map(Cow::Owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expect_uri_match(
        matcher: &UriMatchReplaceDomain,
        input_uri: &'static str,
        expected: &'static str,
    ) {
        let expected_uri = Uri::from_static(expected);
        match matcher.match_replace_uri(Cow::Owned(Uri::from_static(input_uri))) {
            Ok(uri) => assert_eq!(
                uri.as_ref(),
                &expected_uri,
                "input uri: {input_uri}; matcher: {matcher:?}"
            ),
            Err(err) => {
                panic!("unexpected error: {err}; input uri: {input_uri}; matcher: {matcher:?}")
            }
        }
    }

    #[test]
    fn test_domain_match_overwrite_always_match() {
        for (
            input,
            expected_output_port_preserve,
            expected_output_port_drop,
            expected_output_port_overwrite,
        ) in [
            (
                "http://example.com",
                "http://foo.org",
                "http://foo.org",
                "http://foo.org:8888",
            ),
            (
                "http://example.com/bar?q=v",
                "http://foo.org/bar?q=v",
                "http://foo.org/bar?q=v",
                "http://foo.org:8888/bar?q=v",
            ),
        ] {
            let mut matcher = UriMatchReplaceDomain::set_always(Domain::from_static("foo.org"));
            expect_uri_match(&matcher, input, expected_output_port_preserve);

            matcher.set_drop_port();
            expect_uri_match(&matcher, input, expected_output_port_drop);

            matcher.set_overwrite_port(8888);
            expect_uri_match(&matcher, input, expected_output_port_overwrite);
        }
    }

    #[test]
    fn test_domain_match_domain_exact_match() {
        for (
            input,
            expected_output_port_preserve,
            expected_output_port_drop,
            expected_output_port_overwrite,
        ) in [
            (
                "http://example.com",
                "http://foo.org",
                "http://foo.org",
                "http://foo.org:8888",
            ),
            (
                "http://example.com/bar?q=v",
                "http://foo.org/bar?q=v",
                "http://foo.org/bar?q=v",
                "http://foo.org:8888/bar?q=v",
            ),
        ] {
            let mut matcher = UriMatchReplaceDomain::replace_exact(
                Domain::from_static("example.com"),
                Domain::from_static("foo.org"),
            );
            expect_uri_match(&matcher, input, expected_output_port_preserve);

            matcher.set_drop_port();
            expect_uri_match(&matcher, input, expected_output_port_drop);

            matcher.set_overwrite_port(8888);
            expect_uri_match(&matcher, input, expected_output_port_overwrite);
        }
    }

    #[test]
    fn test_domain_match_domain_sub_match() {
        for (
            input,
            expected_output_port_preserve,
            expected_output_port_drop,
            expected_output_port_overwrite,
        ) in [
            (
                "http://bar.example.com",
                "http://foo.org",
                "http://foo.org",
                "http://foo.org:8888",
            ),
            (
                "http://example.com",
                "http://foo.org",
                "http://foo.org",
                "http://foo.org:8888",
            ),
            (
                "http://baz.example.com/bar?q=v",
                "http://foo.org/bar?q=v",
                "http://foo.org/bar?q=v",
                "http://foo.org:8888/bar?q=v",
            ),
            (
                "http://example.com/bar?q=v",
                "http://foo.org/bar?q=v",
                "http://foo.org/bar?q=v",
                "http://foo.org:8888/bar?q=v",
            ),
        ] {
            let mut matcher = UriMatchReplaceDomain::replace_sub(
                Domain::from_static("example.com"),
                Domain::from_static("foo.org"),
            );
            expect_uri_match(&matcher, input, expected_output_port_preserve);

            matcher.set_drop_port();
            expect_uri_match(&matcher, input, expected_output_port_drop);

            matcher.set_overwrite_port(8888);
            expect_uri_match(&matcher, input, expected_output_port_overwrite);
        }
    }

    #[test]
    fn test_domain_match_strip_prefix_match() {
        for (
            input,
            expected_output_port_preserve,
            expected_output_port_drop,
            expected_output_port_overwrite,
        ) in [
            (
                "http://www.example.com",
                "http://example.com",
                "http://example.com",
                "http://example.com:8888",
            ),
            (
                "http://www.example.com/bar?q=v",
                "http://example.com/bar?q=v",
                "http://example.com/bar?q=v",
                "http://example.com:8888/bar?q=v",
            ),
        ] {
            let mut matcher = UriMatchReplaceDomain::drop_prefix_www();
            expect_uri_match(&matcher, input, expected_output_port_preserve);

            matcher.set_drop_port();
            expect_uri_match(&matcher, input, expected_output_port_drop);

            matcher.set_overwrite_port(8888);
            expect_uri_match(&matcher, input, expected_output_port_overwrite);
        }
    }

    fn expect_uri_no_match(matcher: &UriMatchReplaceDomain, input_uri: &'static str) {
        let uri = Cow::Owned(Uri::from_static(input_uri));
        match matcher.match_replace_uri(uri) {
            Ok(found) => panic!("unexpected match for uri {input_uri}: {found}"),
            Err(UriMatchError::NoMatch(_)) => (), // good
            Err(UriMatchError::Unexpected(err)) => {
                panic!("unexpected match error for uri {input_uri}: {err}")
            }
        }
    }

    #[test]
    fn test_domain_no_match() {
        for (mut matcher, input_uri) in [
            (
                UriMatchReplaceDomain::drop_prefix_www(),
                "http://example.com",
            ),
            (
                UriMatchReplaceDomain::drop_prefix(Domain::from_static("api")),
                "http://www.example.com",
            ),
            (
                UriMatchReplaceDomain::replace_exact(
                    Domain::from_static("foo.com"),
                    Domain::example(),
                ),
                "http://example.com",
            ),
            (
                UriMatchReplaceDomain::replace_exact(
                    Domain::from_static("example.org"),
                    Domain::example(),
                ),
                "http://example.com",
            ),
            (
                UriMatchReplaceDomain::replace_exact(
                    Domain::from_static("example.com"),
                    Domain::from_static("plabayo.tech"),
                ),
                "http://www.example.com",
            ),
            (
                UriMatchReplaceDomain::replace_exact(
                    Domain::from_static("example.com"),
                    Domain::from_static("plabayo.tech"),
                ),
                "http://com",
            ),
            (
                UriMatchReplaceDomain::replace_sub(
                    Domain::from_static("example.com"),
                    Domain::from_static("plabayo.tech"),
                ),
                "http://example.org",
            ),
            (
                UriMatchReplaceDomain::replace_sub(
                    Domain::from_static("example.com"),
                    Domain::from_static("plabayo.tech"),
                ),
                "http://www.example.org",
            ),
            (
                UriMatchReplaceDomain::replace_sub(
                    Domain::from_static("example.com"),
                    Domain::from_static("plabayo.tech"),
                ),
                "http://foo.com",
            ),
            (
                UriMatchReplaceDomain::replace_sub(
                    Domain::from_static("example.com"),
                    Domain::from_static("plabayo.tech"),
                ),
                "http://www.foo.com",
            ),
            (
                UriMatchReplaceDomain::replace_sub(
                    Domain::from_static("example.com"),
                    Domain::from_static("plabayo.tech"),
                ),
                "http://com",
            ),
        ] {
            expect_uri_no_match(&matcher, input_uri);

            matcher.set_drop_port();
            expect_uri_no_match(&matcher, input_uri);

            matcher.set_overwrite_port(8888);
            expect_uri_no_match(&matcher, input_uri);
        }
    }
}
