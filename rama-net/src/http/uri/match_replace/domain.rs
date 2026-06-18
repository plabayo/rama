use super::UriMatchReplace;
use crate::address::{Domain, OptPort};
use crate::http::uri::match_replace::UriMatchError;
use crate::uri::Uri;
use rama_utils::macros::generate_set_and_with;
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

}

impl UriMatchReplace for UriMatchReplaceDomain {
    fn match_replace_uri<'a>(&self, uri: Cow<'a, Uri>) -> Result<Cow<'a, Uri>, UriMatchError<'a>> {
        // Resolve the replacement domain (or no-match). Every mode needs an
        // authority — there must be a host to inspect and/or replace.
        let new_domain = match &self.mode {
            Mode::SetAlways(domain) => {
                if uri.authority().is_none() {
                    return Err(UriMatchError::NoMatch(uri));
                }
                domain.clone()
            }
            Mode::ReplaceIfSub { root, new } => match uri_domain(&uri) {
                Some(domain) if root.is_parent_of(&domain) => new.clone(),
                _ => return Err(UriMatchError::NoMatch(uri)),
            },
            Mode::ReplaceIfExact { old, new } => match uri_domain(&uri) {
                Some(domain) if old.eq(&domain) => new.clone(),
                _ => return Err(UriMatchError::NoMatch(uri)),
            },
            Mode::DropPrefix(prefix) => match uri_domain(&uri).and_then(|d| d.strip_sub(prefix)) {
                Some(new) => new,
                None => return Err(UriMatchError::NoMatch(uri)),
            },
        };

        // Native `Uri` sets the host in place (port preserved) and adjusts the
        // port directly — no `into_parts` / `from_parts` round-trip, and the
        // host setter is infallible for a validated `Domain`.
        let mut uri = uri.into_owned();
        uri.set_host(new_domain);
        match self.port_mode {
            PortMode::Preserve => {}
            PortMode::Drop => {
                uri.set_port(OptPort::Unset);
            }
            PortMode::Overwrite(port) => {
                uri.set_port(OptPort::Set(port));
            }
        }
        Ok(Cow::Owned(uri))
    }
}

/// Extract the authority's host as an owned [`Domain`] when it is a domain
/// name (bridging pct-encoded reg-names); `None` for IP hosts or when the
/// URI has no authority.
fn uri_domain(uri: &Uri) -> Option<Domain> {
    uri.authority()?.host().try_as_domain().ok()
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
