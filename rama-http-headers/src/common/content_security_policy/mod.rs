//! `Content-Security-Policy` header — [CSP Level 3].
//!
//! [CSP Level 3]: https://www.w3.org/TR/CSP3/
//!
//! A policy is built up from typed directives — each pairing a
//! [`DirectiveName`] with a [`SourceList`] of [`SourceExpression`]s.
//! Per-directive `with_*` / `set_*` setters (generated via
//! [`rama_utils::macros::generate_set_and_with`]) cover what you'll
//! usually need; the generic [`ContentSecurityPolicy::with`] /
//! [`ContentSecurityPolicy::set`] escape hatch handles anything else.

mod directive;
mod host_source;
mod source_expression;
mod source_list;

pub use self::directive::{Directive, DirectiveName};
pub use self::host_source::{HostSource, HostSourcePort};
pub use self::source_expression::{HashAlgorithm, SourceExpression};
pub use self::source_list::SourceList;

use std::fmt;
use std::str::FromStr;

use rama_http_types::{HeaderName, HeaderValue};
use rama_utils::macros::generate_set_and_with;

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// `Content-Security-Policy` response header.
///
/// Adding a directive that already exists in the policy *replaces* its
/// source-list in place (preserving declared order). The user agent
/// would ignore a second occurrence anyway, so we keep the value the
/// caller most recently supplied.
///
/// # Examples
///
/// ```
/// use rama_http_headers::{ContentSecurityPolicy, HostSource, SourceList};
///
/// let csp = ContentSecurityPolicy::strict_self().with_img_src(
///     SourceList::self_origin()
///         .with_data()
///         .with_host(HostSource::try_parse("https://raw.githubusercontent.com").unwrap()),
/// );
///
/// let rendered = csp.to_string();
/// assert!(rendered.contains("img-src 'self' data: https://raw.githubusercontent.com"));
/// assert!(rendered.contains("frame-ancestors 'none'"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContentSecurityPolicy {
    directives: Vec<Directive>,
}

impl ContentSecurityPolicy {
    /// Empty policy. Build from this when you want to add directives
    /// one at a time rather than starting from a baseline.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            directives: Vec::new(),
        }
    }

    /// Strict same-origin baseline:
    ///
    /// ```text
    /// default-src 'self'; script-src 'self'; style-src 'self';
    /// img-src 'self'; font-src 'self'; connect-src 'self';
    /// form-action 'self'; base-uri 'self'; frame-ancestors 'none'
    /// ```
    #[must_use]
    pub fn strict_self() -> Self {
        Self::empty()
            .with_default_src(SourceList::self_origin())
            .with_script_src(SourceList::self_origin())
            .with_style_src(SourceList::self_origin())
            .with_img_src(SourceList::self_origin())
            .with_font_src(SourceList::self_origin())
            .with_connect_src(SourceList::self_origin())
            .with_form_action(SourceList::self_origin())
            .with_base_uri(SourceList::self_origin())
            .with_frame_ancestors(SourceList::none())
    }

    /// Iterate the policy's directives in encoding order.
    pub fn directives(&self) -> impl Iterator<Item = &Directive> + '_ {
        self.directives.iter()
    }

    /// Generic escape hatch: append or replace any directive by name.
    /// If the directive already exists, its source-list is overwritten
    /// in place (order preserved); otherwise it's appended.
    #[must_use]
    pub fn with(mut self, name: impl Into<DirectiveName>, sources: SourceList) -> Self {
        self.upsert(name.into(), sources);
        self
    }

    /// In-place sibling of [`with`](Self::with).
    pub fn set(&mut self, name: impl Into<DirectiveName>, sources: SourceList) -> &mut Self {
        self.upsert(name.into(), sources);
        self
    }

    fn upsert(&mut self, name: DirectiveName, sources: SourceList) {
        if let Some(slot) = self.directives.iter_mut().find(|d| d.name == name) {
            slot.sources = sources;
        } else {
            self.directives.push(Directive { name, sources });
        }
    }

    // ---- per-directive convenience setters ----
    //
    // Each macro invocation generates both a `with_*` (chaining, takes
    // ownership) and a `set_*` (`&mut self`) form.

    generate_set_and_with! {
        /// Set `default-src`.
        pub fn default_src(mut self, sources: SourceList) -> Self {
            self.upsert(DirectiveName::DefaultSrc, sources);
            self
        }
    }
    generate_set_and_with! {
        /// Set `script-src`.
        pub fn script_src(mut self, sources: SourceList) -> Self {
            self.upsert(DirectiveName::ScriptSrc, sources);
            self
        }
    }
    generate_set_and_with! {
        /// Set `style-src`.
        pub fn style_src(mut self, sources: SourceList) -> Self {
            self.upsert(DirectiveName::StyleSrc, sources);
            self
        }
    }
    generate_set_and_with! {
        /// Set `img-src`.
        pub fn img_src(mut self, sources: SourceList) -> Self {
            self.upsert(DirectiveName::ImgSrc, sources);
            self
        }
    }
    generate_set_and_with! {
        /// Set `font-src`.
        pub fn font_src(mut self, sources: SourceList) -> Self {
            self.upsert(DirectiveName::FontSrc, sources);
            self
        }
    }
    generate_set_and_with! {
        /// Set `connect-src`.
        pub fn connect_src(mut self, sources: SourceList) -> Self {
            self.upsert(DirectiveName::ConnectSrc, sources);
            self
        }
    }
    generate_set_and_with! {
        /// Set `media-src`.
        pub fn media_src(mut self, sources: SourceList) -> Self {
            self.upsert(DirectiveName::MediaSrc, sources);
            self
        }
    }
    generate_set_and_with! {
        /// Set `object-src`.
        pub fn object_src(mut self, sources: SourceList) -> Self {
            self.upsert(DirectiveName::ObjectSrc, sources);
            self
        }
    }
    generate_set_and_with! {
        /// Set `frame-src`.
        pub fn frame_src(mut self, sources: SourceList) -> Self {
            self.upsert(DirectiveName::FrameSrc, sources);
            self
        }
    }
    generate_set_and_with! {
        /// Set `frame-ancestors`. Note that nonces, hashes, and
        /// `'unsafe-inline'` are not valid sources here per CSP3 § 6.1.2
        /// (we don't enforce that — just be aware).
        pub fn frame_ancestors(mut self, sources: SourceList) -> Self {
            self.upsert(DirectiveName::FrameAncestors, sources);
            self
        }
    }
    generate_set_and_with! {
        /// Set `child-src`.
        pub fn child_src(mut self, sources: SourceList) -> Self {
            self.upsert(DirectiveName::ChildSrc, sources);
            self
        }
    }
    generate_set_and_with! {
        /// Set `worker-src`.
        pub fn worker_src(mut self, sources: SourceList) -> Self {
            self.upsert(DirectiveName::WorkerSrc, sources);
            self
        }
    }
    generate_set_and_with! {
        /// Set `manifest-src`.
        pub fn manifest_src(mut self, sources: SourceList) -> Self {
            self.upsert(DirectiveName::ManifestSrc, sources);
            self
        }
    }
    generate_set_and_with! {
        /// Set `form-action`.
        pub fn form_action(mut self, sources: SourceList) -> Self {
            self.upsert(DirectiveName::FormAction, sources);
            self
        }
    }
    generate_set_and_with! {
        /// Set `base-uri`.
        pub fn base_uri(mut self, sources: SourceList) -> Self {
            self.upsert(DirectiveName::BaseUri, sources);
            self
        }
    }
    generate_set_and_with! {
        /// Set `navigate-to`.
        pub fn navigate_to(mut self, sources: SourceList) -> Self {
            self.upsert(DirectiveName::NavigateTo, sources);
            self
        }
    }
    generate_set_and_with! {
        /// Set `report-to`.
        pub fn report_to(mut self, sources: SourceList) -> Self {
            self.upsert(DirectiveName::ReportTo, sources);
            self
        }
    }
    generate_set_and_with! {
        /// Set the valueless `upgrade-insecure-requests` directive.
        pub fn upgrade_insecure_requests(mut self) -> Self {
            self.upsert(DirectiveName::UpgradeInsecureRequests, SourceList::empty());
            self
        }
    }
}

impl fmt::Display for ContentSecurityPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, d) in self.directives.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            d.fmt(f)?;
        }
        Ok(())
    }
}

impl TypedHeader for ContentSecurityPolicy {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::CONTENT_SECURITY_POLICY
    }
}

impl HeaderDecode for ContentSecurityPolicy {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        // CSP allows the header to be set multiple times — the user agent
        // enforces the intersection of all returned policies. For
        // round-tripping we concatenate them preserving order.
        let mut out = Self::empty();
        let mut any = false;
        for value in values {
            any = true;
            let s = value.to_str().map_err(|_err| Error::invalid())?;
            for raw in s.split(';') {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let mut parts = trimmed.split_whitespace();
                let name = match parts.next() {
                    Some(n) => DirectiveName::from(n),
                    None => continue,
                };
                // Skip tokens we can't parse — these are rare on
                // well-formed inputs (every wire keyword / scheme / host
                // shape is accepted), and dropping the rest of the
                // directive on one malformed token would be more
                // surprising than logging it and moving on. Callers
                // wanting strict parsing should pre-validate.
                let sources: SourceList = parts
                    .filter_map(|tok| SourceExpression::from_str(tok).ok())
                    .collect();
                out.directives.push(Directive { name, sources });
            }
        }
        if !any {
            return Err(Error::invalid());
        }
        Ok(out)
    }
}

impl HeaderEncode for ContentSecurityPolicy {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let rendered = self.to_string();
        match HeaderValue::try_from(rendered) {
            Ok(v) => values.extend(::std::iter::once(v)),
            Err(_) => {
                // All typed paths produce ASCII; degrade to empty rather
                // than panic inside the response stack.
                values.extend(::std::iter::once(HeaderValue::from_static("")));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{test_decode, test_encode};
    use super::*;

    use rama_net::Protocol;
    use rama_net::address::Domain;

    #[test]
    fn typed_setters_replace_existing_directive_in_place() {
        let csp = ContentSecurityPolicy::empty()
            .with_default_src(SourceList::self_origin())
            .with_img_src(SourceList::self_origin())
            .with_style_src(SourceList::self_origin())
            .with_img_src(SourceList::self_origin().with_data());
        let names: Vec<&str> = csp.directives().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["default-src", "img-src", "style-src"]);

        let img = csp
            .directives()
            .find(|d| d.name == DirectiveName::ImgSrc)
            .unwrap();
        assert_eq!(img.sources.to_string(), "'self' data:");
    }

    #[test]
    fn strict_self_renders_canonical_lockdown() {
        let s = ContentSecurityPolicy::strict_self().to_string();
        for expected in [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "img-src 'self'",
            "font-src 'self'",
            "connect-src 'self'",
            "form-action 'self'",
            "base-uri 'self'",
            "frame-ancestors 'none'",
        ] {
            assert!(s.contains(expected), "missing `{expected}` in {s}");
        }
    }

    #[test]
    fn upgrade_insecure_requests_renders_as_valueless_directive() {
        let csp = ContentSecurityPolicy::empty().with_upgrade_insecure_requests();
        assert_eq!(csp.to_string(), "upgrade-insecure-requests");
    }

    #[test]
    fn generic_with_escape_hatch_accepts_string_name() {
        let csp =
            ContentSecurityPolicy::empty().with("experimental-thing", SourceList::self_origin());
        assert_eq!(csp.to_string(), "experimental-thing 'self'");
        let d = csp.directives().next().unwrap();
        assert!(matches!(d.name, DirectiveName::Unknown(ref s) if s == "experimental-thing"));
    }

    #[test]
    fn set_mutates_in_place_via_generic_hatch() {
        let mut csp = ContentSecurityPolicy::strict_self();
        csp.set(DirectiveName::ConnectSrc, SourceList::none());
        assert!(csp.to_string().contains("connect-src 'none'"));
    }

    #[test]
    fn typed_host_source_in_img_src() {
        let csp = ContentSecurityPolicy::empty().with_img_src(
            SourceList::self_origin().with_data().with_host(
                HostSource::new(Domain::from_static("raw.githubusercontent.com"))
                    .with_scheme(Protocol::HTTPS),
            ),
        );
        assert_eq!(
            csp.to_string(),
            "img-src 'self' data: https://raw.githubusercontent.com"
        );
    }

    #[test]
    fn decode_round_trip_single_value_typed() {
        let parsed = test_decode::<ContentSecurityPolicy>(&[
            "default-src 'self'; script-src 'self' 'unsafe-inline'",
        ])
        .expect("should decode");
        let names: Vec<&str> = parsed.directives().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["default-src", "script-src"]);
        let script = parsed
            .directives()
            .find(|d| d.name == DirectiveName::ScriptSrc)
            .unwrap();
        assert_eq!(
            script.sources.as_slice(),
            &[SourceExpression::SelfOrigin, SourceExpression::UnsafeInline,],
        );
    }

    #[test]
    fn decode_handles_multiple_header_values() {
        let parsed =
            test_decode::<ContentSecurityPolicy>(&["default-src 'self'", "img-src 'self' data:"])
                .expect("should decode");
        let names: Vec<&str> = parsed.directives().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["default-src", "img-src"]);
    }

    #[test]
    fn decode_tolerates_empty_segments_and_extra_whitespace() {
        let parsed = test_decode::<ContentSecurityPolicy>(&[
            "  default-src 'self'  ;;   script-src 'self'  ",
        ])
        .expect("should decode");
        let names: Vec<&str> = parsed.directives().map(|d| d.name.as_str()).collect();
        assert_eq!(names, vec!["default-src", "script-src"]);
    }

    #[test]
    fn decode_directive_without_value() {
        let parsed =
            test_decode::<ContentSecurityPolicy>(&["upgrade-insecure-requests"]).expect("decode");
        let d = parsed.directives().next().unwrap();
        assert_eq!(d.name, DirectiveName::UpgradeInsecureRequests);
        assert!(d.sources.as_slice().is_empty());
    }

    #[test]
    fn decode_empty_returns_error() {
        assert_eq!(test_decode::<ContentSecurityPolicy>(&[] as &[&str]), None);
    }

    #[test]
    fn encode_round_trips_through_header_map() {
        let csp = ContentSecurityPolicy::strict_self();
        let map = test_encode(csp.clone());
        let raw = map
            .get(ContentSecurityPolicy::name())
            .expect("header set")
            .to_str()
            .unwrap();
        assert_eq!(raw, csp.to_string());
    }

    #[test]
    fn full_decode_encode_round_trip() {
        let original = ContentSecurityPolicy::strict_self()
            .with_img_src(
                SourceList::self_origin()
                    .with_data()
                    .with_host(HostSource::try_parse("https://raw.githubusercontent.com").unwrap()),
            )
            .with_connect_src(SourceList::self_origin())
            .with_upgrade_insecure_requests();
        let wire = original.to_string();
        let parsed = test_decode::<ContentSecurityPolicy>(&[wire.as_str()]).expect("decode");
        assert_eq!(parsed.to_string(), wire);
    }
}
