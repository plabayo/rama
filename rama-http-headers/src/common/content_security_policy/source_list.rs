use std::borrow::Cow;
use std::fmt::{self, Write as _};

use rama_net::Protocol;
use rama_net::address::Domain;
use rama_utils::macros::generate_set_and_with;

use super::host_source::HostSource;
use super::source_expression::{HashAlgorithm, SourceExpression};

/// Ordered list of [`SourceExpression`]s — the value of one CSP
/// directive.
///
/// Builder methods come in two flavours: `with_*` consumes `self` and
/// returns `Self` for chaining; `set_*` / [`add`](SourceList::add)
/// mutate in place.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SourceList {
    sources: Vec<SourceExpression>,
}

impl SourceList {
    /// Empty list — for directives like `upgrade-insecure-requests`
    /// that carry no source value.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            sources: Vec::new(),
        }
    }

    /// `'none'`-only list. Per spec must not be combined with any
    /// other source.
    #[must_use]
    pub fn none() -> Self {
        Self {
            sources: vec![SourceExpression::None],
        }
    }

    /// `'self'`-only list. Equivalent to
    /// `SourceList::empty().with_self_keyword()`.
    #[must_use]
    pub fn self_origin() -> Self {
        Self {
            sources: vec![SourceExpression::SelfOrigin],
        }
    }

    /// Borrow the underlying sources in declared (emit) order.
    pub fn as_slice(&self) -> &[SourceExpression] {
        &self.sources
    }

    /// Iterate sources in declared (emit) order.
    pub fn iter(&self) -> std::slice::Iter<'_, SourceExpression> {
        self.sources.iter()
    }

    /// Push any source expression and return `Self`.
    #[must_use]
    pub fn with(mut self, expr: SourceExpression) -> Self {
        self.sources.push(expr);
        self
    }

    /// Push any source expression in place.
    pub fn add(&mut self, expr: SourceExpression) -> &mut Self {
        self.sources.push(expr);
        self
    }

    // ---- keyword-only convenience hatches ------------------------------
    generate_set_and_with! {
        /// Append the `'self'` keyword.
        pub fn self_keyword(mut self) -> Self {
            self.sources.push(SourceExpression::SelfOrigin);
            self
        }
    }
    generate_set_and_with! {
        /// Append the `'unsafe-inline'` keyword.
        pub fn unsafe_inline(mut self) -> Self {
            self.sources.push(SourceExpression::UnsafeInline);
            self
        }
    }
    generate_set_and_with! {
        /// Append the `'unsafe-eval'` keyword.
        pub fn unsafe_eval(mut self) -> Self {
            self.sources.push(SourceExpression::UnsafeEval);
            self
        }
    }
    generate_set_and_with! {
        /// Append the `'strict-dynamic'` keyword.
        pub fn strict_dynamic(mut self) -> Self {
            self.sources.push(SourceExpression::StrictDynamic);
            self
        }
    }
    generate_set_and_with! {
        /// Append the `'wasm-unsafe-eval'` keyword.
        pub fn wasm_unsafe_eval(mut self) -> Self {
            self.sources.push(SourceExpression::WasmUnsafeEval);
            self
        }
    }
    generate_set_and_with! {
        /// Append the `'report-sample'` keyword.
        pub fn report_sample(mut self) -> Self {
            self.sources.push(SourceExpression::ReportSample);
            self
        }
    }
    generate_set_and_with! {
        /// Append the `*` wildcard.
        pub fn wildcard(mut self) -> Self {
            self.sources.push(SourceExpression::Wildcard);
            self
        }
    }

    // ---- common scheme shortcuts ---------------------------------------
    generate_set_and_with! {
        /// Append the `data:` scheme.
        pub fn data(mut self) -> Self {
            self.sources
                .push(SourceExpression::Scheme(Protocol::from_static("data")));
            self
        }
    }
    generate_set_and_with! {
        /// Append the `blob:` scheme.
        pub fn blob(mut self) -> Self {
            self.sources
                .push(SourceExpression::Scheme(Protocol::from_static("blob")));
            self
        }
    }

    // ---- typed parametrised hatches ------------------------------------
    generate_set_and_with! {
        /// Append a [`Protocol`] as a scheme source (`<scheme>:`).
        pub fn scheme(mut self, scheme: Protocol) -> Self {
            self.sources.push(SourceExpression::Scheme(scheme));
            self
        }
    }
    generate_set_and_with! {
        /// Append a [`HostSource`] (or anything convertible into one —
        /// `Domain`, a `&str` via [`HostSource::try_parse`] etc.).
        pub fn host(mut self, host: impl Into<HostSource>) -> Self {
            self.sources.push(SourceExpression::Host(host.into()));
            self
        }
    }
    generate_set_and_with! {
        /// Append a bare-domain host source (no scheme, port, or path).
        pub fn domain(mut self, domain: Domain) -> Self {
            self.sources
                .push(SourceExpression::Host(HostSource::new(domain)));
            self
        }
    }
    generate_set_and_with! {
        /// Append a `'nonce-<base64>'` source.
        pub fn nonce(mut self, nonce: impl Into<Cow<'static, str>>) -> Self {
            self.sources.push(SourceExpression::Nonce(nonce.into()));
            self
        }
    }
    generate_set_and_with! {
        /// Append a `'<algo>-<base64>'` source.
        pub fn hash(mut self, algorithm: HashAlgorithm, value: impl Into<Cow<'static, str>>) -> Self {
            self.sources.push(SourceExpression::Hash {
                algorithm,
                value: value.into(),
            });
            self
        }
    }
}

impl fmt::Display for SourceList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, src) in self.sources.iter().enumerate() {
            if i > 0 {
                f.write_char(' ')?;
            }
            src.fmt(f)?;
        }
        Ok(())
    }
}

impl<T: Into<SourceExpression>> FromIterator<T> for SourceList {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self {
            sources: iter.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<SourceExpression> for SourceList {
    fn from(expr: SourceExpression) -> Self {
        Self {
            sources: vec![expr],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_space_separated() {
        let list = SourceList::self_origin()
            .with_data()
            .with_host(Domain::from_static("example.com"));
        assert_eq!(list.to_string(), "'self' data: example.com");
    }

    #[test]
    fn none_renders_just_none() {
        assert_eq!(SourceList::none().to_string(), "'none'");
    }

    #[test]
    fn empty_renders_empty() {
        assert_eq!(SourceList::empty().to_string(), "");
    }

    #[test]
    fn set_and_add_mutate_in_place() {
        let mut list = SourceList::empty();
        list.set_self_keyword().set_unsafe_inline();
        assert_eq!(list.to_string(), "'self' 'unsafe-inline'");
        list.add(SourceExpression::Wildcard);
        assert_eq!(list.to_string(), "'self' 'unsafe-inline' *");
    }

    #[test]
    fn builds_from_iter() {
        let list: SourceList = [SourceExpression::SelfOrigin, SourceExpression::Wildcard]
            .into_iter()
            .collect();
        assert_eq!(list.to_string(), "'self' *");
    }

    #[test]
    fn host_helper_accepts_string_and_domain_and_host_source() {
        let from_str = SourceList::empty()
            .with_host(HostSource::try_parse("https://raw.githubusercontent.com").unwrap());
        assert_eq!(from_str.to_string(), "https://raw.githubusercontent.com");

        let from_domain = SourceList::empty().with_domain(Domain::from_static("example.com"));
        assert_eq!(from_domain.to_string(), "example.com");

        let from_built = SourceList::empty().with_host(
            HostSource::new(Domain::from_static("example.com"))
                .with_scheme(Protocol::HTTPS)
                .with_port(8443),
        );
        assert_eq!(from_built.to_string(), "https://example.com:8443");
    }

    #[test]
    fn scheme_helper_accepts_typed_protocol() {
        let list = SourceList::empty().with_scheme(Protocol::HTTPS);
        assert_eq!(list.to_string(), "https:");
    }

    #[test]
    fn hash_helper_emits_canonical_form() {
        let list = SourceList::empty().with_hash(HashAlgorithm::Sha256, "abc");
        assert_eq!(list.to_string(), "'sha256-abc'");
    }
}
