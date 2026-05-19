use std::borrow::Cow;
use std::fmt::{self, Write as _};
use std::str::FromStr;

use rama_net::Protocol;
use rama_net::address::Domain;

use crate::Error;

use super::host_source::HostSource;

/// Cryptographic hash algorithm for [`SourceExpression::Hash`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlgorithm {
    /// Lowercase token used in CSP serialisation (`sha256` / `sha384`
    /// / `sha512`).
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One CSP *source expression* — the building block of a source-list.
///
/// Every variant has a canonical wire form defined by
/// [CSP Level 3 § 2.3](https://www.w3.org/TR/CSP3/#framework-source-list);
/// see [`fmt::Display`] for the mapping.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SourceExpression {
    /// Same-origin sources only.
    SelfOrigin,
    /// No sources are permitted. Per spec must appear alone in a list.
    None,
    /// Permit inline `<script>` / `<style>` blocks and inline event
    /// handlers — generally a bad idea on a hardened policy.
    UnsafeInline,
    /// Permit `eval` and related JS APIs.
    UnsafeEval,
    /// Trust scripts loaded by a nonced / hashed script, ignoring the
    /// rest of the source list.
    StrictDynamic,
    /// Permit specific inline event handlers / style attributes via a
    /// matching hash source.
    UnsafeHashes,
    /// Permit `WebAssembly.instantiate` from buffers (not just from
    /// fetched script sources).
    WasmUnsafeEval,
    /// Include a sample of the violation in CSP reports.
    ReportSample,
    /// Permit inline `<script type="speculationrules">` blocks.
    InlineSpeculationRules,
    /// Match any source (`*`). Equivalent to "no restriction" — only
    /// useful for testing.
    Wildcard,
    /// A whole scheme (e.g. `data:`, `blob:`, `mediastream:`). The
    /// trailing `:` is emitted by the serialiser.
    Scheme(Protocol),
    /// A host source — scheme/host/port/path combination, see
    /// [`HostSource`].
    Host(HostSource),
    /// `'nonce-<base64>'` — pairs with `nonce="…"` on the inline element.
    Nonce(Cow<'static, str>),
    /// `'<algo>-<base64>'` matching an inline script or style.
    Hash {
        algorithm: HashAlgorithm,
        /// Base64-encoded digest, without the `<algo>-` prefix.
        value: Cow<'static, str>,
    },
}

impl SourceExpression {
    /// Build a [`SourceExpression::Scheme`] from a [`Protocol`] (or
    /// anything convertible into one).
    pub fn scheme(scheme: impl Into<Protocol>) -> Self {
        Self::Scheme(scheme.into())
    }

    /// Build a [`SourceExpression::Host`] from anything convertible
    /// into a [`HostSource`] (e.g. a [`Domain`] or a host-source
    /// string via [`HostSource::try_parse`]).
    pub fn host(host: impl Into<HostSource>) -> Self {
        Self::Host(host.into())
    }

    /// Build a [`SourceExpression::Nonce`].
    pub fn nonce(nonce: impl Into<Cow<'static, str>>) -> Self {
        Self::Nonce(nonce.into())
    }

    /// Build a [`SourceExpression::Hash`].
    pub fn hash(algorithm: HashAlgorithm, value: impl Into<Cow<'static, str>>) -> Self {
        Self::Hash {
            algorithm,
            value: value.into(),
        }
    }
}

impl fmt::Display for SourceExpression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SelfOrigin => f.write_str("'self'"),
            Self::None => f.write_str("'none'"),
            Self::UnsafeInline => f.write_str("'unsafe-inline'"),
            Self::UnsafeEval => f.write_str("'unsafe-eval'"),
            Self::StrictDynamic => f.write_str("'strict-dynamic'"),
            Self::UnsafeHashes => f.write_str("'unsafe-hashes'"),
            Self::WasmUnsafeEval => f.write_str("'wasm-unsafe-eval'"),
            Self::ReportSample => f.write_str("'report-sample'"),
            Self::InlineSpeculationRules => f.write_str("'inline-speculation-rules'"),
            Self::Wildcard => f.write_char('*'),
            Self::Scheme(p) => write!(f, "{}:", p.as_str()),
            Self::Host(h) => write!(f, "{h}"),
            Self::Nonce(n) => write!(f, "'nonce-{n}'"),
            Self::Hash { algorithm, value } => write!(f, "'{algorithm}-{value}'"),
        }
    }
}

impl From<Protocol> for SourceExpression {
    fn from(p: Protocol) -> Self {
        Self::Scheme(p)
    }
}

impl From<Domain> for SourceExpression {
    fn from(d: Domain) -> Self {
        Self::Host(HostSource::new(d))
    }
}

impl From<HostSource> for SourceExpression {
    fn from(h: HostSource) -> Self {
        Self::Host(h)
    }
}

impl FromStr for SourceExpression {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // The parser here is intentionally permissive: tokens that are
        // not a recognised keyword / nonce / hash / scheme-only string
        // fall through to a best-effort `HostSource` parse, which itself
        // accepts the wildcard subdomain and `:*` forms.
        match s {
            "*" => return Ok(Self::Wildcard),
            "'self'" => return Ok(Self::SelfOrigin),
            "'none'" => return Ok(Self::None),
            "'unsafe-inline'" => return Ok(Self::UnsafeInline),
            "'unsafe-eval'" => return Ok(Self::UnsafeEval),
            "'strict-dynamic'" => return Ok(Self::StrictDynamic),
            "'unsafe-hashes'" => return Ok(Self::UnsafeHashes),
            "'wasm-unsafe-eval'" => return Ok(Self::WasmUnsafeEval),
            "'report-sample'" => return Ok(Self::ReportSample),
            "'inline-speculation-rules'" => return Ok(Self::InlineSpeculationRules),
            _ => {}
        }

        // `'nonce-<x>'` / `'<alg>-<x>'`.
        if let Some(inner) = s.strip_prefix('\'').and_then(|t| t.strip_suffix('\'')) {
            if let Some(nonce) = inner.strip_prefix("nonce-") {
                return Ok(Self::Nonce(Cow::Owned(nonce.to_owned())));
            }
            for alg in [
                HashAlgorithm::Sha256,
                HashAlgorithm::Sha384,
                HashAlgorithm::Sha512,
            ] {
                if let Some(hash) = inner.strip_prefix(&format!("{}-", alg.as_str())) {
                    return Ok(Self::Hash {
                        algorithm: alg,
                        value: Cow::Owned(hash.to_owned()),
                    });
                }
            }
            // Quoted keyword we don't recognise — keep it round-trip-safe
            // by stashing the whole token as a host (it would be invalid
            // CSP either way; preserving the bytes lets the caller log
            // it sensibly).
            return HostSource::try_parse(s)
                .map(Self::Host)
                .map_err(|_err| Error::invalid());
        }

        // Scheme-only source: `data:`, `https:`, ... (no `/`, ends in `:`).
        if let Some(scheme) = s.strip_suffix(':')
            && !scheme.is_empty()
            && !s.contains('/')
        {
            let proto = Protocol::try_from(scheme).map_err(|_err| Error::invalid())?;
            return Ok(Self::Scheme(proto));
        }

        // Otherwise — host source (may include scheme + port + path).
        HostSource::try_parse(s).map(Self::Host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keywords_round_trip() {
        for (s, want) in [
            ("'self'", SourceExpression::SelfOrigin),
            ("'none'", SourceExpression::None),
            ("'unsafe-inline'", SourceExpression::UnsafeInline),
            ("'unsafe-eval'", SourceExpression::UnsafeEval),
            ("'strict-dynamic'", SourceExpression::StrictDynamic),
            ("*", SourceExpression::Wildcard),
        ] {
            assert_eq!(SourceExpression::from_str(s).unwrap(), want);
            assert_eq!(want.to_string(), s);
        }
    }

    #[test]
    fn scheme_uses_typed_protocol() {
        let parsed = SourceExpression::from_str("data:").unwrap();
        assert!(matches!(parsed, SourceExpression::Scheme(ref p) if p.as_str() == "data"));
        assert_eq!(parsed.to_string(), "data:");

        let https = SourceExpression::scheme(Protocol::HTTPS);
        assert_eq!(https.to_string(), "https:");
    }

    #[test]
    fn host_uses_typed_host_source() {
        let parsed = SourceExpression::from_str("https://raw.githubusercontent.com").unwrap();
        match parsed {
            SourceExpression::Host(h) => {
                assert_eq!(h.scheme().unwrap().as_str(), "https");
                assert_eq!(h.host().as_ref(), "raw.githubusercontent.com");
            }
            other => panic!("expected Host, got {other:?}"),
        }
    }

    #[test]
    fn wildcard_subdomain_host_round_trips() {
        let parsed = SourceExpression::from_str("*.example.com").unwrap();
        assert_eq!(parsed.to_string(), "*.example.com");
    }

    #[test]
    fn nonce_and_hash_round_trip() {
        assert_eq!(
            SourceExpression::from_str("'nonce-abc'")
                .unwrap()
                .to_string(),
            "'nonce-abc'"
        );
        let h = SourceExpression::from_str("'sha384-xyz'").unwrap();
        assert!(matches!(
            h,
            SourceExpression::Hash {
                algorithm: HashAlgorithm::Sha384,
                ..
            }
        ));
        assert_eq!(h.to_string(), "'sha384-xyz'");
    }

    #[test]
    fn from_impls_construct_typed_sources() {
        let from_proto: SourceExpression = Protocol::HTTPS.into();
        assert_eq!(from_proto.to_string(), "https:");

        let from_domain: SourceExpression = Domain::from_static("example.com").into();
        assert_eq!(from_domain.to_string(), "example.com");
    }
}
