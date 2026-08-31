//! URI path parameters captured during routing, plus the helpers that bridge
//! [`rama_net::uri::PathPattern`] matching into [`UriParams`].
//!
//! The matching engine itself lives in rama-net ([`PathPattern`]), whose
//! `{name}` / `{*name}` brace syntax is used directly by HTTP routing; this
//! module owns the routing glue: the configurable HTTP path policy and turning
//! [`PathCaptures`] into the [`UriParams`] extension the
//! [`Path`](crate::service::web::extract::Path) extractor reads.

use crate::StatusCode;
use crate::service::web::response::IntoResponse;
use ahash::{HashMap, HashMapExt as _};
use rama_core::extensions::{Extension, Extensions};
use rama_net::uri::{PathCaptures, PathMatchOptions, PathPattern, PathRef};
use rama_utils::str::arcstr::ArcStr;
use rama_utils::str::smol_str::format_smolstr;

mod de;

#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(http))]
/// Parameters inserted in [`Extensions`] when a path matcher matches a
/// [`Request`](crate::Request).
///
/// Each captured value follows the [`PathDecoding`] policy of the pattern that
/// produced it. Under [`PathDecoding::PercentDecoded`] (the default) valid
/// percent escapes are decoded once. Under [`PathDecoding::Raw`] the URI
/// path's encoded spelling is preserved. Nested patterns with different
/// policies can therefore contribute differently encoded values to one
/// `UriParams`. [`PathCase`] affects comparison only and never changes captured
/// values.
pub struct UriParams {
    params: Option<HashMap<ArcStr, ArcStr>>,
    glob: Option<ArcStr>,
}

impl UriParams {
    fn insert(&mut self, name: ArcStr, value: ArcStr) {
        self.params
            .get_or_insert_with(HashMap::new)
            .insert(name, value);
    }

    /// Return the captured value for `name`, with raw/decoded spelling
    /// determined by its capturing pattern's [`PathDecoding`] policy.
    pub fn get(&self, name: impl AsRef<str>) -> Option<&str> {
        self.params
            .as_ref()
            .and_then(|params| params.get(name.as_ref()))
            .map(AsRef::as_ref)
    }

    /// Return a non-empty captured value for `name`, with raw/decoded spelling
    /// determined by its capturing pattern's [`PathDecoding`] policy.
    pub fn get_non_empty(&self, name: impl AsRef<str>) -> Option<&str> {
        self.get(name).filter(|value| !value.is_empty())
    }

    fn append_glob(&mut self, value: &str) {
        self.glob = Some(ArcStr::from(
            if let Some(glob) = self.glob.take() {
                format_smolstr!("{glob}/{value}")
            } else {
                format_smolstr!("/{value}")
            }
            .as_str(),
        ))
    }

    /// Return the anonymous glob capture, including its leading `/`, with
    /// raw/decoded spelling determined by its capturing pattern's
    /// [`PathDecoding`] policy.
    #[must_use]
    pub fn glob(&self) -> Option<&str> {
        self.glob.as_deref()
    }

    /// Deserialize the [`UriParams`] into a given type.
    pub fn deserialize<T>(&self) -> Result<T, UriParamsDeserializeError>
    where
        T: serde::de::DeserializeOwned,
    {
        match self.params {
            Some(ref params) => {
                let params: Vec<_> = params
                    .iter()
                    .map(|(k, v)| (k.as_ref(), v.as_ref()))
                    .collect();
                let deserializer = de::PathDeserializer::new(&params);
                T::deserialize(deserializer)
            }
            None => Err(de::PathDeserializationError::new(de::ErrorKind::NoParams)),
        }
        .map_err(UriParamsDeserializeError)
    }

    /// Extend the [`UriParams`] with the given iterator.
    pub fn extend<I, K, V>(&mut self, iter: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<ArcStr>,
        V: Into<ArcStr>,
    {
        let params = self.params.get_or_insert_with(HashMap::new);
        for (k, v) in iter {
            params.insert(k.into(), v.into());
        }
        self
    }

    /// Iterate over captured names and values. Each value's spelling follows
    /// its capturing pattern's [`PathDecoding`] policy.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.params
            .as_ref()
            .map(|params| params.iter().map(|(k, v)| (k.as_ref(), v.as_ref())))
            .into_iter()
            .flatten()
    }

    /// Build [`UriParams`] from a successful [`PathPattern`] match: named
    /// captures (incl. `{*name}`) become params, the anonymous `{*}` glob (if
    /// any) becomes the glob value.
    pub(crate) fn from_captures(caps: &PathCaptures<'_, '_>) -> Self {
        let mut params = Self::default();
        for (name, value) in caps.iter() {
            params.insert(ArcStr::from(name), ArcStr::from(value));
        }
        if let Some(glob) = caps.glob() {
            params.append_glob(glob);
        }
        params
    }

    /// `true` when no named param and no glob were captured.
    pub(crate) fn is_empty(&self) -> bool {
        self.glob.is_none() && self.params.as_ref().is_none_or(HashMap::is_empty)
    }
}

impl<K, V> FromIterator<(K, V)> for UriParams
where
    K: Into<ArcStr>,
    V: Into<ArcStr>,
{
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        let mut params = Self::default();
        for (k, v) in iter {
            params.insert(k.into(), v.into());
        }
        params
    }
}

/// ASCII case-comparison policy for HTTP request paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PathCase {
    /// Compare path bytes case-sensitively.
    Sensitive,
    /// Compare ASCII path bytes case-insensitively.
    AsciiInsensitive,
}

/// Percent-escape handling policy for HTTP request paths and captures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PathDecoding {
    /// Match and capture the URI path's encoded spelling.
    ///
    /// Well-formed escapes preserve their spelling, including hex-digit case.
    /// The URI encoded view canonicalizes malformed escapes by encoding the
    /// stray percent sign, so `%` is observed as `%25` in a raw capture.
    Raw,
    /// Decode valid percent escapes once before matching and capture the
    /// decoded value.
    PercentDecoded,
}

/// Typed HTTP path-matching policy used by [`Router`](crate::service::web::Router)
/// and policy-aware [`HttpMatcher`](crate::matcher::HttpMatcher) constructors.
///
/// The two axes are independent. [`Default`] preserves Rama's established
/// case-insensitive, percent-decoded behavior. [`STRICT`](Self::STRICT)
/// provides case-sensitive routing without implicit percent decoding as an
/// explicit opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathMatchPolicy {
    case: PathCase,
    decoding: PathDecoding,
}

impl PathMatchPolicy {
    /// Strict routing: case-sensitive and without implicit percent decoding.
    ///
    /// Captures follow [`PathDecoding::Raw`], including its canonical handling
    /// of malformed percent escapes.
    pub const STRICT: Self = Self::new(PathCase::Sensitive, PathDecoding::Raw);

    /// Construct a policy from independently selected case and decoding axes.
    #[must_use]
    pub const fn new(case: PathCase, decoding: PathDecoding) -> Self {
        Self { case, decoding }
    }

    /// Return the configured case-comparison policy.
    #[must_use]
    pub const fn case(self) -> PathCase {
        self.case
    }

    /// Return the configured percent-decoding policy.
    #[must_use]
    pub const fn decoding(self) -> PathDecoding {
        self.decoding
    }

    pub(crate) const fn options(self) -> PathMatchOptions {
        PathMatchOptions {
            partial: false,
            ignore_ascii_case: match self.case {
                PathCase::Sensitive => false,
                PathCase::AsciiInsensitive => true,
            },
            percent_decode: match self.decoding {
                PathDecoding::Raw => false,
                PathDecoding::PercentDecoded => true,
            },
        }
    }
}

impl Default for PathMatchPolicy {
    fn default() -> Self {
        Self::new(PathCase::AsciiInsensitive, PathDecoding::PercentDecoded)
    }
}

/// Compile `pattern` with an explicit HTTP path-matching policy.
/// Route inputs are normalized by ignoring surrounding whitespace and
/// leading/trailing slashes.
pub(crate) fn compile_pattern_with_policy(pattern: &str, policy: PathMatchPolicy) -> PathPattern {
    let pattern = normalize(pattern);
    if pattern.is_empty() {
        PathPattern::new_with_opts("/", policy.options())
    } else {
        let pattern = format_smolstr!("/{pattern}");
        PathPattern::new_with_opts(pattern.as_str(), policy.options())
    }
}

/// Compile a prefix matcher with an explicit HTTP path-matching policy.
/// It matches a leading run of segments while ignoring trailing segments and
/// the trailing slash, so `/api` matches `/api` and `/api/users`.
pub(crate) fn compile_prefix_pattern_with_policy(
    prefix: &str,
    policy: PathMatchPolicy,
) -> PathPattern {
    PathPattern::new_prefix_with_opts(normalize(prefix), policy.options())
}

/// Match `path` against a compiled [`PathPattern`], inserting the captured
/// [`UriParams`] into `ext` on a successful match that bound anything.
pub(crate) fn match_pattern(
    pattern: &PathPattern,
    ext: Option<&Extensions>,
    path: PathRef<'_>,
) -> bool {
    match pattern.captures(path) {
        Some(caps) => {
            if let Some(ext) = ext {
                let params = UriParams::from_captures(&caps);
                if !params.is_empty() {
                    ext.insert(params);
                }
            }
            true
        }
        None => false,
    }
}

/// Normalise a prefix the way the matcher stores it: trimmed of surrounding
/// whitespace and leading/trailing slashes.
fn normalize(path: &str) -> &str {
    path.trim().trim_matches('/')
}

#[derive(Debug)]
/// Error that can occur during the deserialization of the [`UriParams`].
///
/// See [`UriParams::deserialize`] for more information.
pub struct UriParamsDeserializeError(de::PathDeserializationError);

impl UriParamsDeserializeError {
    /// Get the response body text used for this rejection.
    #[must_use]
    pub fn body_text(&self) -> String {
        use de::ErrorKind;
        match self.0.kind {
            ErrorKind::Message(_)
            | ErrorKind::NoParams
            | ErrorKind::ParseError { .. }
            | ErrorKind::ParseErrorAtIndex { .. }
            | ErrorKind::ParseErrorAtKey { .. } => format!("Invalid URL: {}", self.0.kind),
            ErrorKind::WrongNumberOfParameters { .. } | ErrorKind::UnsupportedType { .. } => {
                self.0.kind.to_string()
            }
        }
    }

    /// Get the status code used for this rejection.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        use de::ErrorKind;
        match self.0.kind {
            ErrorKind::Message(_)
            | ErrorKind::NoParams
            | ErrorKind::ParseError { .. }
            | ErrorKind::ParseErrorAtIndex { .. }
            | ErrorKind::ParseErrorAtKey { .. } => StatusCode::BAD_REQUEST,
            ErrorKind::WrongNumberOfParameters { .. } | ErrorKind::UnsupportedType { .. } => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

impl std::fmt::Display for UriParamsDeserializeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for UriParamsDeserializeError {}

impl IntoResponse for UriParamsDeserializeError {
    fn into_response(self) -> crate::Response {
        crate::utils::macros::log_http_rejection!(
            rejection_type = UriParamsDeserializeError,
            body_text = self.body_text(),
            status = self.status(),
        );
        (self.status(), self.body_text()).into_response()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rama_utils::str::arcstr::arcstr;

    fn compile_pattern(pattern: &str) -> PathPattern {
        compile_pattern_with_policy(pattern, PathMatchPolicy::default())
    }

    fn compile_prefix_pattern(prefix: &str) -> PathPattern {
        compile_prefix_pattern_with_policy(prefix, PathMatchPolicy::default())
    }

    #[test]
    fn pattern_captures_into_uri_params() {
        let pat = compile_pattern("/users/{id}");
        let ext = Extensions::new();
        assert!(match_pattern(
            &pat,
            Some(&ext),
            PathRef::from_raw_str("/users/glen%20dc"),
        ));
        let params = ext.get_ref::<UriParams>().unwrap();
        assert_eq!(params.get("id"), Some("glen dc"));
        assert_eq!(params.get_non_empty("id"), Some("glen dc"));

        // Named catch-all is read as a normal param.
        let pat = compile_pattern("/assets/{*path}");
        let ext = Extensions::new();
        assert!(match_pattern(
            &pat,
            Some(&ext),
            PathRef::from_raw_str("/assets/css/app.css"),
        ));
        assert_eq!(
            ext.get_ref::<UriParams>().unwrap().get("path"),
            Some("css/app.css")
        );
    }

    #[test]
    fn decoding_policy_covers_every_percent_encoded_byte() {
        let raw_pattern = compile_pattern_with_policy(
            "/send/{value}",
            PathMatchPolicy::new(PathCase::Sensitive, PathDecoding::Raw),
        );
        let decoded_pattern = compile_pattern_with_policy(
            "/send/{value}",
            PathMatchPolicy::new(PathCase::Sensitive, PathDecoding::PercentDecoded),
        );

        for byte in u8::MIN..=u8::MAX {
            let encoded = format!("%{byte:02X}");
            let path = format!("/send/{encoded}");
            let path = PathRef::from_raw_str(&path);

            let raw = raw_pattern.captures(path).unwrap();
            assert_eq!(raw.get("value"), Some(encoded.as_str()), "byte {byte:#04x}");

            let bytes = [byte];
            let expected = String::from_utf8_lossy(&bytes);
            let decoded = decoded_pattern.captures(path).unwrap();
            assert_eq!(
                decoded.get("value"),
                Some(expected.as_ref()),
                "byte {byte:#04x}"
            );
        }
    }

    #[test]
    fn uri_params_get_non_empty_filters_empty_values() {
        let params = UriParams::from_iter([("name", ""), ("id", "42")]);

        assert_eq!(params.get("name"), Some(""));
        assert_eq!(params.get_non_empty("name"), None);
        assert_eq!(params.get_non_empty("id"), Some("42"));
        assert_eq!(params.get_non_empty("missing"), None);
    }

    #[test]
    fn prefix_pattern_glue() {
        let api = compile_prefix_pattern("/api");
        assert!(api.is_match(PathRef::from_raw_str("/api")));
        assert!(api.is_match(PathRef::from_raw_str("/api/users")));
        assert!(!api.is_match(PathRef::from_raw_str("/apixyz")));
        // The public default remains case-insensitive.
        assert!(api.is_match(PathRef::from_raw_str("/API/users")));
    }

    #[test]
    fn route_pattern_normalization_preserves_root() {
        for root in ["", "/", " / "] {
            let pat = compile_pattern(root);
            assert!(pat.is_match(PathRef::from_raw_str("/")));
            assert!(!pat.is_match(PathRef::from_raw_str("")));
            assert!(!pat.is_match(PathRef::from_raw_str("/users")));
        }

        let users = compile_pattern(" /users/ ");
        assert!(users.is_match(PathRef::from_raw_str("/users")));
        assert!(!users.is_match(PathRef::from_raw_str("/users/")));
    }

    #[test]
    fn test_deserialize_uri_params() {
        let params = UriParams {
            params: Some({
                let mut params = HashMap::new();
                params.insert(arcstr!("name"), arcstr!("glen dc"));
                params.insert(arcstr!("age"), arcstr!("42"));
                params
            }),
            glob: Some("/age".into()),
        };

        #[derive(serde::Deserialize)]
        struct Person {
            name: String,
            age: u8,
        }

        let person: Person = params.deserialize().unwrap();
        assert_eq!(person.name, "glen dc");
        assert_eq!(person.age, 42);
    }
}
