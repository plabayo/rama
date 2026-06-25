//! URI path parameters captured during routing, plus the helpers that bridge
//! [`rama_net::uri::PathPattern`] matching into [`UriParams`].
//!
//! The matching engine itself lives in rama-net ([`PathPattern`]), whose
//! `{name}` / `{*name}` brace syntax is used directly by HTTP routing; this
//! module owns the routing glue: the case-insensitive match options and
//! turning [`PathCaptures`] into the [`UriParams`] extension the
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
/// parameters that are inserted in the [`Extensions`],
/// in case a path matcher found a match for the given [`Request`](crate::Request).
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

    /// Some str slice will be returned in case a param could be found for the given name.
    pub fn get(&self, name: impl AsRef<str>) -> Option<&str> {
        self.params
            .as_ref()
            .and_then(|params| params.get(name.as_ref()))
            .map(AsRef::as_ref)
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

    /// Some str slice will be returned in case a glob value was captured
    /// for the last part of the Path that was matched on.
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

/// Path-matching options used throughout HTTP routing: case-insensitive,
/// percent-decoded, segment-boundary — mirrors the legacy matcher's behaviour.
pub(crate) const HTTP_PATH_OPTS: PathMatchOptions = PathMatchOptions {
    partial: false,
    ignore_ascii_case: true,
    percent_decode: true,
};

/// Compile `pattern` (in [`PathPattern`] syntax) with the HTTP routing options.
/// Route inputs are normalized the same way the previous matcher accepted them:
/// surrounding whitespace and leading/trailing slashes are ignored.
pub(crate) fn compile_pattern(pattern: &str) -> PathPattern {
    let pattern = normalize(pattern);
    if pattern.is_empty() {
        PathPattern::new_with_opts("/", HTTP_PATH_OPTS)
    } else {
        let pattern = format_smolstr!("/{pattern}");
        PathPattern::new_with_opts(pattern.as_str(), HTTP_PATH_OPTS)
    }
}

/// Compile a prefix matcher (in [`PathPattern`] syntax) with the HTTP routing
/// options: matches a leading run of segments, ignoring trailing segments and
/// the trailing slash. So `/api` matches `/api` and `/api/users`.
pub(crate) fn compile_prefix_pattern(prefix: &str) -> PathPattern {
    PathPattern::new_prefix_with_opts(normalize(prefix), HTTP_PATH_OPTS)
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
    fn prefix_pattern_glue() {
        let api = compile_prefix_pattern("/api");
        assert!(api.is_match(PathRef::from_raw_str("/api")));
        assert!(api.is_match(PathRef::from_raw_str("/api/users")));
        assert!(!api.is_match(PathRef::from_raw_str("/apixyz")));
        // case-insensitive via HTTP_PATH_OPTS
        assert!(api.is_match(PathRef::from_raw_str("/API/users")));
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
