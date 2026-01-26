use std::sync::Arc;

use crate::service::web::response::IntoResponse;
use crate::{Request, StatusCode};
use ahash::{HashMap, HashMapExt as _};
use rama_core::extensions::Extensions;
use rama_net::uri::util::percent_encoding;
use rama_utils::collections::smallvec::SmallVec;
use rama_utils::str::arcstr::ArcStr;
use rama_utils::str::smol_str::{StrExt as _, format_smolstr};
use rama_utils::str::starts_with_ignore_ascii_case;

mod de;

#[derive(Debug, Clone, Default)]
/// parameters that are inserted in the [`Extensions`],
/// in case the [`PathMatcher`] found a match for the given [`Request`].
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

#[derive(Debug, Clone)]
enum PathFragment {
    Literal(ArcStr),
    Param(ArcStr),
    Glob,
}

#[derive(Debug, Clone)]
enum PathMatcherKind {
    Prefix(ArcStr),
    Literal(ArcStr),
    FragmentList(std::sync::Arc<[PathFragment]>),
}

#[derive(Debug, Clone)]
/// Matcher based on the URI path.
pub struct PathMatcher {
    kind: PathMatcherKind,
}

impl PathMatcher {
    /// Create a new [`PathMatcher`] for the given path.
    pub fn new(path: impl AsRef<str>) -> Self {
        let path = path.as_ref();
        let path = path.trim().trim_matches('/');

        if !path.contains(['*', '{', '}']) {
            return Self {
                kind: PathMatcherKind::Literal(ArcStr::from(path)),
            };
        }

        let path_parts: SmallVec<[_; 8]> = path.split('/').filter(|s| !s.is_empty()).collect();
        let fragment_length = path_parts.len();
        if fragment_length == 1 && path_parts[0].is_empty() {
            return Self {
                kind: PathMatcherKind::FragmentList(Arc::from([PathFragment::Glob])),
            };
        }

        let fragments: SmallVec<[_; 8]> = path_parts
            .into_iter()
            .enumerate()
            .filter_map(|(index, s)| {
                if s.is_empty() {
                    return None;
                }
                if s.starts_with(':') {
                    Some(PathFragment::Param(ArcStr::from(
                        s.trim_start_matches(':').to_lowercase_smolstr(),
                    )))
                } else if s.starts_with('{') && s.ends_with('}') && s.len() > 2 {
                    let param_name = s[1..s.len() - 1].to_lowercase_smolstr();
                    Some(PathFragment::Param(ArcStr::from(param_name)))
                } else if s == "*" && index == fragment_length - 1 {
                    Some(PathFragment::Glob)
                } else {
                    Some(PathFragment::Literal(ArcStr::from(
                        s.to_lowercase_smolstr(),
                    )))
                }
            })
            .collect();

        if fragments
            .iter()
            .all(|f| matches!(f, PathFragment::Literal(_)))
        {
            // optimization for pure literal paths..
            return Self {
                kind: PathMatcherKind::Literal(ArcStr::from(path)),
            };
        }

        Self {
            kind: PathMatcherKind::FragmentList(Arc::from(fragments.as_slice())),
        }
    }

    /// Create a new [`PathMatcher`] for the given prefix.
    pub fn new_prefix(path: impl AsRef<str>) -> Self {
        let path = path.as_ref();
        let path = path.trim().trim_matches('/');
        Self {
            kind: PathMatcherKind::Prefix(path.into()),
        }
    }

    /// Create a new [`PathMatcher`] for the given literal.
    ///
    /// Useful constructor in case you want to create a literal
    /// with special characters given [`Self::new`] would interpret
    /// something like `/*` as a glob, while you might require a literal *...
    pub fn new_literal(path: impl AsRef<str>) -> Self {
        let path = path.as_ref();
        let path = path.trim().trim_matches('/');
        Self {
            kind: PathMatcherKind::Literal(path.into()),
        }
    }

    #[must_use]
    pub fn fragment_count(&self) -> usize {
        match &self.kind {
            PathMatcherKind::Prefix(_) | PathMatcherKind::Literal(_) => 0,
            PathMatcherKind::FragmentList(path_fragments) => path_fragments.len(),
        }
    }

    /// Try to remove the literals that prefix other fragments. This can be useful
    /// for routers which want to first match on a literal, and do the rest as a normal prefix.
    ///
    /// Err is returned with the original data in case it doesn't contain literal prefixes.
    pub fn try_remove_literal_prefix(
        self,
        allow_glob: bool,
    ) -> Result<(ArcStr, Option<Self>), Self> {
        match self.kind {
            PathMatcherKind::Literal(s) | PathMatcherKind::Prefix(s) => Ok((s, None)),
            PathMatcherKind::FragmentList(fragments) => {
                let mut pos = 0;
                for fragment in fragments.iter() {
                    if !matches!(fragment, PathFragment::Literal(_)) {
                        break;
                    }
                    pos += 1;
                }
                if pos == 0 || pos == fragments.len() {
                    return Err(Self {
                        kind: PathMatcherKind::FragmentList(fragments),
                    });
                }
                let (fragments, rem) = fragments.split_at(pos);

                let mut output = String::with_capacity(
                    fragments.len()
                        + fragments
                            .iter()
                            .map(|f| match f {
                                PathFragment::Literal(s) => s.len(),
                                PathFragment::Param(_) | PathFragment::Glob => unreachable!(),
                            })
                            .sum::<usize>(),
                );
                for fragment in fragments {
                    match fragment {
                        PathFragment::Literal(s) => output.push_str(s.as_ref()),
                        PathFragment::Param(_) | PathFragment::Glob => unreachable!(),
                    }
                }

                Ok(if rem.is_empty() {
                    (ArcStr::from(output), None)
                } else if !allow_glob
                    && rem
                        .last()
                        .map(|f| matches!(f, PathFragment::Glob))
                        .unwrap_or_default()
                {
                    (
                        ArcStr::from(output),
                        Some(Self {
                            kind: PathMatcherKind::FragmentList(Arc::from(&rem[..rem.len() - 1])),
                        }),
                    )
                } else {
                    (
                        ArcStr::from(output),
                        Some(Self {
                            kind: PathMatcherKind::FragmentList(Arc::from(rem)),
                        }),
                    )
                })
            }
        }
    }

    pub fn matches_path(&self, ext: Option<&mut Extensions>, path: impl AsRef<str>) -> bool {
        match self.matches_path_inner(path) {
            PathMatch::None => false,
            PathMatch::Literal => true,
            PathMatch::WithParams(params) => {
                if let Some(ext) = ext {
                    ext.insert(params);
                }
                true
            }
        }
    }

    fn matches_path_inner(&self, path: impl AsRef<str>) -> PathMatch {
        let path = path.as_ref().trim().trim_matches('/');
        match &self.kind {
            PathMatcherKind::Prefix(prefix) => {
                if prefix.is_empty() || starts_with_ignore_ascii_case(path, prefix) {
                    PathMatch::Literal
                } else {
                    PathMatch::None
                }
            }
            PathMatcherKind::Literal(literal) => {
                if literal.eq_ignore_ascii_case(path) {
                    PathMatch::Literal
                } else {
                    PathMatch::None
                }
            }
            PathMatcherKind::FragmentList(fragments) => {
                let fragments_iter = fragments.iter().map(Some).chain(std::iter::repeat(None));
                let mut params = UriParams::default();
                for (segment, fragment) in path
                    .split('/')
                    .map(Some)
                    .chain(std::iter::repeat(None))
                    .zip(fragments_iter)
                {
                    match (segment, fragment) {
                        (Some(segment), Some(fragment)) => match fragment {
                            PathFragment::Literal(literal) => {
                                if !literal.eq_ignore_ascii_case(segment) {
                                    return PathMatch::None;
                                }
                            }
                            PathFragment::Param(name) => {
                                if segment.is_empty() {
                                    return PathMatch::None;
                                }
                                let segment = percent_encoding::percent_decode(segment.as_bytes())
                                    .decode_utf8()
                                    .map(Into::into)
                                    .unwrap_or_else(|_| segment.into());
                                params.insert(name.clone(), segment);
                            }
                            PathFragment::Glob => {
                                params.append_glob(segment);
                            }
                        },
                        (None, None) => {
                            break;
                        }
                        (Some(segment), None) => {
                            if params.glob().is_none() {
                                return PathMatch::None;
                            }
                            params.append_glob(segment);
                        }
                        _ => {
                            return PathMatch::None;
                        }
                    }
                }

                PathMatch::WithParams(params)
            }
        }
    }
}

impl<Body> rama_core::matcher::Matcher<Request<Body>> for PathMatcher {
    fn matches(&self, ext: Option<&mut Extensions>, req: &Request<Body>) -> bool {
        self.matches_path(ext, req.uri().path())
    }
}

#[derive(Debug, Clone)]
enum PathMatch {
    None,
    Literal,
    WithParams(UriParams),
}

#[cfg(test)]
mod test {
    use super::*;
    use rama_utils::str::arcstr::arcstr;

    #[test]
    fn test_path_matcher_match_path() {
        struct TestCase {
            path: &'static str,
            matcher_path: &'static str,
            result: PathMatch,
        }

        impl TestCase {
            fn some(
                path: &'static str,
                matcher_path: &'static str,
                result: Option<UriParams>,
            ) -> Self {
                Self {
                    path,
                    matcher_path,
                    result: result
                        .map(PathMatch::WithParams)
                        .unwrap_or(PathMatch::Literal),
                }
            }

            fn none(path: &'static str, matcher_path: &'static str) -> Self {
                Self {
                    path,
                    matcher_path,
                    result: PathMatch::None,
                }
            }
        }

        let test_cases = vec![
            TestCase::some("/", "/", None),
            TestCase::some("", "/", None),
            TestCase::some("/", "", None),
            TestCase::some("", "", None),
            TestCase::some("/foo", "/foo", None),
            TestCase::some("/foo", "//foo//", None),
            TestCase::some("/*foo", "/*foo", None),
            TestCase::some("/foo/*bar/baz", "/foo/*bar/baz", None),
            TestCase::none("/foo/*bar/baz", "/foo/*bar"),
            TestCase::none("/", "/{foo}"),
            TestCase::some(
                "/",
                "/*",
                Some(UriParams {
                    glob: Some(ArcStr::from("/")),
                    ..UriParams::default()
                }),
            ),
            TestCase::none("/", "//{foo}"),
            TestCase::none("", "/{foo}"),
            TestCase::none("/foo", "/bar"),
            TestCase::some(
                "/person/glen%20dc/age",
                "/person/{name}/age",
                Some(UriParams {
                    params: Some({
                        let mut params = HashMap::new();
                        params.insert(arcstr!("name"), arcstr!("glen dc"));
                        params
                    }),
                    ..UriParams::default()
                }),
            ),
            TestCase::none("/foo", "/bar"),
            TestCase::some("/foo", "foo", None),
            TestCase::some("/foo/bar/", "foo/bar", None),
            TestCase::none("/foo/bar/", "foo/baz"),
            TestCase::some("/foo/bar/", "/foo/bar", None),
            TestCase::some("/foo/bar", "/foo/bar", None),
            TestCase::some("/foo/bar", "foo/bar", None),
            TestCase::some("/book/oxford-dictionary/author", "/book/{title}/author", {
                let mut params = UriParams::default();
                params.insert(arcstr!("title"), arcstr!("oxford-dictionary"));
                Some(params)
            }),
            TestCase::some("/book/oxford-dictionary/author", "/book/{title}/author", {
                let mut params = UriParams::default();
                params.insert(arcstr!("title"), arcstr!("oxford-dictionary"));
                Some(params)
            }),
            TestCase::some(
                "/book/oxford-dictionary/author/0",
                "/book/{title}/author/{index}",
                {
                    let mut params = UriParams::default();
                    params.insert(arcstr!("title"), arcstr!("oxford-dictionary"));
                    params.insert(arcstr!("index"), arcstr!("0"));
                    Some(params)
                },
            ),
            TestCase::some(
                "/book/oxford-dictionary/author/1",
                "/book/{title}/author/{index}",
                {
                    let mut params = UriParams::default();
                    params.insert(arcstr!("title"), arcstr!("oxford-dictionary"));
                    params.insert(arcstr!("index"), arcstr!("1"));
                    Some(params)
                },
            ),
            TestCase::none("/book/oxford-dictionary", "/book/{title}/author"),
            TestCase::none(
                "/book/oxford-dictionary/author/birthdate",
                "/book/{title}/author",
            ),
            TestCase::none("oxford-dictionary/author", "/book/{title}/author"),
            TestCase::none("/foo", "/"),
            TestCase::none("/foo", "/*f"),
            TestCase::some(
                "/foo",
                "/*",
                Some(UriParams {
                    glob: Some("/foo".into()),
                    ..UriParams::default()
                }),
            ),
            TestCase::some(
                "/assets/css/reset.css",
                "/assets/*",
                Some(UriParams {
                    glob: Some("/css/reset.css".into()),
                    ..UriParams::default()
                }),
            ),
            TestCase::some("/assets/eu/css/reset.css", "/assets/{local}/*", {
                let mut params = UriParams::default();
                params.insert(arcstr!("local"), arcstr!("eu"));
                params.glob = Some("/css/reset.css".into());
                Some(params)
            }),
            TestCase::some("/assets/eu/css/reset.css", "/assets/:local/css/*", {
                let mut params = UriParams::default();
                params.insert(arcstr!("local"), arcstr!("eu"));
                params.glob = Some("/reset.css".into());
                Some(params)
            }),
        ];
        for test_case in test_cases.into_iter() {
            let matcher = PathMatcher::new(test_case.matcher_path);
            let result = matcher.matches_path_inner(test_case.path);
            match (result.clone(), test_case.result.clone()) {
                (PathMatch::None, PathMatch::None) | (PathMatch::Literal, PathMatch::Literal) => (),
                (PathMatch::WithParams(result), PathMatch::WithParams(expected_result)) => {
                    assert_eq!(
                        result.params,
                        expected_result.params,
                        "unexpected result params: ({:?})({}).matcher({}) => {:?} != {:?}",
                        matcher,
                        test_case.matcher_path,
                        test_case.path,
                        result.params,
                        expected_result.params,
                    );
                    assert_eq!(
                        result.glob,
                        expected_result.glob,
                        "unexpected result glob: ({:?})({}).matcher({}) => {:?} != {:?}",
                        matcher,
                        test_case.matcher_path,
                        test_case.path,
                        result.glob,
                        expected_result.glob,
                    );
                }
                _ => {
                    panic!(
                        "unexpected result: ({:?})({}).matcher({}) => {:?} != {:?}",
                        matcher, test_case.matcher_path, test_case.path, result, test_case.result
                    )
                }
            }
        }
    }

    #[test]
    fn test_path_matcher_match_path_literal() {
        for (prefix, path, is_match) in [
            ("", "", true),
            ("/", "/", true),
            ("/", "", true),
            ("", "/", true),
            ("/foo", "/", false),
            ("/foo", "", false),
            ("/", "/foo", false),
            ("", "/foo", false),
            ("/foo", "/foo", true),
            ("/*/foo", "/*/foo", true),
            ("/*/foo", "/*/foo/", true),
            ("/*/foo/", "/*/foo/", true),
            ("/*/foo/", "/*/foo", true),
            ("/*/foo/", "/bar/foo", false),
            ("/bar/foo/", "/bar/foo/baz", false),
            ("/bar/foo", "/bar/foo/baz", false),
            ("/bar/foo*", "/bar/foo/baz", false),
            ("/FoO/42", "/foo/42/1", false),
            ("/FoO/42", "/foo/42/", true),
        ] {
            let matcher = PathMatcher::new_literal(prefix);
            match (matcher.matches_path_inner(path), is_match) {
                (PathMatch::Literal, true) | (PathMatch::None, false) => (),
                (result, is_match) => {
                    panic!(
                        "unexpected result for path '{path}: {result:?} (is_match: {is_match}); matcher = {matcher:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_path_matcher_match_path_prefix() {
        for (prefix, path, is_match) in [
            ("", "", true),
            ("/", "/", true),
            ("/", "", true),
            ("", "/", true),
            ("/foo", "/", false),
            ("/foo", "", false),
            ("/", "/foo", true),
            ("", "/foo", true),
            ("/foo", "/foo", true),
            ("/*/foo", "/*/foo", true),
            ("/*/foo", "/*/foo/", true),
            ("/*/foo/", "/*/foo/", true),
            ("/*/foo/", "/*/foo", true),
            ("/*/foo/", "/bar/foo", false),
            ("/bar/foo/", "/bar/foo/baz", true),
            ("/bar/foo", "/bar/foo/baz", true),
            ("/bar/foo*", "/bar/foo/baz", false),
            ("/FoO/42", "/foo/42/1", true),
        ] {
            let matcher = PathMatcher::new_prefix(prefix);
            match (matcher.matches_path_inner(path), is_match) {
                (PathMatch::Literal, true) | (PathMatch::None, false) => (),
                (result, is_match) => {
                    panic!(
                        "unexpected result for path '{path}: {result:?} (is_match: {is_match}); matcher = {matcher:?}"
                    );
                }
            }
        }
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
