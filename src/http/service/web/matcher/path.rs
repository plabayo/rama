use super::Matcher;
use crate::{
    http::Request,
    service::{context::Extensions, Context},
};
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
/// parameters that are inserted in the [`Context`],
/// in case the [`PathFilter`] found a match for the given [`Request`].
pub struct UriParams {
    params: Option<HashMap<String, String>>,
    glob: Option<String>,
}

impl UriParams {
    fn insert(&mut self, name: String, value: String) {
        self.params
            .get_or_insert_with(HashMap::new)
            .insert(name, value);
    }

    /// Some str slice will be returned in case a param could be found for the given name.
    pub fn get(&self, name: impl AsRef<str>) -> Option<&str> {
        self.params
            .as_ref()
            .and_then(|params| params.get(name.as_ref()))
            .map(String::as_str)
    }

    fn append_glob(&mut self, value: &str) {
        match self.glob {
            Some(ref mut glob) => {
                glob.push('/');
                glob.push_str(value);
            }
            None => self.glob = Some(format!("/{}", value)),
        }
    }

    /// Some str slice will be returned in case a glob value was captured
    /// for the last part of the Path that was filtered on.
    pub fn glob(&self) -> Option<&str> {
        self.glob.as_deref()
    }
}

#[derive(Debug, Clone)]
enum PathFragment {
    Literal(String),
    Param(String),
    Glob,
}

#[derive(Debug, Clone)]
enum PathMatcher {
    Literal(String),
    FragmentList(Vec<PathFragment>),
}

#[derive(Debug, Clone)]
/// Filter based on the URI path.
pub struct PathFilter {
    matcher: PathMatcher,
}

impl PathFilter {
    /// Create a new [`PathFilter`] for the given path.
    pub fn new(path: impl AsRef<str>) -> Self {
        let path = path.as_ref();
        let path = path.trim().trim_matches('/');

        if !path.contains([':', '*']) {
            return Self {
                matcher: PathMatcher::Literal(path.to_lowercase()),
            };
        }

        let path_parts: Vec<_> = path.split('/').filter(|s| !s.is_empty()).collect();
        let fragment_length = path_parts.len();
        if fragment_length == 1 && path_parts[0].is_empty() {
            return Self {
                matcher: PathMatcher::FragmentList(vec![PathFragment::Glob]),
            };
        }

        let fragments: Vec<PathFragment> = path_parts
            .into_iter()
            .enumerate()
            .filter_map(|(index, s)| {
                if s.is_empty() {
                    return None;
                }
                if s.starts_with(':') {
                    Some(PathFragment::Param(
                        s.trim_start_matches(':').to_lowercase(),
                    ))
                } else if s == "*" && index == fragment_length - 1 {
                    Some(PathFragment::Glob)
                } else {
                    Some(PathFragment::Literal(s.to_lowercase()))
                }
            })
            .collect();

        Self {
            matcher: PathMatcher::FragmentList(fragments),
        }
    }

    pub(crate) fn matches_path(&self, path: &str) -> Option<UriParams> {
        let path = path.trim().trim_matches('/');
        match &self.matcher {
            PathMatcher::Literal(literal) => {
                if literal.eq_ignore_ascii_case(path) {
                    Some(UriParams::default())
                } else {
                    None
                }
            }
            PathMatcher::FragmentList(fragments) => {
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
                                    return None;
                                }
                            }
                            PathFragment::Param(name) => {
                                if segment.is_empty() {
                                    return None;
                                }
                                params.insert(name.to_owned(), segment.to_owned());
                            }
                            PathFragment::Glob => {
                                params.append_glob(segment);
                            }
                        },
                        (None, None) => {
                            break;
                        }
                        (Some(segment), None) => {
                            params.glob()?;
                            params.append_glob(segment);
                        }
                        _ => {
                            return None;
                        }
                    }
                }

                Some(params)
            }
        }
    }
}

impl<State> Matcher<State> for PathFilter {
    fn matches(&self, ext: &mut Extensions, _ctx: &Context<State>, req: &Request) -> bool {
        match self.matches_path(req.uri().path()) {
            None => false,
            Some(params) => {
                ext.insert(params);
                true
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_path_filter_match_path() {
        struct TestCase {
            path: &'static str,
            filter_path: &'static str,
            result: Option<UriParams>,
        }

        impl TestCase {
            fn some(path: &'static str, filter_path: &'static str, result: UriParams) -> Self {
                Self {
                    path,
                    filter_path,
                    result: Some(result),
                }
            }

            fn none(path: &'static str, filter_path: &'static str) -> Self {
                Self {
                    path,
                    filter_path,
                    result: None,
                }
            }
        }

        let test_cases = vec![
            TestCase::some("/", "/", UriParams::default()),
            TestCase::some("", "/", UriParams::default()),
            TestCase::some("/", "", UriParams::default()),
            TestCase::some("", "", UriParams::default()),
            TestCase::some("/foo", "/foo", UriParams::default()),
            TestCase::some("/foo", "//foo//", UriParams::default()),
            TestCase::some("/*foo", "/*foo", UriParams::default()),
            TestCase::some("/foo/*bar/baz", "/foo/*bar/baz", UriParams::default()),
            TestCase::none("/foo/*bar/baz", "/foo/*bar"),
            TestCase::none("/", "/:foo"),
            TestCase::some(
                "/",
                "/*",
                UriParams {
                    glob: Some("/".to_owned()),
                    ..UriParams::default()
                },
            ),
            TestCase::none("/", "//:foo"),
            TestCase::none("", "/:foo"),
            TestCase::none("/foo", "/bar"),
            TestCase::some("/foo", "foo", UriParams::default()),
            TestCase::some("/foo/bar/", "foo/bar", UriParams::default()),
            TestCase::none("/foo/bar/", "foo/baz"),
            TestCase::some("/foo/bar/", "/foo/bar", UriParams::default()),
            TestCase::some("/foo/bar", "/foo/bar", UriParams::default()),
            TestCase::some("/foo/bar", "foo/bar", UriParams::default()),
            TestCase::some("/book/oxford-dictionary/author", "/book/:title/author", {
                let mut params = UriParams::default();
                params.insert("title".to_owned(), "oxford-dictionary".to_owned());
                params
            }),
            TestCase::some(
                "/book/oxford-dictionary/author/0",
                "/book/:title/author/:index",
                {
                    let mut params = UriParams::default();
                    params.insert("title".to_owned(), "oxford-dictionary".to_owned());
                    params.insert("index".to_owned(), "0".to_owned());
                    params
                },
            ),
            TestCase::none("/book/oxford-dictionary", "/book/:title/author"),
            TestCase::none(
                "/book/oxford-dictionary/author/birthdate",
                "/book/:title/author",
            ),
            TestCase::none("oxford-dictionary/author", "/book/:title/author"),
            TestCase::none("/foo", "/"),
            TestCase::none("/foo", "/*f"),
            TestCase::some(
                "/foo",
                "/*",
                UriParams {
                    glob: Some("/foo".to_owned()),
                    ..UriParams::default()
                },
            ),
            TestCase::some(
                "/assets/css/reset.css",
                "/assets/*",
                UriParams {
                    glob: Some("/css/reset.css".to_owned()),
                    ..UriParams::default()
                },
            ),
            TestCase::some("/assets/eu/css/reset.css", "/assets/:local/*", {
                let mut params = UriParams::default();
                params.insert("local".to_owned(), "eu".to_owned());
                params.glob = Some("/css/reset.css".to_owned());
                params
            }),
            TestCase::some("/assets/eu/css/reset.css", "/assets/:local/css/*", {
                let mut params = UriParams::default();
                params.insert("local".to_owned(), "eu".to_owned());
                params.glob = Some("/reset.css".to_owned());
                params
            }),
        ];
        for test_case in test_cases.into_iter() {
            let filter = PathFilter::new(test_case.filter_path);
            let result = filter.matches_path(test_case.path);
            match (result.as_ref(), test_case.result.as_ref()) {
                (None, None) => (),
                (Some(result), Some(expected_result)) => {
                    assert_eq!(
                        result.params,
                        expected_result.params,
                        "unexpected result params: ({}).filter({}) => {:?} != {:?}",
                        test_case.filter_path,
                        test_case.path,
                        result.params,
                        expected_result.params,
                    );
                    assert_eq!(
                        result.glob, expected_result.glob,
                        "unexpected result glob: ({}).filter({}) => {:?} != {:?}",
                        test_case.filter_path, test_case.path, result.glob, expected_result.glob,
                    );
                }
                _ => {
                    panic!(
                        "unexpected result: ({}).filter({}) => {:?} != {:?}",
                        test_case.filter_path, test_case.path, result, test_case.result
                    )
                }
            }
        }
    }
}
