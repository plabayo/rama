use super::Matcher;
use crate::{http::Request, service::Context};
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
/// parameters that are inserted in the [`Context`],
/// in case the [`PathFilter`] found a match for the given [`Request`].
pub struct UriParams {
    params: Option<HashMap<String, String>>,
    glob: Option<String>,
}

impl UriParams {
    pub(crate) fn insert(&mut self, name: String, value: String) {
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

    pub(crate) fn insert_glob(&mut self, value: String) {
        self.glob = Some(value);
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

        let path_parts: Vec<_> = path.split('/').collect();
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
        match &self.matcher {
            PathMatcher::Literal(literal) => {
                if literal.eq_ignore_ascii_case(path.trim().trim_matches('/')) {
                    Some(UriParams::default())
                } else {
                    None
                }
            }
            PathMatcher::FragmentList(fragments) => {
                let fragments_iter = fragments.iter().map(Some).chain(std::iter::repeat(None));
                let mut params = UriParams::default();
                for (segment, fragment) in path.split('/').map(Some).zip(fragments_iter) {
                    match (segment, fragment) {
                        (Some(segment), Some(fragment)) => match fragment {
                            PathFragment::Literal(literal) => {
                                if !literal.eq_ignore_ascii_case(segment) {
                                    return None;
                                }
                            }
                            PathFragment::Param(name) => {
                                params.insert(name.to_owned(), segment.to_owned());
                            }
                            PathFragment::Glob => {
                                params.insert_glob(segment.to_owned());
                            }
                        },
                        (None, None) => {
                            break;
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
    fn matches(&self, ctx: &mut Context<State>, req: &Request) -> bool {
        match self.matches_path(req.uri().path()) {
            None => false,
            Some(params) => {
                ctx.insert(params);
                true
            }
        }
    }
}

#[cfg(test)]
mod test {
    // TODO
}
