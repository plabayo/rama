use rama_http_types::Uri;

use super::UriMatchReplaceRule;

#[derive(Debug)]
pub struct UriMatchReplaceRuleset {
    rules: Vec<UriMatchReplaceRule>,
    include_query: bool,
}

impl UriMatchReplaceRuleset {
    pub fn try_match_replace_uri(&self, uri: &Uri) -> Option<Uri> {
        let s = super::rule::uri_to_smoll_str(uri, self.include_query);
        let mut v = Vec::new();
        for rule in self.rules.iter() {
            if let Some(uri) = rule.try_match_replace_uri_str_with_buffer(&s, &mut v) {
                return Some(uri);
            }
        }
        None
    }
}

// TODO:
// - add constructors
// - add setters
// - add docs
// - add tests
