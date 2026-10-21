use super::{UriMatchError, UriMatchReplace};
use crate::std::borrow::Cow;
use crate::{Protocol, address::HostWithOptPort, uri::Uri};

/// Replace a URI's scheme and authority, preserving its path, query and fragment.
///
/// Useful for forwarding to a fixed origin. Incoming userinfo is discarded;
/// the replacement authority contains only the configured host and port.
/// The asterisk request-target is left unchanged (no match).
#[derive(Debug, Clone)]
pub struct UriMatchReplaceOrigin {
    scheme: Protocol,
    address: HostWithOptPort,
}

impl UriMatchReplaceOrigin {
    /// Create a rule that replaces the scheme and host/port without userinfo.
    #[must_use]
    pub fn new(scheme: Protocol, address: impl Into<HostWithOptPort>) -> Self {
        Self {
            scheme,
            address: address.into(),
        }
    }
}

impl UriMatchReplace for UriMatchReplaceOrigin {
    fn match_replace_uri<'a>(
        &self,
        mut uri: Cow<'a, Uri>,
    ) -> Result<Cow<'a, Uri>, UriMatchError<'a>> {
        if uri.is_asterisk() {
            return Err(UriMatchError::NoMatch(uri));
        }

        let rewritten = uri.to_mut();
        rewritten.set_scheme(self.scheme.clone());
        rewritten.set_authority(self.address.clone().into());
        Ok(uri)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_asterisk_request_target() {
        let rule = UriMatchReplaceOrigin::new(
            Protocol::HTTP,
            "example.com".parse::<HostWithOptPort>().unwrap(),
        );
        let uri = Uri::from_static("*");
        assert!(
            matches!(rule.match_replace_uri(Cow::Borrowed(&uri)), Err(UriMatchError::NoMatch(original)) if original.as_ref() == &uri)
        );
    }

    #[test]
    fn replaces_origin_without_changing_encoded_path_query_or_fragment() {
        for target in ["example.org:8080", "127.0.0.1:8080", "[::1]:8080"] {
            let rule = UriMatchReplaceOrigin::new(
                Protocol::HTTP,
                target.parse::<HostWithOptPort>().unwrap(),
            );
            for input in [
                "/a%2Fb?x=%26&empty=#keep",
                "https://user:pass@old.example:443/a%2Fb?x=%26&empty=#keep",
            ] {
                let uri = Uri::parse(input).unwrap();
                for input in [Cow::Borrowed(&uri), Cow::Owned(uri.clone())] {
                    let output = rule.match_replace_uri(input).unwrap();
                    assert_eq!(
                        output.to_string(),
                        format!("http://{target}/a%2Fb?x=%26&empty=#keep")
                    );
                    assert!(output.userinfo().is_none());
                }
            }
        }
    }
}
