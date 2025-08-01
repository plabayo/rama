use std::fmt;

use rama_http_types::{HeaderName, HeaderValue};

use crate::util::IterExt;
use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};

/// The `Expect` header.
///
/// > The "Expect" header field in a request indicates a certain set of
/// > behaviors (expectations) that need to be supported by the server in
/// > order to properly handle this request.  The only such expectation
/// > defined by this specification is 100-continue.
/// >
/// >    Expect  = "100-continue"
///
/// # Example
///
/// ```
/// use rama_http_headers::Expect;
///
/// let expect = Expect::CONTINUE;
/// ```
#[derive(Clone, PartialEq)]
pub struct Expect(());

impl Expect {
    /// "100-continue"
    pub const CONTINUE: Self = Self(());
}

impl TypedHeader for Expect {
    fn name() -> &'static HeaderName {
        &::rama_http_types::header::EXPECT
    }
}

impl HeaderDecode for Expect {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        values
            .just_one()
            .and_then(|value| {
                if value == "100-continue" {
                    Some(Self::CONTINUE)
                } else {
                    None
                }
            })
            .ok_or_else(Error::invalid)
    }
}

impl HeaderEncode for Expect {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(::std::iter::once(HeaderValue::from_static("100-continue")));
    }
}

impl fmt::Debug for Expect {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("Expect").field(&"100-continue").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_decode;
    use super::Expect;

    #[test]
    fn expect_continue() {
        assert_eq!(
            test_decode::<Expect>(&["100-continue"]),
            Some(Expect::CONTINUE),
        );
    }

    #[test]
    fn expectation_failed() {
        assert_eq!(test_decode::<Expect>(&["sandwich"]), None,);
    }

    #[test]
    fn too_many_values() {
        assert_eq!(
            test_decode::<Expect>(&["100-continue", "100-continue"]),
            None,
        );
    }
}
