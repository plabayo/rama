//! `Capsule-Protocol` (RFC 9297 §3.4).

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};
use rama_http_types::structured_fields::{BareItem, parse_item};
use rama_http_types::{HeaderName, HeaderValue};

/// Whether a request's data stream uses the Capsule Protocol.
///
/// The field is a Boolean Structured Field Item; parameters are ignored. A false value has the
/// same meaning as an absent field. Any other value type, including a repeated field (which
/// combines into a List), fails to decode and must be treated as absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapsuleProtocol(bool);

impl CapsuleProtocol {
    /// `Capsule-Protocol: ?1`.
    pub const ENABLED: Self = Self(true);

    /// Construct from the Boolean value.
    #[must_use]
    pub const fn new(enabled: bool) -> Self {
        Self(enabled)
    }

    /// Whether the Capsule Protocol is in use.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.0
    }
}

impl TypedHeader for CapsuleProtocol {
    fn name() -> &'static HeaderName {
        &rama_http_types::header::CAPSULE_PROTOCOL
    }
}

impl HeaderDecode for CapsuleProtocol {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        let value = values.next().ok_or_else(Error::invalid)?;
        if values.next().is_some() {
            return Err(Error::invalid());
        }
        match parse_item(value.as_bytes()) {
            Ok(BareItem::Boolean(enabled)) => Ok(Self(enabled)),
            _ => Err(Error::invalid()),
        }
    }
}

impl HeaderEncode for CapsuleProtocol {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(std::iter::once(HeaderValue::from_static(if self.0 {
            "?1"
        } else {
            "?0"
        })));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HeaderMapExt;
    use rama_http_types::HeaderMap;

    fn decode(values: &[&'static str]) -> Option<CapsuleProtocol> {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(
                &rama_http_types::header::CAPSULE_PROTOCOL,
                HeaderValue::from_static(value),
            );
        }
        headers.typed_get()
    }

    #[test]
    fn boolean_items_with_ignored_parameters() {
        assert_eq!(decode(&["?1"]), Some(CapsuleProtocol::ENABLED));
        assert_eq!(decode(&["?0"]), Some(CapsuleProtocol::new(false)));
        assert_eq!(decode(&["?1;future=1"]), Some(CapsuleProtocol::ENABLED));
        assert_eq!(decode(&[" ?1 "]), Some(CapsuleProtocol::ENABLED));
    }

    #[test]
    fn other_types_and_repetition_are_treated_as_absent() {
        for values in [
            &["1"][..],
            &["\"?1\""],
            &["true"],
            &["?1, ?1"],
            &["?1", "?1"],
            &["?"],
            &[""],
        ] {
            assert_eq!(decode(values), None, "{values:?}");
        }
    }

    #[test]
    fn encodes_canonical_booleans() {
        let mut headers = HeaderMap::new();
        headers.typed_insert(CapsuleProtocol::ENABLED);
        assert_eq!(headers[&rama_http_types::header::CAPSULE_PROTOCOL], "?1");
        headers.typed_insert(CapsuleProtocol::new(false));
        assert_eq!(headers[&rama_http_types::header::CAPSULE_PROTOCOL], "?0");
    }
}
