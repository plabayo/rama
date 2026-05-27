use std::collections::BTreeMap;

use rama_utils::str::arcstr::{ArcStr, arcstr};

use crate::{XpcError, XpcMessage};

const SELECTOR_KEY: &str = "$selector";
const ARGUMENTS_KEY: &str = "$arguments";

/// An NSXPC-inspired structured XPC call.
///
/// `XpcCall` serializes to and from a dictionary of the form:
///
/// ```json
/// { "$selector": "methodName:withReply:", "$arguments": [ ... ] }
/// ```
///
/// This wire format is inspired by `NSXPCConnection` naming conventions.
/// The `$` prefix keeps the protocol-level keys visually distinct from
/// application-level payload keys.
///
/// # Conversion
///
/// - [`From<XpcCall> for XpcMessage`] — encodes the call into a `Dictionary`.
/// - [`TryFrom<XpcMessage> for XpcCall`] — decodes a `Dictionary` back;
///   returns [`XpcError::InvalidMessage`] if the structure does not match.
#[derive(Debug, Clone, PartialEq)]
pub struct XpcCall {
    /// The method selector, e.g. `"updateSettings:withReply:"`.
    pub selector: ArcStr,
    /// Positional arguments for the call. May be empty.
    pub arguments: Vec<XpcMessage>,
}

impl XpcCall {
    /// Create a new `XpcCall` with the given selector and no arguments.
    pub fn new(selector: impl Into<ArcStr>) -> Self {
        Self {
            selector: selector.into(),
            arguments: Vec::new(),
        }
    }

    /// Create a new `XpcCall` with the given selector and arguments.
    pub fn with_arguments(selector: impl Into<ArcStr>, arguments: Vec<XpcMessage>) -> Self {
        Self {
            selector: selector.into(),
            arguments,
        }
    }
}

impl From<XpcCall> for XpcMessage {
    fn from(call: XpcCall) -> Self {
        let mut map = BTreeMap::new();
        map.insert(
            SELECTOR_KEY.to_owned(),
            Self::String(call.selector.as_str().to_owned()),
        );
        map.insert(ARGUMENTS_KEY.to_owned(), Self::Array(call.arguments));
        Self::Dictionary(map)
    }
}

impl TryFrom<XpcMessage> for XpcCall {
    type Error = XpcError;

    fn try_from(msg: XpcMessage) -> Result<Self, Self::Error> {
        let XpcMessage::Dictionary(mut map) = msg else {
            return Err(XpcError::InvalidMessage(arcstr!(
                "XpcCall: expected a Dictionary"
            )));
        };

        let selector = match map.remove(SELECTOR_KEY) {
            Some(XpcMessage::String(s)) => ArcStr::from(s),
            Some(_) => {
                return Err(XpcError::InvalidMessage(arcstr!(
                    "XpcCall: '$selector' must be a String"
                )));
            }
            None => {
                return Err(XpcError::InvalidMessage(arcstr!(
                    "XpcCall: missing '$selector' key"
                )));
            }
        };

        let arguments = match map.remove(ARGUMENTS_KEY) {
            Some(XpcMessage::Array(args)) => args,
            Some(_) => {
                return Err(XpcError::InvalidMessage(arcstr!(
                    "XpcCall: '$arguments' must be an Array"
                )));
            }
            None => {
                return Err(XpcError::InvalidMessage(arcstr!(
                    "XpcCall: missing '$arguments' key"
                )));
            }
        };

        Ok(Self {
            selector,
            arguments,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_empty_arguments() {
        let call = XpcCall::new("ping");
        let msg: XpcMessage = call.clone().into();
        let recovered = XpcCall::try_from(msg).expect("round-trip failed");
        assert_eq!(recovered, call);
    }

    #[test]
    fn round_trip_with_arguments() {
        let args = vec![
            XpcMessage::Bool(true),
            XpcMessage::String("hello".into()),
            XpcMessage::Int64(-42),
        ];
        let call = XpcCall::with_arguments("doSomething:withReply:", args);
        let msg: XpcMessage = call.clone().into();
        let recovered = XpcCall::try_from(msg).expect("round-trip failed");
        assert_eq!(recovered, call);
    }

    #[test]
    fn encoding_keys() {
        let call = XpcCall::new("mySelector:");
        let XpcMessage::Dictionary(map) = XpcMessage::from(call) else {
            panic!("expected Dictionary");
        };
        assert!(map.contains_key(SELECTOR_KEY), "missing $selector key");
        assert!(map.contains_key(ARGUMENTS_KEY), "missing $arguments key");
        assert_eq!(map[SELECTOR_KEY], XpcMessage::String("mySelector:".into()));
        assert_eq!(map[ARGUMENTS_KEY], XpcMessage::Array(vec![]));
    }

    #[test]
    fn error_on_non_dictionary() {
        let err = XpcCall::try_from(XpcMessage::Null).unwrap_err();
        assert!(
            matches!(err, XpcError::InvalidMessage(_)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn error_on_missing_selector() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(ARGUMENTS_KEY.to_owned(), XpcMessage::Array(vec![]));
        let err = XpcCall::try_from(XpcMessage::Dictionary(map)).unwrap_err();
        assert!(matches!(err, XpcError::InvalidMessage(_)));
    }

    #[test]
    fn error_on_missing_arguments() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(SELECTOR_KEY.to_owned(), XpcMessage::String("sel".into()));
        let err = XpcCall::try_from(XpcMessage::Dictionary(map)).unwrap_err();
        assert!(matches!(err, XpcError::InvalidMessage(_)));
    }

    #[test]
    fn error_on_wrong_selector_type() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(SELECTOR_KEY.to_owned(), XpcMessage::Int64(0));
        map.insert(ARGUMENTS_KEY.to_owned(), XpcMessage::Array(vec![]));
        let err = XpcCall::try_from(XpcMessage::Dictionary(map)).unwrap_err();
        assert!(matches!(err, XpcError::InvalidMessage(_)));
    }

    #[test]
    fn error_on_wrong_arguments_type() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(SELECTOR_KEY.to_owned(), XpcMessage::String("sel".into()));
        map.insert(ARGUMENTS_KEY.to_owned(), XpcMessage::Null);
        let err = XpcCall::try_from(XpcMessage::Dictionary(map)).unwrap_err();
        assert!(matches!(err, XpcError::InvalidMessage(_)));
    }
}
