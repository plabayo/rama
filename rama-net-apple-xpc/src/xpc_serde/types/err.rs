use std::fmt;

use serde::de;

use crate::XpcError;

#[derive(Debug)]
pub(crate) struct SerError(String);

impl fmt::Display for SerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SerError {}

impl serde::ser::Error for SerError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self(msg.to_string())
    }
}

impl From<SerError> for XpcError {
    fn from(e: SerError) -> Self {
        Self::SerializationFailed(rama_utils::str::arcstr::ArcStr::from(e.0))
    }
}

#[derive(Debug)]
pub(crate) struct DeError(String);

impl fmt::Display for DeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DeError {}

impl de::Error for DeError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self(msg.to_string())
    }
}

impl From<DeError> for XpcError {
    fn from(e: DeError) -> Self {
        Self::DeserializationFailed(rama_utils::str::arcstr::ArcStr::from(e.0))
    }
}
