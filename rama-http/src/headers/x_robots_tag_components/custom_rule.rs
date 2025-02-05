use crate::headers::util::value_string::{FromStrError, HeaderValueString};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CustomRule {
    key: HeaderValueString,
    value: Option<HeaderValueString>,
}

impl CustomRule {
    pub(super) fn new(key: &str) -> Result<Self, FromStrError> {
        Ok(Self {
            key: key.parse()?,
            value: None,
        })
    }

    pub(super) fn with_value(key: &str, value: &str) -> Result<Self, FromStrError> {
        Ok(Self {
            key: key.parse()?,
            value: Some(value.parse()?),
        })
    }

    pub(super) fn key(&self) -> &HeaderValueString {
        &self.key
    }

    pub(super) fn value(&self) -> Option<&HeaderValueString> {
        self.value.as_ref()
    }

    pub(super) fn as_tuple(&self) -> (&HeaderValueString, &Option<HeaderValueString>) {
        (&self.key, &self.value)
    }
}

impl From<HeaderValueString> for CustomRule {
    fn from(key: HeaderValueString) -> Self {
        Self { key, value: None }
    }
}

impl From<(HeaderValueString, HeaderValueString)> for CustomRule {
    fn from(key_value: (HeaderValueString, HeaderValueString)) -> Self {
        Self {
            key: key_value.0,
            value: Some(key_value.1),
        }
    }
}
