use crate::headers::util::value_string::{FromStrError, HeaderValueString};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustomRule {
    key: HeaderValueString,
    value: Option<HeaderValueString>,
}

impl CustomRule {
    pub fn new(key: &str) -> Result<Self, FromStrError> {
        Ok(Self {
            key: key.parse()?,
            value: None,
        })
    }

    pub fn with_value(key: &str, value: &str) -> Result<Self, FromStrError> {
        Ok(Self {
            key: key.parse()?,
            value: Some(value.parse()?),
        })
    }

    pub fn key(&self) -> &HeaderValueString {
        &self.key
    }

    pub fn value(&self) -> Option<&HeaderValueString> {
        self.value.as_ref()
    }
}
