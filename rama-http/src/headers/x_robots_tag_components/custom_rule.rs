use crate::headers::util::value_string::HeaderValueString;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CustomRule {
    key: HeaderValueString,
    value: Option<HeaderValueString>,
}

impl CustomRule {
    pub(super) fn as_tuple(&self) -> (&HeaderValueString, Option<&HeaderValueString>) {
        (&self.key, self.value.as_ref())
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
