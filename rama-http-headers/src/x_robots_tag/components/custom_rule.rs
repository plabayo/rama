use crate::util::HeaderValueString;

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
/// A non-std rule that we are not aware of. An unknown rule.
///
/// Note that parsing key-value custom rules is not supported,
/// only boolean rules.
///
/// Displaying key-value custom rules _is_ supported.
pub struct CustomRule {
    key: HeaderValueString,
    value: Option<HeaderValueString>,
}

impl CustomRule {
    pub fn new_boolean_directive(key: HeaderValueString) -> Self {
        Self { key, value: None }
    }

    pub fn new_key_value_directive(key: HeaderValueString, value: HeaderValueString) -> Self {
        Self {
            key,
            value: Some(value),
        }
    }
}

impl CustomRule {
    pub fn as_tuple(&self) -> (&HeaderValueString, Option<&HeaderValueString>) {
        (&self.key, self.value.as_ref())
    }
}
