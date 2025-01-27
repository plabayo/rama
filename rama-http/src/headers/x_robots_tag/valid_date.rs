use chrono::{DateTime, Utc};
use rama_core::error::OpaqueError;
use std::ops::Deref;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ValidDate(DateTime<Utc>);

impl ValidDate {
    pub(super) fn new(date: DateTime<Utc>) -> Result<Self, OpaqueError> {
        Ok(Self(date))
    }
}

impl Deref for ValidDate {
    type Target = DateTime<Utc>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<ValidDate> for DateTime<Utc> {
    fn from(value: ValidDate) -> Self {
        value.0
    }
}

impl TryFrom<DateTime<Utc>> for ValidDate {
    type Error = OpaqueError;

    fn try_from(value: DateTime<Utc>) -> Result<Self, Self::Error> {
        ValidDate::new(value)
    }
}

impl AsRef<DateTime<Utc>> for ValidDate {
    fn as_ref(&self) -> &DateTime<Utc> {
        &self.0
    }
}

impl AsMut<DateTime<Utc>> for ValidDate {
    fn as_mut(&mut self) -> &mut DateTime<Utc> {
        &mut self.0
    }
}
