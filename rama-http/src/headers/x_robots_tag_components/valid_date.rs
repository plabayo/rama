use chrono::{DateTime, Utc};
use rama_core::error::{ErrorContext, OpaqueError};
use std::ops::Deref;
use std::str::FromStr;

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

impl FromStr for ValidDate {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ValidDate::new(
            DateTime::parse_from_rfc3339(s)
                .or_else(|_| {
                    DateTime::parse_from_rfc2822(s)
                        .or_else(|_| DateTime::parse_from_str(s, "%A, %d-%b-%y %T %Z"))
                })
                .with_context(|| "Failed to parse date")?
                .with_timezone(&Utc),
        )
    }
}
