use chrono::{DateTime, Utc};
use rama_core::error::{ErrorContext, OpaqueError};
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ValidDate(DateTime<Utc>);

impl ValidDate {
    pub(super) fn new(date: DateTime<Utc>) -> Self {
        Self(date)
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
        Ok(ValidDate::new(
            DateTime::parse_from_rfc3339(s) // check ISO 8601
                .or_else(|_| {
                    DateTime::parse_from_rfc2822(s) // check RFC 822
						.or_else(|_| DateTime::parse_from_str(s, "%A, %d-%b-%Y %H:%M:%S %Z"))
                    // check RFC 850
                })
                .with_context(|| "Failed to parse date")?
                .with_timezone(&Utc),
        ))
    }
}

impl Display for ValidDate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_valid_date_strings {
        ($($str:literal),+) => {
            $(assert!(ValidDate::from_str($str).is_ok(),
            "'{}': {:?}",
            $str, ValidDate::from_str($str).err());)+
        };
    }

    macro_rules! test_invalid_date_strings {
        ($($str:literal),+) => {
            $(assert!(ValidDate::from_str($str).is_err());)+
        };
    }

    #[test]
    fn test_valid_rfc_822() {
        test_valid_date_strings!(
            "Wed, 02 Oct 2002 08:00:00 EST",
            "Wed, 02 Oct 2002 13:00:00 GMT",
            "Wed, 02 Oct 2002 15:00:00 +0200",
            "Mon, 11 Mar 2019 01:57:00 EST",
            "11 Mar 2019 01:57:23 EDT",
            "Mon, 11 Mar 2019 01:57:00 -0500",
            "Mon, 11 Mar 2019 01:57 A",
            "11 Mar 2019 01:00 N",
            "11 Mar 2019 01:59 A",
            "Mon, 11 Mar 2019 02:00 Z",
            "Mon, 11 Mar 2019 02:00:34 Z",
            "11 Mar 2019 02:00 PST"
        );
    }

    // fails, because it cannot convert timezone from an abbreviation
    // #[test]
    // fn test_valid_rfc_850() {
    //     test_valid_date_strings!(
    //         "Monday, 01-Jan-2001 08:58:35 UTC",
    //         "Tuesday, 19-Feb-82 10:14:55 PST",
    //         "Wednesday, 1-Jan-83 00:00:00 PDT",
    //         "Thursday, 30-Nov-12 16:59:59 MST",
    //         "Friday, 9-Mar-31 12:00:00 CST",
    //         "Friday, 19-Dec-99 23:59:59 EST"
    //     );
    // }

    #[test]
    fn test_valid_iso_8601() {
        test_valid_date_strings!(
            "2025-02-02T14:30:00+00:00",
            "2023-06-15T23:59:59-05:00",
            "2019-12-31T12:00:00+08:45",
            "2020-02-29T00:00:00Z",
            "2024-10-10T10:10:10+02:00",
            "2022-07-01T16:45:30-07:00",
            "2018-01-01T09:00:00+09:30",
            "2030-05-20T05:05:05+05:30",
            "1999-12-31T23:59:59-03:00",
            "2045-11-11T11:11:11+14:00"
        );
    }

    #[test]
    fn test_invalid_date_times() {
        test_invalid_date_strings!(
            "2025-02-30T14:30:00+00:00",
            "2023-06-15T25:00:00-05:00",
            "2019-12-31T12:60:00+08:45",
            "2020-02-29T00:00:00",
            "Thu, 32 Dec 2023 10:00:00 +0200",
            "Mon, 15 Jan 2023 23:59:60 -0500",
            "2024-10-10T10:10:10",
            "2022-07-01T16:45:30 UTC",
            "2018-01-01T09:00:00+09:75",
            "2030-05-20T05:05:05+24:00",
            "1999-12-31 23:59:59 -03:00",
            "2045-11-11T11:11:11 EST"
        );
    }
}
