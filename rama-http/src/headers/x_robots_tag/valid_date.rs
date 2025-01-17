use rama_core::error::OpaqueError;
use regex::Regex;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;

// "A date must be specified in a format such as RFC 822, RFC 850, or ISO 8601."
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidDate(String);

impl ValidDate {
    pub fn new(date: &str) -> Option<Self> {
        let new = Self(date.to_owned());
        match new.is_valid() {
            true => Some(new),
            false => None,
        }
    }

    pub fn date(&self) -> &str {
        &self.0
    }

    pub fn into_date(self) -> String {
        self.0
    }

    pub fn is_valid(&self) -> bool {
        let rfc_822 = r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s(0[1-9]|[12]\d|3[01])\s(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{2}\s([01]\d|2[0-4]):([0-5]\d|60):([0-5]\d|60)\s(UT|GMT|EST|EDT|CST|CDT|MST|MDT|PST|PDT|[+-]\d{4})$";
        let rfc_850 = r"^(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday),\s(0?[1-9]|[12]\d|3[01])-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-\d{2}\s([01]\d|2[0-4]):([0-5]\d|60):([0-5]\d|60)\s(UT|GMT|EST|EDT|CST|CDT|MST|MDT|PST|PDT|[+-]\d{4})$";
        let iso_8601 = r"^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])\s([01]\d|2[0-4]):([0-5]\d|60):([0-5]\d|60).\d{3}$";

        check_is_valid(rfc_822, self.date())
            || check_is_valid(rfc_850, self.date())
            || check_is_valid(iso_8601, self.date())
    }
}

fn check_is_valid(re: &str, date: &str) -> bool {
    Regex::new(re)
        .and_then(|r| Ok(r.is_match(date)))
        .unwrap_or(false)
}

impl FromStr for ValidDate {
    type Err = OpaqueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s).ok_or_else(|| OpaqueError::from_display("Invalid date format"))
    }
}

impl Display for ValidDate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self)
    }
}

impl Deref for ValidDate {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.date()
    }
}
