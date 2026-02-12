use ahash::HashMap;
use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Utc};
use rama_core::error::{BoxError, ErrorContext};
use rama_core::telemetry::tracing;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::sync::OnceLock;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectiveDateTime {
    value: DateTime<Utc>,
    parsed_format: Option<ParsedFormat>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParsedFormat {
    RFC3339,
    RFC2822,
    RFC850,
}

impl DirectiveDateTime {
    pub fn try_new_ymd_and_hms(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        min: u32,
        sec: u32,
    ) -> Result<Self, BoxError> {
        Utc.with_ymd_and_hms(year, month, day, hour, min, sec)
            .single()
            .context("invalid date-time input")
            .map(Into::into)
    }

    pub fn try_new_ymd(year: i32, month: u32, day: u32) -> Result<Self, BoxError> {
        Self::try_new_ymd_and_hms(year, month, day, 0, 0, 0)
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn format_rfc3339(mut self) -> Self {
            self.parsed_format = Some(ParsedFormat::RFC3339);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn format_rfc2822(mut self) -> Self {
            self.parsed_format = Some(ParsedFormat::RFC2822);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn format_rfc855(mut self) -> Self {
            self.parsed_format = Some(ParsedFormat::RFC850);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        pub fn format_default(mut self) -> Self {
            self.parsed_format = None;
            self
        }
    }

    #[must_use]
    pub fn date_time(&self) -> &DateTime<Utc> {
        &self.value
    }

    #[must_use]
    pub fn into_date_time(self) -> DateTime<Utc> {
        self.value
    }
}

impl From<DirectiveDateTime> for DateTime<Utc> {
    fn from(value: DirectiveDateTime) -> Self {
        value.value
    }
}

impl From<DateTime<Utc>> for DirectiveDateTime {
    fn from(value: DateTime<Utc>) -> Self {
        Self {
            value,
            parsed_format: None,
        }
    }
}

impl AsRef<DateTime<Utc>> for DirectiveDateTime {
    fn as_ref(&self) -> &DateTime<Utc> {
        &self.value
    }
}

impl FromStr for DirectiveDateTime {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
            return Ok(Self {
                value: dt.with_timezone(&Utc),
                parsed_format: Some(ParsedFormat::RFC3339),
            });
        }
        if let Ok(dt) = DateTime::parse_from_rfc2822(s) {
            return Ok(Self {
                value: dt.with_timezone(&Utc),
                parsed_format: Some(ParsedFormat::RFC2822),
            });
        }
        if let Ok(dt) = datetime_from_rfc_850(s) {
            return Ok(Self {
                value: dt.with_timezone(&Utc),
                parsed_format: Some(ParsedFormat::RFC850),
            });
        }
        tracing::debug!("failed to parse datetime value: {s}");
        Err(BoxError::from("invalid datetime value"))
    }
}

impl Display for DirectiveDateTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.parsed_format {
            Some(ParsedFormat::RFC2822) | None => self.value.to_rfc2822().fmt(f),
            Some(ParsedFormat::RFC3339) => self.value.to_rfc3339().fmt(f),
            Some(ParsedFormat::RFC850) => self.value.format("%A, %d-%b-%y %T").fmt(f),
        }
    }
}

fn datetime_from_rfc_850(s: &str) -> Result<DateTime<FixedOffset>, BoxError> {
    let (naive_date_time, remainder) = NaiveDateTime::parse_and_remainder(s, "%A, %d-%b-%y %T")
        .context("failed to parse naive datetime")
        .context_str_field("str", s)?;

    let fixed_offset = offset_from_abbreviation(remainder)?;

    Ok(DateTime::from_naive_utc_and_offset(
        naive_date_time,
        fixed_offset,
    ))
}

fn offset_from_abbreviation(remainder: &str) -> Result<FixedOffset, BoxError> {
    let abbreviation = get_timezone_map()
        .get(remainder.trim())
        .context("invalid abbreviation")
        .context_str_field("remainder", remainder)?;

    abbreviation
        .parse()
        .context("failed to parse timezone abbreviation")
        .context_str_field("abbreviation", *abbreviation)
        .context_str_field("remainder", remainder)
}

static TIMEZONE_MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

fn get_timezone_map() -> &'static HashMap<&'static str, &'static str> {
    TIMEZONE_MAP.get_or_init(|| {
        [
            ("ACDT", "+1030"),
            ("ACST", "+0930"),
            ("ACT", "−0500"),
            ("ACWST", "+0845"),
            ("ADT", "−0300"),
            ("AEDT", "+1100"),
            ("AEST", "+1000"),
            ("AFT", "+0430"),
            ("AKDT", "−0800"),
            ("AKST", "−0900"),
            ("ALMT", "+0600"),
            ("AMST", "−0300"),
            ("AMT", "+0400"),
            ("ANAT", "+1200"),
            ("AQTT", "+0500"),
            ("ART", "−0300"),
            ("AST", "−0400"),
            ("AWST", "+0800"),
            ("AZOST", "+0000"),
            ("AZOT", "−0100"),
            ("AZT", "+0400"),
            ("BIOT", "+0600"),
            ("BIT", "−1200"),
            ("BNT", "+0800"),
            ("BOT", "−0400"),
            ("BRST", "−0200"),
            ("BRT", "−0300"),
            ("BST", "+0600"),
            ("BTT", "+0600"),
            ("CAT", "+0200"),
            ("CCT", "+0630"),
            ("CDT", "−0500"),
            ("CEST", "+0200"),
            ("CET", "+0100"),
            ("CHADT", "+1345"),
            ("CHAST", "+1245"),
            ("CHOST", "+0900"),
            ("CHOT", "+0800"),
            ("CHST", "+1000"),
            ("CHUT", "+1000"),
            ("CIST", "−0800"),
            ("CKT", "−1000"),
            ("CLST", "−0300"),
            ("CLT", "−0400"),
            ("COST", "−0400"),
            ("COT", "−0500"),
            ("CST", "−0600"),
            ("CVT", "−0100"),
            ("CWST", "+0845"),
            ("CXT", "+0700"),
            ("DAVT", "+0700"),
            ("DDUT", "+1000"),
            ("DFT", "+0100"),
            ("EASST", "−0500"),
            ("EAST", "−0600"),
            ("EAT", "+0300"),
            ("ECT", "−0500"),
            ("EDT", "−0400"),
            ("EEST", "+0300"),
            ("EET", "+0200"),
            ("EGST", "+0000"),
            ("EGT", "−0100"),
            ("EST", "−0500"),
            ("FET", "+0300"),
            ("FJT", "+1200"),
            ("FKST", "−0300"),
            ("FKT", "−0400"),
            ("FNT", "−0200"),
            ("GALT", "−0600"),
            ("GAMT", "−0900"),
            ("GET", "+0400"),
            ("GFT", "−0300"),
            ("GILT", "+1200"),
            ("GIT", "−0900"),
            ("GMT", "+0000"),
            ("GST", "+0400"),
            ("GYT", "−0400"),
            ("HAEC", "+0200"),
            ("HDT", "−0900"),
            ("HKT", "+0800"),
            ("HMT", "+0500"),
            ("HOVST", "+0800"),
            ("HOVT", "+0700"),
            ("HST", "−1000"),
            ("ICT", "+0700"),
            ("IDLW", "−1200"),
            ("IDT", "+0300"),
            ("IOT", "+0600"),
            ("IRDT", "+0430"),
            ("IRKT", "+0800"),
            ("IRST", "+0330"),
            ("IST", "+0530"),
            ("JST", "+0900"),
            ("KALT", "+0200"),
            ("KGT", "+0600"),
            ("KOST", "+1100"),
            ("KRAT", "+0700"),
            ("KST", "+0900"),
            ("LHST", "+1030"),
            ("LINT", "+1400"),
            ("MAGT", "+1200"),
            ("MART", "−0930"),
            ("MAWT", "+0500"),
            ("MDT", "−0600"),
            ("MEST", "+0200"),
            ("MET", "+0100"),
            ("MHT", "+1200"),
            ("MIST", "+1100"),
            ("MIT", "−0930"),
            ("MMT", "+0630"),
            ("MSK", "+0300"),
            ("MST", "+0800"),
            ("MUT", "+0400"),
            ("MVT", "+0500"),
            ("MYT", "+0800"),
            ("NCT", "+1100"),
            ("NDT", "−0230"),
            ("NFT", "+1100"),
            ("NOVT", "+0700"),
            ("NPT", "+0545"),
            ("NST", "−0330"),
            ("NT", "−0330"),
            ("NUT", "−1100"),
            ("NZDST", "+1300"),
            ("NZDT", "+1300"),
            ("NZST", "+1200"),
            ("OMST", "+0600"),
            ("ORAT", "+0500"),
            ("PDT", "−0700"),
            ("PET", "−0500"),
            ("PETT", "+1200"),
            ("PGT", "+1000"),
            ("PHOT", "+1300"),
            ("PHST", "+0800"),
            ("PHT", "+0800"),
            ("PKT", "+0500"),
            ("PMDT", "−0200"),
            ("PMST", "−0300"),
            ("PONT", "+1100"),
            ("PST", "−0800"),
            ("PWT", "+0900"),
            ("PYST", "−0300"),
            ("PYT", "−0400"),
            ("RET", "+0400"),
            ("ROTT", "−0300"),
            ("SAKT", "+1100"),
            ("SAMT", "+0400"),
            ("SAST", "+0200"),
            ("SBT", "+1100"),
            ("SCT", "+0400"),
            ("SDT", "−1000"),
            ("SGT", "+0800"),
            ("SLST", "+0530"),
            ("SRET", "+1100"),
            ("SRT", "−0300"),
            ("SST", "−1100"),
            ("SYOT", "+0300"),
            ("TAHT", "−1000"),
            ("TFT", "+0500"),
            ("THA", "+0700"),
            ("TJT", "+0500"),
            ("TKT", "+1300"),
            ("TLT", "+0900"),
            ("TMT", "+0500"),
            ("TOT", "+1300"),
            ("TRT", "+0300"),
            ("TST", "+0800"),
            ("TVT", "+1200"),
            ("ULAST", "+0900"),
            ("ULAT", "+0800"),
            ("UTC", "+0000"),
            ("UYST", "−0200"),
            ("UYT", "−0300"),
            ("UZT", "+0500"),
            ("VET", "−0400"),
            ("VLAT", "+1000"),
            ("VOLT", "+0300"),
            ("VOST", "+0600"),
            ("VUT", "+1100"),
            ("WAKT", "+1200"),
            ("WAST", "+0200"),
            ("WAT", "+0100"),
            ("WEST", "+0100"),
            ("WET", "+0000"),
            ("WGST", "−0200"),
            ("WGT", "−0300"),
            ("WIB", "+0700"),
            ("WIT", "+0900"),
            ("WITA", "+0800"),
            ("WST", "+0800"),
            ("YAKT", "+0900"),
            ("YEKT", "+0500"),
        ]
        .into_iter()
        .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! test_valid_date_strings {
        ($($str:literal),+) => {
            $(assert!(DirectiveDateTime::from_str($str).is_ok(),
            "'{}': {:?}",
            $str, DirectiveDateTime::from_str($str).err());)+
        };
    }

    macro_rules! test_invalid_date_strings {
        ($($str:literal),+) => {
            $(assert!(DirectiveDateTime::from_str($str).is_err());)+
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

    #[test]
    fn test_valid_rfc_850() {
        test_valid_date_strings!(
            "Sunday, 04-Feb-24 23:59:59 GMT",
            "Monday, 29-Feb-88 12:34:56 UTC",
            "Tuesday, 01-Jan-80 00:00:00 EST",
            "Friday, 31-Dec-99 23:59:59 CST",
            "Thursday, 24-Feb-00 23:59:59 MST",
            "Friday, 01-Mar-19 00:00:01 PST",
            "Saturday, 31-Oct-20 13:45:30 EDT",
            "Wednesday, 27-Jun-12 23:59:60 CDT",
            "Monday, 03-Sep-01 01:02:03 CET",
            "Tuesday, 15-Aug-95 18:00:00 PDT"
        );
    }

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
