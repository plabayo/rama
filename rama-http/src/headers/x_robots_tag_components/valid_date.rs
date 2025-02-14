use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use rama_core::error::{ErrorContext, OpaqueError};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::OnceLock;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ValidDate(DateTime<Utc>);

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

impl From<DateTime<Utc>> for ValidDate {
    fn from(value: DateTime<Utc>) -> Self {
        Self(value)
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
        Ok(ValidDate(
            DateTime::parse_from_rfc3339(s) // check ISO 8601
                .or_else(|_| {
                    DateTime::parse_from_rfc2822(s) // check RFC 822
                        .or_else(|_| datetime_from_rfc_850(s))
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

fn datetime_from_rfc_850(s: &str) -> Result<DateTime<FixedOffset>, OpaqueError> {
    let (naive_date_time, remainder) = NaiveDateTime::parse_and_remainder(s, "%A, %d-%b-%y %T")
        .with_context(|| "failed to parse naive datetime")?;

    let fixed_offset = offset_from_abbreviation(remainder)?;

    Ok(DateTime::from_naive_utc_and_offset(
        naive_date_time,
        fixed_offset,
    ))
}

fn offset_from_abbreviation(remainder: &str) -> Result<FixedOffset, OpaqueError> {
    get_timezone_map()
        .get(remainder.trim())
        .ok_or_else(|| OpaqueError::from_display(format!("invalid abbreviation: {}", remainder)))?
        .parse()
        .with_context(|| "failed to parse timezone abbreviation")
}

static TIMEZONE_MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

fn get_timezone_map() -> &'static HashMap<&'static str, &'static str> {
    TIMEZONE_MAP.get_or_init(|| {
        let mut map = HashMap::new();
        map.insert("ACDT", "+1030");
        map.insert("ACST", "+0930");
        map.insert("ACT", "−0500");
        map.insert("ACWST", "+0845");
        map.insert("ADT", "−0300");
        map.insert("AEDT", "+1100");
        map.insert("AEST", "+1000");
        map.insert("AFT", "+0430");
        map.insert("AKDT", "−0800");
        map.insert("AKST", "−0900");
        map.insert("ALMT", "+0600");
        map.insert("AMST", "−0300");
        map.insert("AMT", "+0400");
        map.insert("ANAT", "+1200");
        map.insert("AQTT", "+0500");
        map.insert("ART", "−0300");
        map.insert("AST", "−0400");
        map.insert("AWST", "+0800");
        map.insert("AZOST", "+0000");
        map.insert("AZOT", "−0100");
        map.insert("AZT", "+0400");
        map.insert("BIOT", "+0600");
        map.insert("BIT", "−1200");
        map.insert("BNT", "+0800");
        map.insert("BOT", "−0400");
        map.insert("BRST", "−0200");
        map.insert("BRT", "−0300");
        map.insert("BST", "+0600");
        map.insert("BTT", "+0600");
        map.insert("CAT", "+0200");
        map.insert("CCT", "+0630");
        map.insert("CDT", "−0500");
        map.insert("CEST", "+0200");
        map.insert("CET", "+0100");
        map.insert("CHADT", "+1345");
        map.insert("CHAST", "+1245");
        map.insert("CHOST", "+0900");
        map.insert("CHOT", "+0800");
        map.insert("CHST", "+1000");
        map.insert("CHUT", "+1000");
        map.insert("CIST", "−0800");
        map.insert("CKT", "−1000");
        map.insert("CLST", "−0300");
        map.insert("CLT", "−0400");
        map.insert("COST", "−0400");
        map.insert("COT", "−0500");
        map.insert("CST", "−0600");
        map.insert("CVT", "−0100");
        map.insert("CWST", "+0845");
        map.insert("CXT", "+0700");
        map.insert("DAVT", "+0700");
        map.insert("DDUT", "+1000");
        map.insert("DFT", "+0100");
        map.insert("EASST", "−0500");
        map.insert("EAST", "−0600");
        map.insert("EAT", "+0300");
        map.insert("ECT", "−0500");
        map.insert("EDT", "−0400");
        map.insert("EEST", "+0300");
        map.insert("EET", "+0200");
        map.insert("EGST", "+0000");
        map.insert("EGT", "−0100");
        map.insert("EST", "−0500");
        map.insert("FET", "+0300");
        map.insert("FJT", "+1200");
        map.insert("FKST", "−0300");
        map.insert("FKT", "−0400");
        map.insert("FNT", "−0200");
        map.insert("GALT", "−0600");
        map.insert("GAMT", "−0900");
        map.insert("GET", "+0400");
        map.insert("GFT", "−0300");
        map.insert("GILT", "+1200");
        map.insert("GIT", "−0900");
        map.insert("GMT", "+0000");
        map.insert("GST", "+0400");
        map.insert("GYT", "−0400");
        map.insert("HAEC", "+0200");
        map.insert("HDT", "−0900");
        map.insert("HKT", "+0800");
        map.insert("HMT", "+0500");
        map.insert("HOVST", "+0800");
        map.insert("HOVT", "+0700");
        map.insert("HST", "−1000");
        map.insert("ICT", "+0700");
        map.insert("IDLW", "−1200");
        map.insert("IDT", "+0300");
        map.insert("IOT", "+0600");
        map.insert("IRDT", "+0430");
        map.insert("IRKT", "+0800");
        map.insert("IRST", "+0330");
        map.insert("IST", "+0530");
        map.insert("JST", "+0900");
        map.insert("KALT", "+0200");
        map.insert("KGT", "+0600");
        map.insert("KOST", "+1100");
        map.insert("KRAT", "+0700");
        map.insert("KST", "+0900");
        map.insert("LHST", "+1030");
        map.insert("LINT", "+1400");
        map.insert("MAGT", "+1200");
        map.insert("MART", "−0930");
        map.insert("MAWT", "+0500");
        map.insert("MDT", "−0600");
        map.insert("MEST", "+0200");
        map.insert("MET", "+0100");
        map.insert("MHT", "+1200");
        map.insert("MIST", "+1100");
        map.insert("MIT", "−0930");
        map.insert("MMT", "+0630");
        map.insert("MSK", "+0300");
        map.insert("MST", "+0800");
        map.insert("MUT", "+0400");
        map.insert("MVT", "+0500");
        map.insert("MYT", "+0800");
        map.insert("NCT", "+1100");
        map.insert("NDT", "−0230");
        map.insert("NFT", "+1100");
        map.insert("NOVT", "+0700");
        map.insert("NPT", "+0545");
        map.insert("NST", "−0330");
        map.insert("NT", "−0330");
        map.insert("NUT", "−1100");
        map.insert("NZDST", "+1300");
        map.insert("NZDT", "+1300");
        map.insert("NZST", "+1200");
        map.insert("OMST", "+0600");
        map.insert("ORAT", "+0500");
        map.insert("PDT", "−0700");
        map.insert("PET", "−0500");
        map.insert("PETT", "+1200");
        map.insert("PGT", "+1000");
        map.insert("PHOT", "+1300");
        map.insert("PHST", "+0800");
        map.insert("PHT", "+0800");
        map.insert("PKT", "+0500");
        map.insert("PMDT", "−0200");
        map.insert("PMST", "−0300");
        map.insert("PONT", "+1100");
        map.insert("PST", "−0800");
        map.insert("PWT", "+0900");
        map.insert("PYST", "−0300");
        map.insert("PYT", "−0400");
        map.insert("RET", "+0400");
        map.insert("ROTT", "−0300");
        map.insert("SAKT", "+1100");
        map.insert("SAMT", "+0400");
        map.insert("SAST", "+0200");
        map.insert("SBT", "+1100");
        map.insert("SCT", "+0400");
        map.insert("SDT", "−1000");
        map.insert("SGT", "+0800");
        map.insert("SLST", "+0530");
        map.insert("SRET", "+1100");
        map.insert("SRT", "−0300");
        map.insert("SST", "−1100");
        map.insert("SYOT", "+0300");
        map.insert("TAHT", "−1000");
        map.insert("TFT", "+0500");
        map.insert("THA", "+0700");
        map.insert("TJT", "+0500");
        map.insert("TKT", "+1300");
        map.insert("TLT", "+0900");
        map.insert("TMT", "+0500");
        map.insert("TOT", "+1300");
        map.insert("TRT", "+0300");
        map.insert("TST", "+0800");
        map.insert("TVT", "+1200");
        map.insert("ULAST", "+0900");
        map.insert("ULAT", "+0800");
        map.insert("UTC", "+0000");
        map.insert("UYST", "−0200");
        map.insert("UYT", "−0300");
        map.insert("UZT", "+0500");
        map.insert("VET", "−0400");
        map.insert("VLAT", "+1000");
        map.insert("VOLT", "+0300");
        map.insert("VOST", "+0600");
        map.insert("VUT", "+1100");
        map.insert("WAKT", "+1200");
        map.insert("WAST", "+0200");
        map.insert("WAT", "+0100");
        map.insert("WEST", "+0100");
        map.insert("WET", "+0000");
        map.insert("WGST", "−0200");
        map.insert("WGT", "−0300");
        map.insert("WIB", "+0700");
        map.insert("WIT", "+0900");
        map.insert("WITA", "+0800");
        map.insert("WST", "+0800");
        map.insert("YAKT", "+0900");
        map.insert("YEKT", "+0500");
        map
    })
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
