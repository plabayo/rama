use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
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

    fn datetime_from_rfc_850(s: &str) -> Result<DateTime<FixedOffset>, OpaqueError> {
        let (naive_date_time, remainder) =
            NaiveDateTime::parse_and_remainder(s, "%A, %d-%b-%y %T")
                .with_context(|| "failed to parse naive datetime")?;

        let fixed_offset = Self::offset_from_abbreviation(remainder)?;

        Ok(DateTime::from_naive_utc_and_offset(naive_date_time, fixed_offset))
    }

    fn offset_from_abbreviation(remainder: &str) -> Result<FixedOffset, OpaqueError> {
        Ok(match remainder.trim() {
            "ACDT" => "+1030",
            "ACST" => "+0930",
            "ACT" => "−0500",
            "ACWST" => "+0845",
            "ADT" => "−0300",
            "AEDT" => "+1100",
            "AEST" => "+1000",
            "AFT" => "+0430",
            "AKDT" => "−0800",
            "AKST" => "−0900",
            "ALMT" => "+0600",
            "AMST" => "−0300",
            "AMT" => "+0400",
            "ANAT" => "+1200",
            "AQTT" => "+0500",
            "ART" => "−0300",
            "AST" => "−0400",
            "AWST" => "+0800",
            "AZOST" => "+0000",
            "AZOT" => "−0100",
            "AZT" => "+0400",
            "BIOT" => "+0600",
            "BIT" => "−1200",
            "BNT" => "+0800",
            "BOT" => "−0400",
            "BRST" => "−0200",
            "BRT" => "−0300",
            "BST" => "+0600",
            "BTT" => "+0600",
            "CAT" => "+0200",
            "CCT" => "+0630",
            "CDT" => "−0500",
            "CEST" => "+0200",
            "CET" => "+0100",
            "CHADT" => "+1345",
            "CHAST" => "+1245",
            "CHOST" => "+0900",
            "CHOT" => "+0800",
            "CHST" => "+1000",
            "CHUT" => "+1000",
            "CIST" => "−0800",
            "CKT" => "−1000",
            "CLST" => "−0300",
            "CLT" => "−0400",
            "COST" => "−0400",
            "COT" => "−0500",
            "CST" => "−0600",
            "CVT" => "−0100",
            "CWST" => "+0845",
            "CXT" => "+0700",
            "DAVT" => "+0700",
            "DDUT" => "+1000",
            "DFT" => "+0100",
            "EASST" => "−0500",
            "EAST" => "−0600",
            "EAT" => "+0300",
            "ECT" => "−0500",
            "EDT" => "−0400",
            "EEST" => "+0300",
            "EET" => "+0200",
            "EGST" => "+0000",
            "EGT" => "−0100",
            "EST" => "−0500",
            "FET" => "+0300",
            "FJT" => "+1200",
            "FKST" => "−0300",
            "FKT" => "−0400",
            "FNT" => "−0200",
            "GALT" => "−0600",
            "GAMT" => "−0900",
            "GET" => "+0400",
            "GFT" => "−0300",
            "GILT" => "+1200",
            "GIT" => "−0900",
            "GMT" => "+0000",
            "GST" => "+0400",
            "GYT" => "−0400",
            "HAEC" => "+0200",
            "HDT" => "−0900",
            "HKT" => "+0800",
            "HMT" => "+0500",
            "HOVST" => "+0800",
            "HOVT" => "+0700",
            "HST" => "−1000",
            "ICT" => "+0700",
            "IDLW" => "−1200",
            "IDT" => "+0300",
            "IOT" => "+0600",
            "IRDT" => "+0430",
            "IRKT" => "+0800",
            "IRST" => "+0330",
            "IST" => "+0530",
            "JST" => "+0900",
            "KALT" => "+0200",
            "KGT" => "+0600",
            "KOST" => "+1100",
            "KRAT" => "+0700",
            "KST" => "+0900",
            "LHST" => "+1030",
            "LINT" => "+1400",
            "MAGT" => "+1200",
            "MART" => "−0930",
            "MAWT" => "+0500",
            "MDT" => "−0600",
            "MEST" => "+0200",
            "MET" => "+0100",
            "MHT" => "+1200",
            "MIST" => "+1100",
            "MIT" => "−0930",
            "MMT" => "+0630",
            "MSK" => "+0300",
            "MST" => "+0800",
            "MUT" => "+0400",
            "MVT" => "+0500",
            "MYT" => "+0800",
            "NCT" => "+1100",
            "NDT" => "−0230",
            "NFT" => "+1100",
            "NOVT" => "+0700",
            "NPT" => "+0545",
            "NST" => "−0330",
            "NT" => "−0330",
            "NUT" => "−1100",
            "NZDST" => "+1300",
            "NZDT" => "+1300",
            "NZST" => "+1200",
            "OMST" => "+0600",
            "ORAT" => "+0500",
            "PDT" => "−0700",
            "PET" => "−0500",
            "PETT" => "+1200",
            "PGT" => "+1000",
            "PHOT" => "+1300",
            "PHST" => "+0800",
            "PHT" => "+0800",
            "PKT" => "+0500",
            "PMDT" => "−0200",
            "PMST" => "−0300",
            "PONT" => "+1100",
            "PST" => "−0800",
            "PWT" => "+0900",
            "PYST" => "−0300",
            "PYT" => "−0400",
            "RET" => "+0400",
            "ROTT" => "−0300",
            "SAKT" => "+1100",
            "SAMT" => "+0400",
            "SAST" => "+0200",
            "SBT" => "+1100",
            "SCT" => "+0400",
            "SDT" => "−1000",
            "SGT" => "+0800",
            "SLST" => "+0530",
            "SRET" => "+1100",
            "SRT" => "−0300",
            "SST" => "−1100",
            "SYOT" => "+0300",
            "TAHT" => "−1000",
            "TFT" => "+0500",
            "THA" => "+0700",
            "TJT" => "+0500",
            "TKT" => "+1300",
            "TLT" => "+0900",
            "TMT" => "+0500",
            "TOT" => "+1300",
            "TRT" => "+0300",
            "TST" => "+0800",
            "TVT" => "+1200",
            "ULAST" => "+0900",
            "ULAT" => "+0800",
            "UTC" => "+0000",
            "UYST" => "−0200",
            "UYT" => "−0300",
            "UZT" => "+0500",
            "VET" => "−0400",
            "VLAT" => "+1000",
            "VOLT" => "+0300",
            "VOST" => "+0600",
            "VUT" => "+1100",
            "WAKT" => "+1200",
            "WAST" => "+0200",
            "WAT" => "+0100",
            "WEST" => "+0100",
            "WET" => "+0000",
            "WGST" => "−0200",
            "WGT" => "−0300",
            "WIB" => "+0700",
            "WIT" => "+0900",
            "WITA" => "+0800",
            "WST" => "+0800",
            "YAKT" => "+0900",
            "YEKT" => "+0500",
            _ => {
                return Err(OpaqueError::from_display(
                    "timezone abbreviation not recognized",
                ))
            }
        }
        .parse()
        .with_context(|| "failed to parse timezone abbreviation")?)
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

impl From<DateTime<Utc>> for ValidDate {
    fn from(value: DateTime<Utc>) -> Self {
        Self::new(value)
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
						.or_else(|_| Self::datetime_from_rfc_850(s))
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
