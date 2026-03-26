use ahash::HashMap;
use jiff::{Timestamp, Zoned};
use rama_core::error::{BoxError, ErrorContext};
use rama_core::telemetry::tracing;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::sync::OnceLock;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectiveDateTime {
    value: Timestamp,
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
        let civil_dt = jiff::civil::DateTime::new(year as i16, month as i8, day as i8, hour as i8, min as i8, sec as i8, 0)
            .context("invalid date-time input")?;
        let timestamp = civil_dt.to_zoned(jiff::tz::TimeZone::UTC)
            .context("failed to convert to UTC timestamp")?
            .timestamp();
        Ok(Self {
            value: timestamp,
            parsed_format: None,
        })
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
    pub fn date_time(&self) -> &Timestamp {
        &self.value
    }

    #[must_use]
    pub fn into_date_time(self) -> Timestamp {
        self.value
    }
}

impl From<DirectiveDateTime> for Timestamp {
    fn from(value: DirectiveDateTime) -> Self {
        value.value
    }
}

impl From<Timestamp> for DirectiveDateTime {
    fn from(value: Timestamp) -> Self {
        Self {
            value,
            parsed_format: None,
        }
    }
}

impl AsRef<Timestamp> for DirectiveDateTime {
    fn as_ref(&self) -> &Timestamp {
        &self.value
    }
}

impl FromStr for DirectiveDateTime {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try RFC3339 format first
        if let Ok(timestamp) = Timestamp::from_str(s) {
            // Validate timezone offset if present (but not for Z timezone)
            if !s.ends_with('Z') && (s.contains('+') || s.contains('-')) {
                if let Some(tz_part) = s.rfind('+').or_else(|| s.rfind('-')) {
                    let tz_str = &s[tz_part..];
                    // Check for invalid timezone offsets like +24:00
                    if tz_str.len() >= 5 {
                        if let Ok(hours) = tz_str[1..3].parse::<i32>() {
                            if hours >= 24 {
                                tracing::debug!("rejected RFC3339 with invalid timezone offset: {s}");
                                // Continue to other parsers instead of returning this invalid timestamp
                            } else {
                                return Ok(Self {
                                    value: timestamp,
                                    parsed_format: Some(ParsedFormat::RFC3339),
                                });
                            }
                        } else {
                            return Ok(Self {
                                value: timestamp,
                                parsed_format: Some(ParsedFormat::RFC3339),
                            });
                        }
                    } else {
                        return Ok(Self {
                            value: timestamp,
                            parsed_format: Some(ParsedFormat::RFC3339),
                        });
                    }
                } else {
                    return Ok(Self {
                        value: timestamp,
                        parsed_format: Some(ParsedFormat::RFC3339),
                    });
                }
            } else {
                return Ok(Self {
                    value: timestamp,
                    parsed_format: Some(ParsedFormat::RFC3339),
                });
            }
        }
        // Try parsing as RFC2822 format
        if let Ok(zoned) = Zoned::strptime("%a, %d %b %Y %H:%M:%S %z", s)
            .or_else(|_| Zoned::strptime("%d %b %Y %H:%M:%S %z", s))
            .or_else(|_| Zoned::strptime("%a, %d %b %Y %H:%M %z", s)) {
            return Ok(Self {
                value: zoned.timestamp(),
                parsed_format: Some(ParsedFormat::RFC2822),
            });
        }
        
        // Try parsing RFC2822 with timezone abbreviations
        if let Ok(timestamp) = datetime_from_rfc2822_jiff(s) {
            return Ok(Self {
                value: timestamp,
                parsed_format: Some(ParsedFormat::RFC2822),
            });
        }
        // Try parsing RFC850 format
        if let Ok(timestamp) = datetime_from_rfc_850_jiff(s) {
            return Ok(Self {
                value: timestamp,
                parsed_format: Some(ParsedFormat::RFC850),
            });
        }
        tracing::debug!("failed to parse datetime value: {s}");
        Err(BoxError::from("invalid datetime value"))
    }
}

impl Display for DirectiveDateTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let zoned = self.value.to_zoned(jiff::tz::TimeZone::UTC);
        match self.parsed_format {
            Some(ParsedFormat::RFC2822) | None => {
                let civil = zoned.datetime();
                let weekday = match civil.weekday() {
                    jiff::civil::Weekday::Monday => "Mon",
                    jiff::civil::Weekday::Tuesday => "Tue",
                    jiff::civil::Weekday::Wednesday => "Wed",
                    jiff::civil::Weekday::Thursday => "Thu",
                    jiff::civil::Weekday::Friday => "Fri",
                    jiff::civil::Weekday::Saturday => "Sat",
                    jiff::civil::Weekday::Sunday => "Sun",
                };
                let month = match civil.month() {
                    1 => "Jan", 2 => "Feb", 3 => "Mar", 4 => "Apr",
                    5 => "May", 6 => "Jun", 7 => "Jul", 8 => "Aug",
                    9 => "Sep", 10 => "Oct", 11 => "Nov", 12 => "Dec",
                    _ => "???", // Should never happen
                };
                // Format timezone offset manually to ensure +0000 format
                let offset_seconds = zoned.offset().seconds();
                let offset_hours = offset_seconds / 3600;
                let offset_minutes = (offset_seconds.abs() % 3600) / 60;
                let offset_sign = if offset_seconds >= 0 { "+" } else { "-" };
                
                write!(f, "{}, {} {} {} {:02}:{:02}:{:02} {}{:02}{:02}",
                    weekday,
                    civil.day(),
                    month,
                    civil.year(),
                    civil.hour(),
                    civil.minute(),
                    civil.second(),
                    offset_sign,
                    offset_hours.abs(),
                    offset_minutes
                )
            },
            Some(ParsedFormat::RFC3339) => {
                // Format RFC3339 with Z for UTC timezone
                let formatted = format!("{}", self.value);
                if formatted.ends_with("+00:00") {
                    write!(f, "{}Z", &formatted[..formatted.len()-6])
                } else {
                    write!(f, "{}", formatted)
                }
            },
            Some(ParsedFormat::RFC850) => {
                let civil = zoned.datetime();
                let weekday = match civil.weekday() {
                    jiff::civil::Weekday::Monday => "Monday",
                    jiff::civil::Weekday::Tuesday => "Tuesday",
                    jiff::civil::Weekday::Wednesday => "Wednesday",
                    jiff::civil::Weekday::Thursday => "Thursday",
                    jiff::civil::Weekday::Friday => "Friday",
                    jiff::civil::Weekday::Saturday => "Saturday",
                    jiff::civil::Weekday::Sunday => "Sunday",
                };
                let month = match civil.month() {
                    1 => "Jan", 2 => "Feb", 3 => "Mar", 4 => "Apr",
                    5 => "May", 6 => "Jun", 7 => "Jul", 8 => "Aug",
                    9 => "Sep", 10 => "Oct", 11 => "Nov", 12 => "Dec",
                    _ => "???", // Should never happen
                };
                write!(f, "{}, {:02}-{}-{:02} {:02}:{:02}:{:02}",
                    weekday,
                    civil.day(),
                    month,
                    civil.year() % 100,
                    civil.hour(),
                    civil.minute(),
                    civil.second()
                )
            },
        }
    }
}

fn datetime_from_rfc2822_jiff(s: &str) -> Result<Timestamp, BoxError> {
    // Try to parse RFC2822 format with timezone abbreviations: "Wed, 02 Oct 2002 08:00:00 EST"
    if let Some((datetime_part, tz_part)) = s.rsplit_once(' ') {
        // Try patterns with and without day of week
        let patterns = [
            "%a, %d %b %Y %H:%M:%S",
            "%d %b %Y %H:%M:%S",
            "%a, %d %b %Y %H:%M",
            "%d %b %Y %H:%M",
        ];
        
        for pattern in &patterns {
            if let Ok(civil_dt) = jiff::civil::DateTime::strptime(pattern, datetime_part) {
                if let Some(&offset_str) = get_timezone_map().get(tz_part.trim()) {
                    if let Ok(offset) = parse_offset_string(offset_str) {
                        let zoned = civil_dt.to_zoned(jiff::tz::TimeZone::fixed(offset))
                            .context("failed to create zoned datetime with offset")?;
                        return Ok(zoned.timestamp());
                    }
                }
            }
        }
    }
    
    Err(BoxError::from(format!("failed to parse RFC2822 datetime: {}", s)))
}

fn datetime_from_rfc_850_jiff(s: &str) -> Result<Timestamp, BoxError> {
    // Try to parse the RFC850 format: "Friday, 31-Dec-99 23:59:59 GMT"
    if let Ok(zoned) = Zoned::strptime("%A, %d-%b-%y %H:%M:%S %Z", s)
        .or_else(|_| Zoned::strptime("%A, %d-%b-%y %H:%M:%S %z", s)) {
        return Ok(zoned.timestamp());
    }
    
    // Fallback: try to parse with timezone abbreviation lookup
    if let Some((datetime_part, tz_part)) = s.rsplit_once(' ') {
        if let Ok(civil_dt) = jiff::civil::DateTime::strptime("%A, %d-%b-%y %H:%M:%S", datetime_part) {
            if let Some(&offset_str) = get_timezone_map().get(tz_part.trim()) {
                if let Ok(offset) = parse_offset_string(offset_str) {
                    let zoned = civil_dt.to_zoned(jiff::tz::TimeZone::fixed(offset))
                        .context("failed to create zoned datetime with offset")?;
                    return Ok(zoned.timestamp());
                }
            }
        }
    }
    
    Err(BoxError::from(format!("failed to parse RFC850 datetime: {}", s)))
}

fn parse_offset_string(offset_str: &str) -> Result<jiff::tz::Offset, BoxError> {
    // Parse offset strings like "+0500", "-0300", etc.
    if offset_str.len() != 5 {
        return Err(BoxError::from("invalid offset format"));
    }
    
    let sign = match offset_str.chars().next() {
        Some('+') => 1,
        Some('−') | Some('-') => -1,
        _ => return Err(BoxError::from("invalid offset sign")),
    };
    
    let hours: i8 = offset_str[1..3].parse()
        .context("failed to parse offset hours")?;
    let minutes: i8 = offset_str[3..5].parse()
        .context("failed to parse offset minutes")?;
    
    // Validate timezone offset bounds
    if hours < 0 || hours > 23 || minutes < 0 || minutes > 59 {
        return Err(BoxError::from("invalid offset hours or minutes"));
    }
    
    // Check for maximum valid offset (+/- 14 hours)
    let total_offset_minutes = hours as i32 * 60 + minutes as i32;
    if total_offset_minutes > 14 * 60 {
        return Err(BoxError::from("offset exceeds maximum valid timezone offset"));
    }
    
    let total_seconds = sign * (hours as i32 * 3600 + minutes as i32 * 60);
    jiff::tz::Offset::from_seconds(total_seconds)
        .context("failed to create offset from seconds")
}

static TIMEZONE_MAP: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

fn get_timezone_map() -> &'static HashMap<&'static str, &'static str> {
    TIMEZONE_MAP.get_or_init(|| {
        [
            ("ACDT", "+1030"),
            ("ACST", "+0930"),
            ("ACT", "-0500"),
            ("ACWST", "+0845"),
            ("ADT", "-0300"),
            ("AEDT", "+1100"),
            ("AEST", "+1000"),
            ("AFT", "+0430"),
            ("AKDT", "-0800"),
            ("AKST", "-0900"),
            ("ALMT", "+0600"),
            ("AMST", "-0300"),
            ("AMT", "+0400"),
            ("ANAT", "+1200"),
            ("AQTT", "+0500"),
            ("ART", "-0300"),
            ("AST", "-0400"),
            ("AWST", "+0800"),
            ("AZOST", "+0000"),
            ("AZOT", "-0100"),
            ("AZT", "+0400"),
            ("BIOT", "+0600"),
            ("BIT", "-1200"),
            ("BNT", "+0800"),
            ("BOT", "-0400"),
            ("BRST", "-0200"),
            ("BRT", "-0300"),
            ("BST", "+0600"),
            ("BTT", "+0600"),
            ("CAT", "+0200"),
            ("CCT", "+0630"),
            ("CDT", "-0500"),
            ("CEST", "+0200"),
            ("CET", "+0100"),
            ("CHADT", "+1345"),
            ("CHAST", "+1245"),
            ("CHOST", "+0900"),
            ("CHOT", "+0800"),
            ("CHST", "+1000"),
            ("CHUT", "+1000"),
            ("CIST", "-0800"),
            ("CKT", "-1000"),
            ("CLST", "-0300"),
            ("CLT", "-0400"),
            ("COST", "-0400"),
            ("COT", "-0500"),
            ("CST", "-0600"),
            ("CVT", "-0100"),
            ("CWST", "+0845"),
            ("CXT", "+0700"),
            ("DAVT", "+0700"),
            ("DDUT", "+1000"),
            ("DFT", "+0100"),
            ("EASST", "-0500"),
            ("EAST", "-0600"),
            ("EAT", "+0300"),
            ("ECT", "-0500"),
            ("EDT", "-0400"),
            ("EEST", "+0300"),
            ("EET", "+0200"),
            ("EGST", "+0000"),
            ("EGT", "-0100"),
            ("EST", "-0500"),
            ("FET", "+0300"),
            ("FJT", "+1200"),
            ("FKST", "-0300"),
            ("FKT", "-0400"),
            ("FNT", "-0200"),
            ("GALT", "-0600"),
            ("GAMT", "-0900"),
            ("GET", "+0400"),
            ("GFT", "-0300"),
            ("GILT", "+1200"),
            ("GIT", "-0900"),
            ("GMT", "+0000"),
            ("GST", "+0400"),
            ("GYT", "-0400"),
            ("HAEC", "+0200"),
            ("HDT", "-0900"),
            ("HKT", "+0800"),
            ("HMT", "+0500"),
            ("HOVST", "+0800"),
            ("HOVT", "+0700"),
            ("HST", "-1000"),
            ("ICT", "+0700"),
            ("IDLW", "-1200"),
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
            ("MART", "-0930"),
            ("MAWT", "+0500"),
            ("MDT", "-0600"),
            ("MEST", "+0200"),
            ("MET", "+0100"),
            ("MHT", "+1200"),
            ("MIST", "+1100"),
            ("MIT", "-0930"),
            ("MMT", "+0630"),
            ("MSK", "+0300"),
            ("MST", "-0700"),
            ("MUT", "+0400"),
            ("MVT", "+0500"),
            ("MYT", "+0800"),
            ("NCT", "+1100"),
            ("NDT", "-0230"),
            ("NFT", "+1100"),
            ("NOVT", "+0700"),
            ("NPT", "+0545"),
            ("NST", "-0330"),
            ("NT", "-0330"),
            ("NUT", "-1100"),
            ("NZDST", "+1300"),
            ("NZDT", "+1300"),
            ("NZST", "+1200"),
            ("OMST", "+0600"),
            ("ORAT", "+0500"),
            ("PDT", "-0700"),
            ("PET", "-0500"),
            ("PETT", "+1200"),
            ("PGT", "+1000"),
            ("PHOT", "+1300"),
            ("PHST", "+0800"),
            ("PHT", "+0800"),
            ("PKT", "+0500"),
            ("PMDT", "-0200"),
            ("PMST", "-0300"),
            ("PONT", "+1100"),
            ("PST", "-0800"),
            ("PWT", "+0900"),
            ("PYST", "-0300"),
            ("PYT", "-0400"),
            ("RET", "+0400"),
            ("ROTT", "-0300"),
            ("SAKT", "+1100"),
            ("SAMT", "+0400"),
            ("SAST", "+0200"),
            ("SBT", "+1100"),
            ("SCT", "+0400"),
            ("SDT", "-1000"),
            ("SGT", "+0800"),
            ("SLST", "+0530"),
            ("SRET", "+1100"),
            ("SRT", "-0300"),
            ("SST", "-1100"),
            ("SYOT", "+0300"),
            ("TAHT", "-1000"),
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
            ("UYST", "-0200"),
            ("UYT", "-0300"),
            ("UZT", "+0500"),
            ("VET", "-0400"),
            ("VLAT", "+1000"),
            ("VOLT", "+0300"),
            ("VOST", "+0600"),
            ("VUT", "+1100"),
            ("WAKT", "+1200"),
            ("WAST", "+0200"),
            ("WAT", "+0100"),
            ("WEST", "+0100"),
            ("WET", "+0000"),
            ("WGST", "-0200"),
            ("WGT", "-0300"),
            ("WIB", "+0700"),
            ("WIT", "+0900"),
            ("WITA", "+0800"),
            ("WST", "+0800"),
            ("YAKT", "+0900"),
            ("YEKT", "+0500"),
            // Military time zones
            ("A", "+0100"),
            ("B", "+0200"),
            ("C", "+0300"),
            ("D", "+0400"),
            ("E", "+0500"),
            ("F", "+0600"),
            ("G", "+0700"),
            ("H", "+0800"),
            ("I", "+0900"),
            ("K", "+1000"),
            ("L", "+1100"),
            ("M", "+1200"),
            ("N", "-0100"),
            ("O", "-0200"),
            ("P", "-0300"),
            ("Q", "-0400"),
            ("R", "-0500"),
            ("S", "-0600"),
            ("T", "-0700"),
            ("U", "-0800"),
            ("V", "-0900"),
            ("W", "-1000"),
            ("X", "-1100"),
            ("Y", "-1200"),
            ("Z", "+0000"),
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
