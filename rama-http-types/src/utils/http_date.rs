//! RFC 9110 §5.6.7 HTTP-dates as unix seconds.
//!
//! Formats IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`) and parses it plus the two obsolete
//! forms a recipient must accept: RFC 850 (`Sunday, 06-Nov-94 08:49:37 GMT`) and asctime
//! (`Sun Nov  6 08:49:37 1994`).

use std::cell::RefCell;

use bytes::Bytes;
use rama_utils::{bytes::trim_ows, time::now_unix};

/// Byte length of every IMF-fixdate.
pub const HTTP_DATE_LEN: usize = 29;

/// `Fri, 31 Dec 9999 23:59:59 GMT`, the last second an HTTP-date can represent.
pub const MAX_HTTP_DATE_UNIX_SECS: u64 = 253_402_300_799;

const SECS_PER_DAY: u64 = 86_400;
const WEEKDAYS: [&[u8; 3]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const MONTHS: [&[u8; 3]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];

/// Format `unix_secs` as an IMF-fixdate; values past [`MAX_HTTP_DATE_UNIX_SECS`] clamp to it.
#[must_use]
pub const fn format_http_date(unix_secs: u64) -> [u8; HTTP_DATE_LEN] {
    let secs = if unix_secs > MAX_HTTP_DATE_UNIX_SECS {
        MAX_HTTP_DATE_UNIX_SECS
    } else {
        unix_secs
    };
    let days = secs / SECS_PER_DAY;
    let secs_of_day = secs % SECS_PER_DAY;
    let (year, month, day) = civil_from_days(days);
    // 1970-01-01 was a Thursday.
    let weekday = WEEKDAYS[((days + 4) % 7) as usize];
    let month = MONTHS[(month - 1) as usize];

    let mut out = *b"Thu, 01 Jan 1970 00:00:00 GMT";
    out[0] = weekday[0];
    out[1] = weekday[1];
    out[2] = weekday[2];
    put_2(&mut out, 5, day);
    out[8] = month[0];
    out[9] = month[1];
    out[10] = month[2];
    put_2(&mut out, 12, year / 100);
    put_2(&mut out, 14, year % 100);
    put_2(&mut out, 17, secs_of_day / 3600);
    put_2(&mut out, 20, secs_of_day / 60 % 60);
    put_2(&mut out, 23, secs_of_day % 60);
    out
}

/// [`format_http_date`] for the current second of rama's cached wall clock.
#[must_use]
pub fn format_http_date_now() -> [u8; HTTP_DATE_LEN] {
    format_http_date(now_unix_secs())
}

/// Same as [`format_http_date`] but returned as owned Bytes.
#[must_use]
pub fn format_http_date_bytes(unix_secs: u64) -> Bytes {
    Bytes::from_owner(format_http_date(unix_secs))
}

thread_local! {
    /// The second last formatted by [`format_http_date_now_bytes`], with its bytes.
    static NOW: RefCell<(u64, Bytes)> = const { RefCell::new((u64::MAX, Bytes::new())) };
}

/// [`format_http_date_bytes`], sharing the bytes of [`format_http_date_now_bytes`]
/// when `unix_secs` is the second those were last formatted for on this thread.
///
/// Never refreshes the shared bytes: only the clock does.
#[must_use]
pub fn format_http_date_bytes_maybe_now(unix_secs: u64) -> Bytes {
    let secs = unix_secs.min(MAX_HTTP_DATE_UNIX_SECS);
    NOW.with(|now| {
        let now = now.borrow();
        (now.0 == secs).then(|| now.1.clone())
    })
    .unwrap_or_else(|| format_http_date_bytes(secs))
}

/// [`format_http_date_now`] as shared bytes, formatted once per second per thread.
///
/// Suits the `Date` of every response: callers within one second share one allocation.
#[must_use]
pub fn format_http_date_now_bytes() -> Bytes {
    let secs = now_unix_secs();
    NOW.with(|now| {
        let mut now = now.borrow_mut();
        if now.0 != secs {
            *now = (secs, Bytes::from_owner(format_http_date(secs)));
        }
        now.1.clone()
    })
}

fn now_unix_secs() -> u64 {
    u64::try_from(now_unix())
        .unwrap_or(0)
        .min(MAX_HTTP_DATE_UNIX_SECS)
}

/// Unix seconds of an IMF-fixdate, RFC 850 or asctime HTTP-date, ignoring surrounding OWS.
///
/// `None` for anything else, including dates before 1970, impossible dates such as
/// 31 Feb, and a weekday that does not match the date. An RFC 850 two-digit year more
/// than 50 years ahead of the current year (rama's cached clock) falls in the past century.
#[must_use]
pub fn parse_http_date(value: &[u8]) -> Option<u64> {
    parse_http_date_in(value, year_of(now_unix_secs()))
}

/// [`parse_http_date`] with `current_year` pinned, for deterministic tests.
fn parse_http_date_in(value: &[u8], current_year: u64) -> Option<u64> {
    let value = trim_ows(value);
    let fields = match value.len() {
        29 => parse_imf_fixdate(value),
        24 => parse_asctime(value),
        _ => parse_rfc850(value, current_year),
    }?;
    fields.unix_secs()
}

const fn year_of(unix_secs: u64) -> u64 {
    civil_from_days(unix_secs / SECS_PER_DAY).0
}

/// RFC 9110 §5.6.7: a two-digit year more than 50 years ahead belongs to the past century.
const fn expand_two_digit_year(two_digits: u64, current_year: u64) -> u64 {
    let year = current_year - current_year % 100 + two_digits;
    if year > current_year + 50 {
        year - 100
    } else {
        year
    }
}

/// Calendar fields as written; [`Fields::unix_secs`] validates them.
struct Fields {
    weekday: u64,
    day: u64,
    month: u64,
    year: u64,
    hour: u64,
    minute: u64,
    second: u64,
}

impl Fields {
    fn unix_secs(&self) -> Option<u64> {
        if !(1970..=9999).contains(&self.year)
            || self.day == 0
            || self.day > days_in_month(self.year, self.month)
            || self.hour > 23
            || self.minute > 59
            || self.second > 59
        {
            return None;
        }
        let days = days_from_civil(self.year, self.month, self.day);
        // 1970-01-01 was a Thursday.
        if (days + 4) % 7 != self.weekday {
            return None;
        }
        Some(days * SECS_PER_DAY + self.hour * 3600 + self.minute * 60 + self.second)
    }
}

/// `Sun, 06 Nov 1994 08:49:37 GMT`
fn parse_imf_fixdate(s: &[u8]) -> Option<Fields> {
    let [
        w0,
        w1,
        w2,
        b',',
        b' ',
        d0,
        d1,
        b' ',
        m0,
        m1,
        m2,
        b' ',
        y0,
        y1,
        y2,
        y3,
        b' ',
        rest @ ..,
    ] = s
    else {
        return None;
    };
    let [h0, h1, b':', i0, i1, b':', s0, s1, b' ', b'G', b'M', b'T'] = rest else {
        return None;
    };
    Some(Fields {
        weekday: weekday([*w0, *w1, *w2])?,
        day: two_digits(*d0, *d1)?,
        month: month([*m0, *m1, *m2])?,
        year: two_digits(*y0, *y1)? * 100 + two_digits(*y2, *y3)?,
        hour: two_digits(*h0, *h1)?,
        minute: two_digits(*i0, *i1)?,
        second: two_digits(*s0, *s1)?,
    })
}

/// `Sunday, 06-Nov-94 08:49:37 GMT`; the byte before the hour is not checked, as established
/// parsers accept any.
fn parse_rfc850(s: &[u8], current_year: u64) -> Option<Fields> {
    let comma = s.iter().position(|&b| b == b',')?;
    let (name, rest) = s.split_at(comma);
    let weekday = WEEKDAY_NAMES.iter().position(|full| *full == name)? as u64;
    let [
        b',',
        b' ',
        d0,
        d1,
        b'-',
        m0,
        m1,
        m2,
        b'-',
        y0,
        y1,
        _,
        h0,
        h1,
        b':',
        i0,
        i1,
        b':',
        s0,
        s1,
        b' ',
        b'G',
        b'M',
        b'T',
    ] = rest
    else {
        return None;
    };
    let year = two_digits(*y0, *y1)?;
    Some(Fields {
        weekday,
        day: two_digits(*d0, *d1)?,
        month: month([*m0, *m1, *m2])?,
        year: expand_two_digit_year(year, current_year),
        hour: two_digits(*h0, *h1)?,
        minute: two_digits(*i0, *i1)?,
        second: two_digits(*s0, *s1)?,
    })
}

/// `Sun Nov  6 08:49:37 1994`
fn parse_asctime(s: &[u8]) -> Option<Fields> {
    let [
        w0,
        w1,
        w2,
        b' ',
        m0,
        m1,
        m2,
        b' ',
        d0,
        d1,
        b' ',
        h0,
        h1,
        b':',
        i0,
        i1,
        b':',
        s0,
        s1,
        b' ',
        y0,
        y1,
        y2,
        y3,
    ] = s
    else {
        return None;
    };
    let day = if *d0 == b' ' {
        digit(*d1)?
    } else {
        two_digits(*d0, *d1)?
    };
    Some(Fields {
        weekday: weekday([*w0, *w1, *w2])?,
        day,
        month: month([*m0, *m1, *m2])?,
        year: two_digits(*y0, *y1)? * 100 + two_digits(*y2, *y3)?,
        hour: two_digits(*h0, *h1)?,
        minute: two_digits(*i0, *i1)?,
        second: two_digits(*s0, *s1)?,
    })
}

const WEEKDAY_NAMES: [&[u8]; 7] = [
    b"Sunday",
    b"Monday",
    b"Tuesday",
    b"Wednesday",
    b"Thursday",
    b"Friday",
    b"Saturday",
];

fn weekday(name: [u8; 3]) -> Option<u64> {
    WEEKDAYS.iter().position(|w| **w == name).map(|i| i as u64)
}

fn month(name: [u8; 3]) -> Option<u64> {
    MONTHS
        .iter()
        .position(|m| **m == name)
        .map(|i| i as u64 + 1)
}

const fn digit(b: u8) -> Option<u64> {
    if b.is_ascii_digit() {
        Some((b - b'0') as u64)
    } else {
        None
    }
}

const fn two_digits(tens: u8, ones: u8) -> Option<u64> {
    match (digit(tens), digit(ones)) {
        (Some(t), Some(o)) => Some(t * 10 + o),
        _ => None,
    }
}

const fn is_leap_year(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

const fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date in 1970..=9999 (Hinnant's algorithm).
const fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year / 400;
    let year_of_era = year - era * 400;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

const fn put_2(out: &mut [u8; HTTP_DATE_LEN], at: usize, value: u64) {
    out[at] = b'0' + (value / 10) as u8;
    out[at + 1] = b'0' + (value % 10) as u8;
}

/// Proleptic Gregorian `(year, month, day)` for days since 1970-01-01 (Hinnant's algorithm).
const fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn formatted(secs: u64) -> String {
        String::from_utf8(format_http_date(secs).to_vec()).unwrap()
    }

    #[test]
    fn known_dates() {
        for (secs, expected) in [
            (0, "Thu, 01 Jan 1970 00:00:00 GMT"),
            (784_111_777, "Sun, 06 Nov 1994 08:49:37 GMT"),
            (951_782_400, "Tue, 29 Feb 2000 00:00:00 GMT"),
            (4_107_542_399, "Sun, 28 Feb 2100 23:59:59 GMT"),
            (4_107_542_400, "Mon, 01 Mar 2100 00:00:00 GMT"),
            (MAX_HTTP_DATE_UNIX_SECS, "Fri, 31 Dec 9999 23:59:59 GMT"),
        ] {
            assert_eq!(formatted(secs), expected, "{secs}");
        }
    }

    #[test]
    fn clamps_past_9999() {
        assert_eq!(formatted(u64::MAX), formatted(MAX_HTTP_DATE_UNIX_SECS));
    }

    #[test]
    fn now_bytes_are_shared_within_a_second() {
        assert_eq!(format_http_date_now().len(), HTTP_DATE_LEN);
        let first = format_http_date_now_bytes();
        let second = format_http_date_now_bytes();
        if first == second {
            assert_eq!(first.as_ptr(), second.as_ptr());
        }
        assert_eq!(first.len(), HTTP_DATE_LEN);
    }

    #[test]
    fn maybe_now_shares_the_now_bytes() {
        let now = format_http_date_now_bytes();
        let secs = parse_http_date(&now).unwrap();
        let shared = format_http_date_bytes_maybe_now(secs);
        // a tick between the two calls leaves the earlier second cached
        assert_eq!(shared.as_ptr(), now.as_ptr());
    }

    #[test]
    fn maybe_now_formats_other_seconds_without_replacing_now() {
        let now = format_http_date_now_bytes();
        let secs = parse_http_date(&now).unwrap();
        for other in [1_000, secs - 1, secs + 1, u64::MAX] {
            let bytes = format_http_date_bytes_maybe_now(other);
            assert_eq!(&bytes[..], &format_http_date(other), "{other}");
            assert_ne!(bytes.as_ptr(), now.as_ptr(), "{other}");
        }
        assert_eq!(
            format_http_date_bytes_maybe_now(secs).as_ptr(),
            now.as_ptr()
        );
    }

    #[test]
    fn parses_all_three_formats() {
        for value in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ] {
            assert_eq!(
                parse_http_date_in(value.as_bytes(), 2026),
                Some(784_111_777),
                "{value}"
            );
        }
        assert_eq!(
            parse_http_date_in(b" \tSun, 06 Nov 1994 08:49:37 GMT ", 2026),
            Some(784_111_777)
        );
        assert_eq!(
            parse_http_date_in(b"Saturday, 01-Jan-00 00:00:00 GMT", 2026),
            Some(946_684_800)
        );
        assert_eq!(
            parse_http_date_in(b"Tue, 29 Feb 2000 00:00:00 GMT", 2026),
            Some(951_782_400)
        );
    }

    #[test]
    fn parse_round_trips_format() {
        let mut secs = 0_u64;
        while secs <= MAX_HTTP_DATE_UNIX_SECS {
            assert_eq!(
                parse_http_date(&format_http_date(secs)),
                Some(secs),
                "{secs}"
            );
            secs += 7_919_993;
        }
        assert_eq!(
            parse_http_date(&format_http_date(MAX_HTTP_DATE_UNIX_SECS)),
            Some(MAX_HTTP_DATE_UNIX_SECS)
        );
    }

    #[test]
    fn two_digit_years_follow_the_current_year() {
        assert_eq!(expand_two_digit_year(76, 2026), 2076);
        assert_eq!(expand_two_digit_year(77, 2026), 1977);
        assert_eq!(expand_two_digit_year(0, 2026), 2000);
        assert_eq!(expand_two_digit_year(95, 2090), 2095);
        assert_eq!(expand_two_digit_year(40, 2090), 2040);
        assert_eq!(
            parse_http_date_in(b"Thursday, 01-Jan-70 00:00:00 GMT", 2019),
            Some(0)
        );
        assert_eq!(
            parse_http_date_in(b"Thursday, 01-Jan-70 00:00:00 GMT", 2020),
            None
        );
    }

    #[test]
    fn fixtures() {
        const CASES: &str = include_str!("../../fixtures/http_date/parse.txt");
        let mut checked = 0;
        for line in CASES.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (expected, input) = line.split_once(' ').unwrap_or((line, ""));
            let expected = (expected != "reject").then(|| expected.parse::<u64>().unwrap());
            let input = input.replace("\\t", "\t");
            assert_eq!(
                parse_http_date_in(input.as_bytes(), 2026),
                expected,
                "{input:?}"
            );
            if let Some(secs) = expected {
                assert_eq!(
                    parse_http_date_in(&format_http_date(secs), 2026),
                    Some(secs)
                );
            }
            checked += 1;
        }
        assert!(checked > 60, "{checked}");
    }

    #[test]
    fn rejects_invalid_dates() {
        for value in [
            "",
            "Wed, 31 Dec 1969 23:59:59 GMT",
            "Sat, 01 Jan 10000 00:00:00 GMT",
            "Mon, 31 Feb 1994 08:48:37 GMT",
            "Thu, 29 Feb 1900 00:00:00 GMT",
            "Mon, 07 Nov 1994 24:00:00 GMT",
            "Mon, 07 Nov 1994 08:60:00 GMT",
            "Mon, 07 Nov 1994 08:48:60 GMT",
            "Tue, 07 Nov 1994 08:48:37 GMT",
            "Mon, 07 nov 1994 08:48:37 GMT",
            "Mon, 07 Nov 1994 08:48:37 UTC",
            "Mon,  7 Nov 1994 08:48:37 GMT",
            "Monday, 07-Nov-1994 08:48:37 GMT",
            "Mon, 07-Nov-94 08:48:37 GMT",
            "Monday, 07-Nov-94 08:48:37 GMT\u{0}",
            "Mon Nov  7 08:48:37 99999",
            "Mon Nov 07 08:48:37 1994x",
            "Mon Nov  x 08:48:37 1994",
        ] {
            assert_eq!(parse_http_date(value.as_bytes()), None, "{value:?}");
        }
    }
}
