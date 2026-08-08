//! The PAC date/time host functions.
//!
//! Each takes an optional trailing `"GMT"` argument; without it the
//! comparison happens in the clock's own zone. Weekday, date and the
//! minute/second time ranges wrap, so `weekdayRange("FRI", "MON")`
//! covers the weekend; the hour-only `timeRange` pair does not, matching
//! the reference implementations.

use jiff::{Zoned, civil::Weekday, tz::TimeZone};

const WEEKDAYS: [(&str, Weekday); 7] = [
    ("SUN", Weekday::Sunday),
    ("MON", Weekday::Monday),
    ("TUE", Weekday::Tuesday),
    ("WED", Weekday::Wednesday),
    ("THU", Weekday::Thursday),
    ("FRI", Weekday::Friday),
    ("SAT", Weekday::Saturday),
];

const MONTHS: [&str; 12] = [
    "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
];

/// Strip a trailing `"GMT"` argument, returning the zone to evaluate in:
/// `None` keeps the clock's own zone (local time).
fn split_gmt(args: &[String]) -> (&[String], Option<TimeZone>) {
    match args.split_last() {
        Some((last, rest)) if last.eq_ignore_ascii_case("GMT") => (rest, Some(TimeZone::UTC)),
        _ => (args, None),
    }
}

fn in_zone(now: &Zoned, zone: Option<TimeZone>) -> Zoned {
    match zone {
        Some(zone) => now.with_time_zone(zone),
        None => now.clone(),
    }
}

fn weekday(arg: &str) -> Option<Weekday> {
    WEEKDAYS
        .iter()
        .find(|(name, _)| arg.eq_ignore_ascii_case(name))
        .map(|(_, weekday)| *weekday)
}

fn month(arg: &str) -> Option<i8> {
    MONTHS
        .iter()
        .position(|name| arg.eq_ignore_ascii_case(name))
        .and_then(|index| i8::try_from(index + 1).ok())
}

/// Is `value` inside `[from, to]`, wrapping when the range does?
fn in_wrapping_range<T: PartialOrd + Copy>(value: T, from: T, to: T) -> bool {
    if from <= to {
        value >= from && value <= to
    } else {
        value >= from || value <= to
    }
}

/// `weekdayRange(wd1, [wd2], [gmt])`.
pub(super) fn weekday_range(now: &Zoned, args: &[String]) -> bool {
    let (args, zone) = split_gmt(args);
    let now = in_zone(now, zone);
    let today = now.weekday();

    match args {
        [wd1] => weekday(wd1).is_some_and(|wd1| today == wd1),
        [wd1, wd2] => match (weekday(wd1), weekday(wd2)) {
            (Some(wd1), Some(wd2)) => in_wrapping_range(
                today.to_sunday_zero_offset(),
                wd1.to_sunday_zero_offset(),
                wd2.to_sunday_zero_offset(),
            ),
            _ => false,
        },
        _ => false,
    }
}

/// `dateRange(...)`: day, month and/or year bounds, in any of the
/// documented arities.
pub(super) fn date_range(now: &Zoned, args: &[String]) -> bool {
    let (args, zone) = split_gmt(args);
    let now = in_zone(now, zone);
    let (day, month_now, year) = (now.day(), now.month(), now.year());

    // each argument is a day (1-31), a month name, or a year (>=1000)
    let parsed: Vec<DatePart> = args.iter().map(|arg| DatePart::parse(arg)).collect();

    match parsed.as_slice() {
        [DatePart::Day(d)] => day == *d,
        [DatePart::Month(m)] => month_now == *m,
        [DatePart::Year(y)] => year == *y,
        [DatePart::Day(d1), DatePart::Day(d2)] => in_wrapping_range(day, *d1, *d2),
        [DatePart::Month(m1), DatePart::Month(m2)] => in_wrapping_range(month_now, *m1, *m2),
        [DatePart::Year(y1), DatePart::Year(y2)] => year >= *y1 && year <= *y2,
        [
            DatePart::Day(d1),
            DatePart::Month(m1),
            DatePart::Day(d2),
            DatePart::Month(m2),
        ] => in_wrapping_range((month_now, day), (*m1, *d1), (*m2, *d2)),
        [
            DatePart::Day(d1),
            DatePart::Month(m1),
            DatePart::Year(y1),
            DatePart::Day(d2),
            DatePart::Month(m2),
            DatePart::Year(y2),
        ] => {
            let now = (year, month_now, day);
            now >= (*y1, *m1, *d1) && now <= (*y2, *m2, *d2)
        }
        [
            DatePart::Month(m1),
            DatePart::Year(y1),
            DatePart::Month(m2),
            DatePart::Year(y2),
        ] => {
            let now = (year, month_now);
            now >= (*y1, *m1) && now <= (*y2, *m2)
        }
        _ => false,
    }
}

enum DatePart {
    Day(i8),
    Month(i8),
    Year(i16),
    Invalid,
}

impl DatePart {
    fn parse(arg: &str) -> Self {
        if let Some(month) = month(arg) {
            return Self::Month(month);
        }
        match arg.trim().parse::<i32>() {
            // a PAC year is always 4 digits; anything smaller is a day
            Ok(value) if value >= 1000 => i16::try_from(value).map_or(Self::Invalid, Self::Year),
            Ok(value) if (1..=31).contains(&value) => {
                i8::try_from(value).map_or(Self::Invalid, Self::Day)
            }
            _ => Self::Invalid,
        }
    }
}

/// `timeRange(...)`: hour, hour+minute or hour+minute+second bounds.
pub(super) fn time_range(now: &Zoned, args: &[String]) -> bool {
    let (args, zone) = split_gmt(args);
    let now = in_zone(now, zone);
    let (hour, minute, second) = (
        i32::from(now.hour()),
        i32::from(now.minute()),
        i32::from(now.second()),
    );

    let numbers: Option<Vec<i32>> = args.iter().map(|arg| arg.trim().parse().ok()).collect();
    let Some(numbers) = numbers else {
        return false;
    };

    match numbers.as_slice() {
        [h] => hour == *h,
        // the hour-only pair is the one range that does not wrap
        [h1, h2] => hour >= *h1 && hour <= *h2,
        [h1, m1, h2, m2] => in_wrapping_range(
            as_minutes(hour, minute),
            as_minutes(*h1, *m1),
            as_minutes(*h2, *m2),
        ),
        [h1, m1, s1, h2, m2, s2] => in_wrapping_range(
            as_seconds(hour, minute, second),
            as_seconds(*h1, *m1, *s1),
            as_seconds(*h2, *m2, *s2),
        ),
        _ => false,
    }
}

/// Widened, since the numbers come from the script: an out-of-range hour
/// then compares out of range instead of overflowing.
fn as_minutes(hour: i32, minute: i32) -> i64 {
    i64::from(hour) * 60 + i64::from(minute)
}

fn as_seconds(hour: i32, minute: i32, second: i32) -> i64 {
    i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(stamp: &str) -> Zoned {
        // fixed offset so the tests do not depend on the host time zone
        stamp.parse().unwrap()
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn weekday_single_and_range() {
        // 2026-08-01 is a Saturday
        let now = at("2026-08-01T12:00:00+00:00[UTC]");
        assert!(weekday_range(&now, &args(&["SAT", "GMT"])));
        assert!(!weekday_range(&now, &args(&["MON", "GMT"])));
        assert!(weekday_range(&now, &args(&["FRI", "MON", "GMT"])));
        assert!(weekday_range(&now, &args(&["MON", "SAT", "GMT"])));
        assert!(!weekday_range(&now, &args(&["MON", "FRI", "GMT"])));
        // junk never matches
        assert!(!weekday_range(&now, &args(&["NOPE", "GMT"])));
        assert!(!weekday_range(&now, &args(&[])));
    }

    #[test]
    fn date_day_month_year() {
        let now = at("2026-08-01T12:00:00+00:00[UTC]");
        assert!(date_range(&now, &args(&["1", "GMT"])));
        assert!(!date_range(&now, &args(&["2", "GMT"])));
        assert!(date_range(&now, &args(&["AUG", "GMT"])));
        assert!(date_range(&now, &args(&["2026", "GMT"])));
        assert!(date_range(&now, &args(&["1", "15", "GMT"])));
        assert!(date_range(&now, &args(&["JUL", "SEP", "GMT"])));
        assert!(date_range(&now, &args(&["2025", "2027", "GMT"])));
        assert!(!date_range(&now, &args(&["SEP", "OCT", "GMT"])));
    }

    #[test]
    fn date_day_month_pairs_wrap() {
        let now = at("2026-01-05T12:00:00+00:00[UTC]");
        // 24 DEC – 6 JAN wraps the new year
        assert!(date_range(&now, &args(&["24", "DEC", "6", "JAN", "GMT"])));
        assert!(!date_range(&now, &args(&["1", "FEB", "28", "FEB", "GMT"])));
    }

    #[test]
    fn date_full_and_month_year_ranges() {
        let now = at("2026-08-01T12:00:00+00:00[UTC]");
        assert!(date_range(
            &now,
            &args(&["1", "JUL", "2026", "1", "SEP", "2026", "GMT"])
        ));
        assert!(!date_range(
            &now,
            &args(&["1", "JUL", "2027", "1", "SEP", "2027", "GMT"])
        ));
        assert!(date_range(
            &now,
            &args(&["JUL", "2026", "SEP", "2026", "GMT"])
        ));
    }

    #[test]
    fn time_hour_minute_second() {
        let now = at("2026-08-01T12:30:45+00:00[UTC]");
        assert!(time_range(&now, &args(&["12", "GMT"])));
        assert!(!time_range(&now, &args(&["13", "GMT"])));
        assert!(time_range(&now, &args(&["9", "17", "GMT"])));
        assert!(time_range(&now, &args(&["12", "0", "13", "0", "GMT"])));
        assert!(!time_range(&now, &args(&["12", "0", "12", "15", "GMT"])));
        assert!(time_range(
            &now,
            &args(&["12", "30", "0", "12", "30", "59", "GMT"])
        ));
        // the hour-only pair does not wrap, unlike the finer-grained forms
        let night = at("2026-08-01T23:30:00+00:00[UTC]");
        assert!(!time_range(&night, &args(&["22", "6", "GMT"])));
        assert!(!time_range(&night, &args(&["6", "22", "GMT"])));
        assert!(time_range(&night, &args(&["22", "0", "6", "0", "GMT"])));
        assert!(!time_range(&now, &args(&["nope", "GMT"])));
    }

    #[test]
    fn absurd_numbers_compare_instead_of_overflowing() {
        let now = at("2026-08-01T12:30:45+00:00[UTC]");
        // 12:30:45 is outside a window that starts and ends 2e9 hours in
        for list in [
            &["2000000000", "0", "2000000000", "0", "GMT"][..],
            &["-2000000000", "0", "-2000000000", "0", "GMT"][..],
            &["2000000000", "0", "0", "2000000000", "0", "1", "GMT"][..],
        ] {
            assert!(!time_range(&now, &args(list)), "{list:?}");
        }
        // ... and inside one that merely ends there
        assert!(time_range(
            &now,
            &args(&["0", "0", "0", "2000000000", "0", "0", "GMT"])
        ));
        // the date parts reject out-of-range numbers outright
        assert!(!date_range(&now, &args(&["2000000000", "GMT"])));
        assert!(!date_range(
            &now,
            &args(&["99999999999999", "9999999999999", "GMT"])
        ));
    }

    #[test]
    fn clock_zone_is_used_without_gmt() {
        // 23:30 in Brussels is 21:30 UTC: without "GMT" the clock's own
        // zone is used, so this holds whatever zone the test host is in
        let now = at("2026-08-01T23:30:00+02:00[Europe/Brussels]");
        assert!(time_range(&now, &args(&["23"])));
        assert!(!time_range(&now, &args(&["21"])));
        assert!(time_range(&now, &args(&["21", "GMT"])));
        assert!(!time_range(&now, &args(&["23", "GMT"])));
    }

    #[test]
    fn date_ranges_need_both_bounds_to_hold() {
        let now = at("2026-08-01T12:00:00+00:00[UTC]");

        // year pair: outside on either side is false, not "either bound"
        assert!(date_range(&now, &args(&["2020", "2030", "GMT"])));
        assert!(!date_range(&now, &args(&["2027", "2030", "GMT"])));
        assert!(!date_range(&now, &args(&["2010", "2020", "GMT"])));

        // day/month/year pair, spanning and not
        let span = args(&["1", "JUL", "2026", "31", "AUG", "2026", "GMT"]);
        assert!(date_range(&now, &span));
        assert!(!date_range(
            &now,
            &args(&["2", "AUG", "2026", "31", "AUG", "2026", "GMT"]),
        ));
        assert!(!date_range(
            &now,
            &args(&["1", "JAN", "2020", "31", "JUL", "2026", "GMT"]),
        ));

        // month/year pair, likewise
        assert!(date_range(
            &now,
            &args(&["JUL", "2026", "SEP", "2026", "GMT"]),
        ));
        assert!(!date_range(
            &now,
            &args(&["SEP", "2026", "DEC", "2026", "GMT"]),
        ));
        assert!(!date_range(
            &now,
            &args(&["JAN", "2020", "JUL", "2026", "GMT"]),
        ));
    }

    #[test]
    fn a_day_outside_the_calendar_is_never_a_day() {
        let now = at("2026-08-01T12:00:00+00:00[UTC]");
        // 0 and 32 are neither a day nor a year, so they parse to nothing and
        // the call matches nothing
        for junk in ["0", "32", "-1", "999"] {
            assert!(!date_range(&now, &args(&[junk, "GMT"])), "{junk}");
        }
        // ... while the edges of the calendar still are days
        assert!(date_range(&now, &args(&["1", "GMT"])));
        assert!(!date_range(&now, &args(&["31", "GMT"])));
    }

    #[test]
    fn time_ranges_compare_hours_minutes_and_seconds_together() {
        // 13:20:30 — every component distinct, so wrong arithmetic shows up
        let now = at("2026-08-01T13:20:30+00:00[UTC]");

        // inside by seconds only
        assert!(time_range(
            &now,
            &args(&["13", "20", "29", "13", "20", "31", "GMT"]),
        ));
        // one second before the window opens
        assert!(!time_range(
            &now,
            &args(&["13", "20", "31", "13", "20", "40", "GMT"]),
        ));
        // one second after it closes
        assert!(!time_range(
            &now,
            &args(&["13", "20", "10", "13", "20", "29", "GMT"]),
        ));
        // minutes must not be confused for seconds, nor hours for minutes
        assert!(!time_range(&now, &args(&["13", "30", "13", "40", "GMT"])));
        assert!(time_range(&now, &args(&["13", "10", "13", "30", "GMT"])));
        assert!(!time_range(&now, &args(&["20", "13", "20", "40", "GMT"])));
    }
}
