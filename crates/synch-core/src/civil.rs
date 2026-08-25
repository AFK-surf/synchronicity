//! Proleptic-Gregorian calendar arithmetic: Howard Hinnant's `days_from_civil`
//! and `civil_from_days`, shared so date math needs no calendar dependency and
//! exists exactly once.
//!
//! Before this module the pair was written out five times across the S3
//! gateway (SigV4 scope dates, `Last-Modified` headers) and the net crate (TUF
//! expiries, X.509 validity), with two different spellings of the negative-day
//! floor. They agreed — but arithmetic where a divergent edit is silent is the
//! last place to keep copies.

/// Days from 1970-01-01 to a proleptic Gregorian date.
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The inverse of [`days_from_civil`]: `(year, month, day)` for a day count
/// since 1970-01-01.
pub fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (year + i64::from(month <= 2), month, day)
}

/// The civil date and time of day of a unix timestamp:
/// `(year, month, day, hour, minute, second)`.
pub fn civil_from_unix(unix_secs: i64) -> (i64, i64, i64, i64, i64, i64) {
    let (year, month, day) = civil_from_days(unix_secs.div_euclid(86_400));
    let rest = unix_secs.rem_euclid(86_400);
    (year, month, day, rest / 3600, (rest % 3600) / 60, rest % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_conversions_are_inverses_across_the_edges() {
        // The epoch, both leap-rule edges (1900 is not a leap year, 2000 is),
        // and a pre-epoch date, which is where the two hand-written floors
        // this module replaced could have parted ways.
        for (days, date) in [
            (0, (1970, 1, 1)),
            (days_from_civil(2000, 2, 29), (2000, 2, 29)),
            (days_from_civil(1900, 3, 1), (1900, 3, 1)),
            (days_from_civil(1969, 12, 31), (1969, 12, 31)),
            (days_from_civil(2026, 8, 24), (2026, 8, 24)),
        ] {
            assert_eq!(civil_from_days(days), date);
            let (y, m, d) = date;
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(days_from_civil(1969, 12, 31), -1);
    }

    #[test]
    fn time_of_day_floors_toward_the_previous_midnight() {
        assert_eq!(civil_from_unix(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil_from_unix(-1), (1969, 12, 31, 23, 59, 59));
        assert_eq!(civil_from_unix(86_400 + 3_661), (1970, 1, 2, 1, 1, 1));
    }
}
