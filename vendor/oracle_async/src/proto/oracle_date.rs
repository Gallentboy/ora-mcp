use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, NaiveTime, Timelike, Utc};
use crate::error::{Error, Result};

pub fn decode_date(data: &[u8]) -> Result<NaiveDate> {
    if data.len() < 7 {
        return Err(Error::Decode("date buffer less than 7 bytes".into()));
    }
    let century = (data[0] as i32) - 100;
    let year_in_century = (data[1] as i32) - 100;
    let year = century * 100 + year_in_century;
    let month = data[2] as u32;
    let day = data[3] as u32;

    NaiveDate::from_ymd_opt(year, month, day)
        .ok_or_else(|| Error::Decode(format!("invalid date components: {year}-{month}-{day}")))
}

pub fn decode_datetime(data: &[u8]) -> Result<NaiveDateTime> {
    if data.len() < 7 {
        return Err(Error::Decode("datetime buffer less than 7 bytes".into()));
    }
    let date = decode_date(data)?;
    let hour = (data[4] as u32).saturating_sub(1);
    let minute = (data[5] as u32).saturating_sub(1);
    let second = (data[6] as u32).saturating_sub(1);
    let nanos = if data.len() >= 11 {
        u32::from_be_bytes([data[7], data[8], data[9], data[10]])
    } else {
        0
    };

    let time = NaiveTime::from_hms_nano_opt(hour, minute, second, nanos)
        .ok_or_else(|| Error::Decode(format!("invalid time components: {hour}:{minute}:{second}.{nanos}")))?;

    Ok(NaiveDateTime::new(date, time))
}

pub fn decode_datetime_tz(data: &[u8]) -> Result<DateTime<Utc>> {
    let dt = decode_datetime(data)?;
    if data.len() >= 13 && (data[11] & 0x80 == 0) {
        let tz_hour = (data[11] as i32) - 20;
        let tz_min = (data[12] as i32) - 60;
        let total_offset_secs = tz_hour * 3600 + tz_min * 60;
        let offset = chrono::FixedOffset::east_opt(total_offset_secs)
            .ok_or_else(|| Error::Decode(format!("invalid tz offset: {total_offset_secs}")))?;
        let local = dt.and_local_timezone(offset).single()
            .ok_or_else(|| Error::Decode("ambiguous local time for offset".into()))?;
        Ok(local.with_timezone(&Utc))
    } else {
        Ok(dt.and_utc())
    }
}

pub fn encode_date(date: NaiveDate) -> [u8; 7] {
    let year = date.year();
    let century = (year / 100) + 100;
    let year_in_century = (year % 100) + 100;
    [
        century as u8,
        year_in_century as u8,
        date.month() as u8,
        date.day() as u8,
        1, // Hour + 1
        1, // Min + 1
        1, // Sec + 1
    ]
}

pub fn encode_datetime(dt: NaiveDateTime) -> [u8; 11] {
    let year = dt.year();
    let century = (year / 100) + 100;
    let year_in_century = (year % 100) + 100;
    let nanos = dt.nanosecond().to_be_bytes();
    [
        century as u8,
        year_in_century as u8,
        dt.month() as u8,
        dt.day() as u8,
        (dt.hour() + 1) as u8,
        (dt.minute() + 1) as u8,
        (dt.second() + 1) as u8,
        nanos[0],
        nanos[1],
        nanos[2],
        nanos[3],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_date_roundtrip() {
        let d = NaiveDate::from_ymd_opt(2026, 10, 23).unwrap();
        let encoded = encode_date(d);
        let decoded = decode_date(&encoded).unwrap();
        assert_eq!(d, decoded);
    }

    #[test]
    fn test_datetime_roundtrip() {
        let dt = NaiveDate::from_ymd_opt(2026, 10, 23)
            .unwrap()
            .and_hms_nano_opt(18, 45, 30, 123_456_000)
            .unwrap();
        let encoded = encode_datetime(dt);
        let decoded = decode_datetime(&encoded).unwrap();
        assert_eq!(dt, decoded);
    }
}
