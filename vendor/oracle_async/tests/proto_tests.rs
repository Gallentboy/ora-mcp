use chrono::{NaiveDate, NaiveDateTime};
use rust_decimal::Decimal;
use std::str::FromStr;
use ora_async::proto::{
    decode_date, decode_datetime, decode_number, decode_number_to_decimal, decode_number_to_f64,
    decode_number_to_i64, encode_date, encode_datetime, encode_i64_to_number, TnsType,
};
use ora_async::{FromValue, OracleValue};

#[test]
fn test_oracle_number_zero() {
    assert_eq!(decode_number(&[128]).unwrap(), "0");
    assert_eq!(decode_number_to_i64(&[128]).unwrap(), 0);
    assert_eq!(decode_number_to_f64(&[128]).unwrap(), 0.0);
    assert_eq!(encode_i64_to_number(0), vec![128]);
}

#[test]
fn test_oracle_number_positive_integers() {
    let test_cases = [1, 7, 42, 100, 101, 9999, 123456789, 9223372036854775807i64];
    for &tc in &test_cases {
        let enc = encode_i64_to_number(tc);
        let dec = decode_number_to_i64(&enc).unwrap();
        assert_eq!(dec, tc, "Failed for {tc}");
    }
}

#[test]
fn test_oracle_number_negative_integers() {
    let test_cases = [-1, -42, -100, -101, -9999, -123456789];
    for &tc in &test_cases {
        let enc = encode_i64_to_number(tc);
        let dec = decode_number_to_i64(&enc).unwrap();
        assert_eq!(dec, tc, "Failed for {tc}");
    }
}

#[test]
fn test_oracle_number_known_vectors() {
    // Known Oracle dump vectors:
    // 1 -> [193, 2]
    assert_eq!(encode_i64_to_number(1), vec![193, 2]);
    assert_eq!(decode_number(&[193, 2]).unwrap(), "1");
    assert_eq!(decode_number_to_decimal(&[193, 2]).unwrap(), Decimal::from(1));

    // -1 -> [62, 100, 102]
    assert_eq!(encode_i64_to_number(-1), vec![62, 100, 102]);
    assert_eq!(decode_number(&[62, 100, 102]).unwrap(), "-1");
    assert_eq!(decode_number_to_decimal(&[62, 100, 102]).unwrap(), Decimal::from(-1));
}

#[test]
fn test_date_and_datetime_roundtrip() {
    let date = NaiveDate::from_ymd_opt(2026, 10, 23).unwrap();
    let enc_date = encode_date(date);
    let dec_date = decode_date(&enc_date).unwrap();
    assert_eq!(dec_date, date);

    let dt = NaiveDateTime::new(
        date,
        chrono::NaiveTime::from_hms_nano_opt(14, 25, 36, 500_000_000).unwrap(),
    );
    let enc_dt = encode_datetime(dt);
    let dec_dt = decode_datetime(&enc_dt).unwrap();
    assert_eq!(dec_dt, dt);
}

#[test]
fn test_tns_type_roundtrip() {
    assert_eq!(TnsType::from(2), TnsType::Number);
    assert_eq!(TnsType::from(9), TnsType::Varchar);
    assert_eq!(TnsType::from(12), TnsType::Date);
    assert_eq!(TnsType::from(112), TnsType::Clob);
    assert_eq!(TnsType::from(113), TnsType::Blob);
    assert_eq!(u8::from(TnsType::Number), 2);
}

#[test]
fn test_oracle_value_conversions() {
    let v_str = OracleValue::Text("42".into());
    assert_eq!(i64::from_value(v_str.clone()).unwrap(), 42);
    assert_eq!(String::from_value(v_str).unwrap(), "42");

    let v_num = OracleValue::Number(Decimal::from_str("123.45").unwrap());
    assert_eq!(f64::from_value(v_num.clone()).unwrap(), 123.45);
    assert_eq!(String::from_value(v_num).unwrap(), "123.45");

    let v_null = OracleValue::Null;
    let opt: Option<i64> = Option::from_value(v_null).unwrap();
    assert_eq!(opt, None);
}
