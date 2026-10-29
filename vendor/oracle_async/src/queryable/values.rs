use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use rust_decimal::Decimal;
use std::fmt;
use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub enum OracleValue {
    Null,
    Int(i64),
    Float(f64),
    Number(Decimal),
    Text(String),
    Binary(Vec<u8>),
    Date(NaiveDate),
    Timestamp(NaiveDateTime),
    TimestampTz(DateTime<Utc>),
    Boolean(bool),
    Cursor(u16),
}

impl fmt::Display for OracleValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OracleValue::Null => write!(f, "NULL"),
            OracleValue::Int(v) => write!(f, "{v}"),
            OracleValue::Float(v) => write!(f, "{v}"),
            OracleValue::Number(v) => write!(f, "{v}"),
            OracleValue::Text(v) => write!(f, "{v}"),
            OracleValue::Binary(v) => write!(f, "<{} bytes>", v.len()),
            OracleValue::Date(v) => write!(f, "{v}"),
            OracleValue::Timestamp(v) => write!(f, "{v}"),
            OracleValue::TimestampTz(v) => write!(f, "{v}"),
            OracleValue::Boolean(v) => write!(f, "{v}"),
            OracleValue::Cursor(v) => write!(f, "<Cursor {v}>"),
        }
    }
}

pub trait FromValue: Sized {
    fn from_value(val: OracleValue) -> Result<Self>;
}

impl<T: FromValue> FromValue for Option<T> {
    fn from_value(val: OracleValue) -> Result<Self> {
        if val == OracleValue::Null {
            Ok(None)
        } else {
            T::from_value(val).map(Some)
        }
    }
}

impl FromValue for String {
    fn from_value(val: OracleValue) -> Result<Self> {
        match val {
            OracleValue::Text(s) => Ok(s),
            OracleValue::Number(d) => Ok(d.to_string()),
            OracleValue::Int(i) => Ok(i.to_string()),
            OracleValue::Float(f) => Ok(f.to_string()),
            OracleValue::Date(d) => Ok(d.to_string()),
            OracleValue::Timestamp(t) => Ok(t.to_string()),
            OracleValue::TimestampTz(tz) => Ok(tz.to_rfc3339()),
            OracleValue::Boolean(b) => Ok(b.to_string()),
            other => Err(Error::FromValue(format!("cannot convert {other:?} to String"))),
        }
    }
}

impl FromValue for i64 {
    fn from_value(val: OracleValue) -> Result<Self> {
        match val {
            OracleValue::Int(i) => Ok(i),
            OracleValue::Number(d) => {
                use rust_decimal::prelude::ToPrimitive;
                d.to_i64()
                    .ok_or_else(|| Error::FromValue(format!("decimal {d} out of range for i64")))
            }
            OracleValue::Float(f) => Ok(f as i64),
            OracleValue::Text(s) => s
                .parse::<i64>()
                .map_err(|e| Error::FromValue(format!("failed to parse i64 from '{s}': {e}"))),
            other => Err(Error::FromValue(format!("cannot convert {other:?} to i64"))),
        }
    }
}

impl FromValue for i32 {
    fn from_value(val: OracleValue) -> Result<Self> {
        let v = i64::from_value(val)?;
        i32::try_from(v).map_err(|e| Error::FromValue(format!("i64 {v} out of range for i32: {e}")))
    }
}

impl FromValue for f64 {
    fn from_value(val: OracleValue) -> Result<Self> {
        match val {
            OracleValue::Float(f) => Ok(f),
            OracleValue::Number(d) => {
                use rust_decimal::prelude::ToPrimitive;
                d.to_f64()
                    .ok_or_else(|| Error::FromValue(format!("decimal {d} out of range for f64")))
            }
            OracleValue::Int(i) => Ok(i as f64),
            OracleValue::Text(s) => s
                .parse::<f64>()
                .map_err(|e| Error::FromValue(format!("failed to parse f64 from '{s}': {e}"))),
            other => Err(Error::FromValue(format!("cannot convert {other:?} to f64"))),
        }
    }
}

impl FromValue for bool {
    fn from_value(val: OracleValue) -> Result<Self> {
        match val {
            OracleValue::Boolean(b) => Ok(b),
            OracleValue::Int(i) => Ok(i != 0),
            OracleValue::Text(s) => match s.to_uppercase().as_str() {
                "TRUE" | "1" | "Y" | "YES" => Ok(true),
                "FALSE" | "0" | "N" | "NO" => Ok(false),
                _ => Err(Error::FromValue(format!("cannot parse bool from '{s}'"))),
            },
            other => Err(Error::FromValue(format!("cannot convert {other:?} to bool"))),
        }
    }
}

impl FromValue for Decimal {
    fn from_value(val: OracleValue) -> Result<Self> {
        match val {
            OracleValue::Number(d) => Ok(d),
            OracleValue::Int(i) => Ok(Decimal::from(i)),
            OracleValue::Text(s) => s
                .parse::<Decimal>()
                .map_err(|e| Error::FromValue(format!("failed to parse Decimal from '{s}': {e}"))),
            other => Err(Error::FromValue(format!("cannot convert {other:?} to Decimal"))),
        }
    }
}

impl FromValue for NaiveDate {
    fn from_value(val: OracleValue) -> Result<Self> {
        match val {
            OracleValue::Date(d) => Ok(d),
            OracleValue::Timestamp(t) => Ok(t.date()),
            other => Err(Error::FromValue(format!("cannot convert {other:?} to NaiveDate"))),
        }
    }
}

impl FromValue for NaiveDateTime {
    fn from_value(val: OracleValue) -> Result<Self> {
        match val {
            OracleValue::Timestamp(t) => Ok(t),
            OracleValue::Date(d) => Ok(d.and_hms_opt(0, 0, 0).unwrap()),
            other => Err(Error::FromValue(format!("cannot convert {other:?} to NaiveDateTime"))),
        }
    }
}

impl FromValue for Vec<u8> {
    fn from_value(val: OracleValue) -> Result<Self> {
        match val {
            OracleValue::Binary(b) => Ok(b),
            OracleValue::Text(s) => Ok(s.into_bytes()),
            other => Err(Error::FromValue(format!("cannot convert {other:?} to Vec<u8>"))),
        }
    }
}
