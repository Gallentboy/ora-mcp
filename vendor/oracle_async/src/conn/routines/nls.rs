//! NLS 会话参数加载——go-ora `Connection.GetNLS()` 的等价实现。
//!
//! 一次性 PL/SQL 块从 `sys.nls_session_parameters` 聚合 13 项会话格式参数，
//! 以 OUT 参数回传（go-ora 同款 SQL 与 40/48/56 字节的 maxLen）。
//! 用途：日期/时间戳的展示格式（NLS_DATE_FORMAT 等）与排序、货币符号口径。
//!
//! 注意：go-ora 在连接末尾调用且失败只打日志（不阻断连接）——本实现同。

use log::{debug, warn};
use crate::conn::Conn;
use crate::conn::routines::bind::{BindParam, BindValue, Direction};
use crate::conn::routines::Routine;
use crate::error::Result;
use crate::proto::TnsType;
use crate::queryable::OracleValue;

/// NLS 会话参数（go-ora NLSData 的核心字段集）
#[derive(Debug, Default, Clone)]
pub struct NlsData {
    pub calendar: String,
    pub comp: String,
    pub length_semantics: String,
    pub nchar_conv_excep: String,
    pub date_lang: String,
    pub sort: String,
    pub currency: String,
    pub date_format: String,
    pub iso_currency: String,
    pub numeric_chars: String,
    pub dual_currency: String,
    pub timestamp: String,
    pub timestamp_tz: String,
}

impl NlsData {
    fn from_outputs(vals: &[OracleValue]) -> Self {
        let get = |i: usize| match vals.get(i) {
            Some(OracleValue::Text(s)) => s.clone(),
            Some(v) => v.to_string(),
            None => String::new(),
        };
        Self {
            calendar: get(0),
            comp: get(1),
            length_semantics: get(2),
            nchar_conv_excep: get(3),
            date_lang: get(4),
            sort: get(5),
            currency: get(6),
            date_format: get(7),
            iso_currency: get(8),
            numeric_chars: get(9),
            dual_currency: get(10),
            timestamp: get(11),
            timestamp_tz: get(12),
        }
    }
}

/// go-ora GetNLS 的 PL/SQL 块（原样照抄，13 个 OUT 参数）
const NLS_SQL: &str = "BEGIN
  SELECT
    MAX(CASE WHEN PARAMETER='NLS_CALENDAR' THEN VALUE END),
    MAX(CASE WHEN PARAMETER='NLS_COMP' THEN VALUE END),
    MAX(CASE WHEN PARAMETER='NLS_LENGTH_SEMANTICS' THEN VALUE END),
    MAX(CASE WHEN PARAMETER='NLS_NCHAR_CONV_EXCP' THEN VALUE END),
    MAX(CASE WHEN PARAMETER='NLS_DATE_LANGUAGE' THEN VALUE END),
    MAX(CASE WHEN PARAMETER='NLS_SORT' THEN VALUE END),
    MAX(CASE WHEN PARAMETER='NLS_CURRENCY' THEN VALUE END),
    MAX(CASE WHEN PARAMETER='NLS_DATE_FORMAT' THEN VALUE END),
    MAX(CASE WHEN PARAMETER='NLS_ISO_CURRENCY' THEN VALUE END),
    MAX(CASE WHEN PARAMETER='NLS_NUMERIC_CHARACTERS' THEN VALUE END),
    MAX(CASE WHEN PARAMETER='NLS_DUAL_CURRENCY' THEN VALUE END),
    MAX(CASE WHEN PARAMETER='NLS_TIMESTAMP_FORMAT' THEN VALUE END),
    MAX(CASE WHEN PARAMETER='NLS_TIMESTAMP_TZ_FORMAT' THEN VALUE END)
  INTO :p_nls_calendar, :p_nls_comp, :p_nls_length_semantics,
       :p_nls_nchar_conv_excep, :p_nls_date_lang, :p_nls_sort,
       :p_nls_currency, :p_nls_date_format, :p_nls_iso_currency,
       :p_nls_numeric_chars, :p_nls_dual_currency, :p_nls_timestamp,
       :p_nls_timestamp_tz
  FROM sys.nls_session_parameters;
END;";

#[derive(Default)]
pub struct LoadNlsRoutine;

impl LoadNlsRoutine {
    pub fn new() -> Self {
        Self
    }
}

/// 13 个 OUT 参数（maxLen 与 go-ora 一致：40/48/56）
fn nls_output_params() -> Vec<BindParam> {
    let mut params = Vec::with_capacity(13);
    for i in 0..13 {
        let max_len = match i {
            11 => 48, // timestamp
            12 => 56, // timestamp_tz
            _ => 40,
        };
        params.push(BindParam {
            name: format!("p_nls_{i}"),
            direction: Direction::Output,
            value: BindValue::Null,
            data_type: Some(TnsType::NChar),
            max_len,
        });
    }
    params
}

#[async_trait::async_trait]
impl Routine<Option<NlsData>> for LoadNlsRoutine {
    async fn call(&mut self, conn: &mut Conn) -> Result<Option<NlsData>> {
        let params = nls_output_params();
        let mut routine = crate::conn::routines::exec::ExecRoutine::with_params(
            NLS_SQL,
            false,
            0,
            params,
        );
        match routine.call(conn).await {
            Ok(resp) => {
                let data = NlsData::from_outputs(&resp.output_values);
                debug!(
                    "NLS loaded: date_format={:?}, timestamp={:?}, numeric={:?}",
                    data.date_format, data.timestamp, data.numeric_chars
                );
                conn.nls = Some(Box::new(data.clone()));
                Ok(Some(data))
            }
            Err(e) => {
                // go-ora 同口径：失败不阻断连接（仅日志）
                warn!("NLS load failed (non-fatal): {e}");
                Ok(None)
            }
        }
    }
}
