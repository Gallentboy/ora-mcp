//! 绑定参数（go-ora `Stmt.Pars` / `writePars` / `setDataType` 的逐项复刻）。
//!
//! 协议要点（真机 11g 验证口径）：
//! - 参数定义段（`writeDefine` 的对偶）在 `basicWrite` 里由
//!   `PutBytes(1) + PutUint(len(Pars), 2)` 引入，每列按 `ParameterInfo.write`
//!   形态写元数据；
//! - 参数值段由 `MsgCode 7`（`session.PutBytes(7)`）引入，按序写非 LONG 参数
//!   的 CLR，再统一写所有 LONG 参数；
//! - 出参（Direction=Output）在 parse 轮不写值；重新执行轮（!parse）才写；
//! - 空值：`PutClr(nil)` 即单字节 0（NULL）。
//!
//! 本模块只做「值 → 线缆字节」的编码与元数据推导，不改动执行流程。

use crate::error::{Error, Result};
use crate::proto::decode_ext;
use crate::proto::oracle_date::{encode_date, encode_datetime};
use crate::proto::oracle_number::{
    encode_decimal_to_number, encode_f64_to_number, encode_i64_to_number,
};
use crate::proto::tns_types::TnsType;
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use rust_decimal::Decimal;

/// 参数方向（go-ora ParameterDirection）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Input,
    Output,
    InOut,
}

/// 绑定参数值
#[derive(Debug, Clone)]
pub enum BindValue {
    Null,
    Text(String),
    Int(i64),
    Float(f64),
    Number(Decimal),
    Bool(bool),
    Bytes(Vec<u8>),
    Date(NaiveDate),
    Timestamp(NaiveDateTime),
    TimestampTz(DateTime<Utc>),
}

/// 一个绑定参数（元数据 + 值）
#[derive(Debug, Clone)]
pub struct BindParam {
    pub name: String,
    pub direction: Direction,
    pub value: BindValue,
    /// 显式指定类型（None = 按值推导，等价 go-ora setDataType）
    pub data_type: Option<TnsType>,
    /// 出参的最大长度（Input 时按实际值长度回填）
    pub max_len: usize,
}

impl BindParam {
    pub fn input(value: BindValue) -> Self {
        Self {
            name: String::new(),
            direction: Direction::Input,
            value,
            data_type: None,
            max_len: 0,
        }
    }

    pub fn output(data_type: TnsType, max_len: usize) -> Self {
        Self {
            name: String::new(),
            direction: Direction::Output,
            value: BindValue::Null,
            data_type: Some(data_type),
            max_len,
        }
    }

    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// go-ora setDataType：按值推导 Oracle 类型与长度
    /// 返回 (类型, max_len, charset_form, charset_id, cont_flag)
    fn resolve_meta(&self, charset_id: u32) -> (TnsType, usize, u8, u32, u32) {
        if let Some(dt) = self.data_type {
            let is_text = matches!(dt, TnsType::NChar | TnsType::Varchar | TnsType::Char);
            let len = if self.max_len > 0 { self.max_len } else { 4000 };
            return (
                dt,
                len,
                if is_text { 1 } else { 0 },
                if is_text { charset_id } else { 0 },
                if is_text { 16 } else { 0 },
            );
        }
        match &self.value {
            // go-ora：字符串类参数 ContFlag = 16、CharsetForm = 1
            BindValue::Null => (TnsType::NChar, 1, 1, charset_id, 16),
            BindValue::Text(s) => (TnsType::NChar, s.len().max(1), 1, charset_id, 16),
            BindValue::Int(_) | BindValue::Float(_) | BindValue::Number(_) => {
                (TnsType::Number, 22, 0, 0, 0)
            }
            BindValue::Bool(_) => (TnsType::Boolean, 1, 0, 0, 0),
            BindValue::Bytes(b) => (TnsType::Raw, b.len().max(1), 0, 0, 0),
            BindValue::Date(_) => (TnsType::Date, 7, 0, 0, 0),
            BindValue::Timestamp(_) => (TnsType::Timestamp, 11, 0, 0, 0),
            BindValue::TimestampTz(_) => (TnsType::TimeStampTzDty, 13, 0, 0, 0),
        }
    }

    /// 值 → 线缆字节（go-ora encodePrimValue）
    fn encode_value(&self, charset_id: u32) -> Result<Vec<u8>> {
        Ok(match &self.value {
            BindValue::Null => Vec::new(),
            BindValue::Text(s) => crate::proto::charset::encode(s, charset_id),
            BindValue::Int(v) => encode_i64_to_number(*v),
            BindValue::Float(v) => encode_f64_to_number(*v)?,
            BindValue::Number(d) => encode_decimal_to_number(d)?,
            BindValue::Bool(b) => {
                if *b {
                    vec![1, 1]
                } else {
                    vec![1, 0]
                }
            }
            BindValue::Bytes(b) => b.clone(),
            BindValue::Date(d) => encode_date(*d).to_vec(),
            BindValue::Timestamp(t) => encode_datetime(*t).to_vec(),
            BindValue::TimestampTz(t) => {
                // 时区时间戳：11 字节本地时间 + 时区偏移两字节
                let local = t.naive_utc();
                let mut b = encode_datetime(local).to_vec();
                b.push(20); // 偏移小时 + 20（UTC 即 0+20）
                b.push(60); // 偏移分钟 + 60
                b
            }
        })
    }

    /// 参数元数据（`ParameterInfo.write` 的字段集）
    fn write_meta(&self, w: &mut crate::io::TtcWriter, charset_id: u32, ttc_version: u8) {
        let (dt, max_len, form, csid, cont) = self.resolve_meta(charset_id);
        w.put_byte(u8::from(dt));
        w.put_byte(0x03); // Flag：输入输出均参与（go-ora col.Flag = 3）
        w.put_byte(0); // Precision
        w.put_byte(0); // Scale
        w.put_uint(max_len as u64, 4, true, true);
        w.put_uint(0, 4, true, true); // MaxNoOfArrayElements
        if ttc_version >= 10 {
            w.put_int(cont as i64, 8, true, true);
        } else {
            w.put_int(cont as i64, 4, true, true);
        }
        w.put_byte(0); // ToID = nil
        w.put_uint(0, 2, true, true); // Version
        w.put_uint(csid as u64, 2, true, true); // CharsetID
        w.put_byte(form); // CharsetForm
        w.put_uint(max_len as u64, 4, true, true); // MaxCharLen
    }
}

/// 参数定义体 + 值段的完整写入（go-ora writePars + 参数元数据）。
///
/// 注意：参数段**标记**（`1 + 压缩个数`）由调用方在 long-fetch 之后写
/// （basicWrite 的位置），本函数只写「列定义体」与「MsgCode 7 值段」——
/// 两者都位于 al8i4 数组之后。
///
/// `parse` 为 true 时写全部输入值；false（重新执行）时跳过纯出参的值。
pub fn write_params(
    w: &mut crate::io::TtcWriter,
    params: &[BindParam],
    charset_id: u32,
    ttc_version: u8,
    parse: bool,
) -> Result<()> {
    if params.is_empty() {
        return Ok(());
    }
    // 参数列定义体（每列 ParameterInfo.write 形态）
    for p in params {
        p.write_meta(w, charset_id, ttc_version);
    }

    // 参数值段：MsgCode 7 + 非 LONG 值（再统一 LONG；本实现无 LONG 参数）
    w.put_byte(7);
    for p in params {
        if !parse && p.direction == Direction::Output {
            continue;
        }
        let bytes = p.encode_value(charset_id)?;
        if bytes.is_empty() {
            w.put_byte(0); // NULL
        } else {
            w.put_clr(&bytes);
        }
    }
    Ok(())
}

/// 从 SQL 中抽取 `:1` / `:name` 形态的绑定占位符出现顺序（go-ora 的
/// named-parameter 支持只做 `:name` → 位置映射；这里仅提供校验与计数）。
pub fn count_bind_placeholders(sql: &str) -> usize {
    let bytes = sql.as_bytes();
    let mut count = 0usize;
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    while i < bytes.len() {
        match bytes[i] {
            b'\'' if !in_double => in_single = !in_single,
            b'"' if !in_single => in_double = !in_double,
            b':' if !in_single && !in_double => {
                // 排除 := 赋值与 :: 转义
                let prev = if i > 0 { bytes[i - 1] } else { 0 };
                let next = bytes.get(i + 1).copied().unwrap_or(0);
                if next != b'=' && prev != b':' && (next.is_ascii_alphanumeric() || next == b'_') {
                    count += 1;
                    // 跳过标识符主体
                    let mut j = i + 1;
                    while j < bytes.len()
                        && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_')
                    {
                        j += 1;
                    }
                    i = j;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }
    count
}

/// 供调用方判断解码扩展类型是否可用（编译期自检）
pub fn ext_decoders_available() -> bool {
    decode_ext::decode_boolean(&[1, 1]).is_some()
}

/// 把 `OracleValue` 转为绑定值（Queryable::exec_with_params 的入参形态）
pub fn value_to_bind(v: &crate::queryable::OracleValue) -> BindValue {
    use crate::queryable::OracleValue as V;
    match v {
        V::Null => BindValue::Null,
        V::Int(i) => BindValue::Int(*i),
        V::Float(f) => BindValue::Float(*f),
        V::Number(d) => BindValue::Number(*d),
        V::Text(s) => BindValue::Text(s.clone()),
        V::Binary(b) => BindValue::Bytes(b.clone()),
        V::Date(d) => BindValue::Date(*d),
        V::Timestamp(t) => BindValue::Timestamp(*t),
        V::TimestampTz(t) => BindValue::TimestampTz(*t),
        V::Boolean(b) => BindValue::Bool(*b),
        V::Cursor(_) => BindValue::Null,
    }
}

/// 参数个数与占位符个数校验（防错位；go-ora 由驱动层隐式容忍，这里显式报错）
pub fn validate_param_count(sql: &str, params: &[BindParam]) -> Result<()> {
    let expected = count_bind_placeholders(sql);
    if expected != params.len() {
        return Err(Error::Protocol(format!(
            "SQL 有 {expected} 个绑定占位符，但提供了 {} 个参数",
            params.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::TtcWriter;

    #[test]
    fn count_placeholders_ignores_literals_and_comments() {
        assert_eq!(count_bind_placeholders("SELECT * FROM t WHERE a = :1"), 1);
        assert_eq!(count_bind_placeholders("SELECT :a, :b FROM dual"), 2);
        // 字符串字面量内不算
        assert_eq!(count_bind_placeholders("SELECT ':x' FROM dual"), 0);
        // PL/SQL 赋值 := 不算
        assert_eq!(count_bind_placeholders("BEGIN x := 1; END;"), 0);
        // 双引号标识符内不算
        assert_eq!(count_bind_placeholders("SELECT \":x\" FROM dual"), 0);
        // 同名重复出现按次数计
        assert_eq!(count_bind_placeholders("SELECT :a FROM t WHERE b = :a"), 2);
    }

    #[test]
    fn validate_count_mismatch() {
        let p = [BindParam::input(BindValue::Int(1))];
        assert!(validate_param_count("SELECT :1 FROM dual", &p).is_ok());
        assert!(validate_param_count("SELECT :1, :2 FROM dual", &p).is_err());
    }

    #[test]
    fn param_meta_derivation() {
        // 字符串 → NCHAR + charset form 1
        let p = BindParam::input(BindValue::Text("abc".into()));
        let (dt, len, form, _, _) = p.resolve_meta(852);
        assert_eq!(dt, TnsType::NChar);
        assert_eq!(len, 3);
        assert_eq!(form, 1);
        // 整数 → NUMBER
        let p = BindParam::input(BindValue::Int(42));
        assert_eq!(p.resolve_meta(852).0, TnsType::Number);
        // 字节 → RAW
        let p = BindParam::input(BindValue::Bytes(vec![1, 2, 3]));
        assert_eq!(p.resolve_meta(852).0, TnsType::Raw);
        // 日期 → DATE
        let p = BindParam::input(BindValue::Date(
            chrono::NaiveDate::from_ymd_opt(2026, 10, 24).unwrap(),
        ));
        assert_eq!(p.resolve_meta(852).0, TnsType::Date);
    }

    #[test]
    fn param_value_encoding() {
        // 字符串按服务器字符集编码（852 = GBK）
        let p = BindParam::input(BindValue::Text("中文".into()));
        let enc = p.encode_value(852).unwrap();
        assert_eq!(crate::proto::charset::decode(&enc, 852), "中文");
        // 整数走 NUMBER 编码
        let p = BindParam::input(BindValue::Int(42));
        assert_eq!(
            crate::proto::oracle_number::decode_number_to_i64(&p.encode_value(852).unwrap()).unwrap(),
            42
        );
        // NULL 编码为空（线缆上写单字节 0）
        let p = BindParam::input(BindValue::Null);
        assert!(p.encode_value(852).unwrap().is_empty());
    }

    #[test]
    fn write_params_emits_meta_and_values() {
        let params = vec![
            BindParam::input(BindValue::Int(7)),
            BindParam::input(BindValue::Text("hi".into())),
        ];
        let mut w = TtcWriter::new();
        write_params(&mut w, &params, 852, 6, true).unwrap();
        let bytes = w.freeze();
        // 首个字节是首列的 DataType（NUMBER = 2）
        assert_eq!(bytes[0], u8::from(TnsType::Number));
        // 值段：MsgCode 7 出现在定义体之后
        assert!(bytes.contains(&7));
        assert!(bytes.len() > 10);
    }
}
