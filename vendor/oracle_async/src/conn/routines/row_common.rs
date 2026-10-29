//! TTCOEXEC / Fetch 共享的响应解析件：Msg 16 列描述、Msg 6 行块头、
//! Msg 21 列位图、单元格类型解码、Msg 27 隐式游标（RefCursor.load）、
//! Msg 15 服务端 Warning、语句类型判定。exec 与 fetch 两条路径必须同构——
//! exeOp=0x8021 下服务器会把 describe+行数据推迟到首个 [3,5,0] fetch 包
//! 返回（真机 11g 实测），fetch 循环不认 Msg 16 即字节错位。

use std::sync::Arc;
use log::{trace, warn};
use crate::conn::Conn;
use crate::error::{Error, Result};
use crate::io::TtcReader;
use crate::proto::tns_types::TnsType;
use crate::proto::decode_ext;
use crate::proto::{
    oracle_date::{decode_date, decode_datetime, decode_datetime_tz},
    oracle_number::decode_number_to_decimal,
};
use crate::queryable::row::ColumnMeta;
use crate::queryable::values::OracleValue;
use crate::proto::charset;

/// 语句类型（go-ora StmtType 同口径，由 refineSqlText 前缀判定）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StmtType {
    Select,
    Dml,
    PlSql,
    Others,
}

/// go-ora refineSqlText：剥离块注释/**/、行注释--、引号内内容后取有效前缀
fn refine_sql_text(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut in_single = false;
    let mut in_double = false;
    let mut block_comment = false;
    let mut line_comment = false;
    let mut i = 0;
    while i < bytes.len() {
        let ch = bytes[i];
        match ch {
            b'\\' => {
                i += 1; // bypass next character
            }
            b'/' if !in_double && !in_single && !line_comment => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                    block_comment = true;
                    i += 1;
                }
            }
            b'*' if !in_double && !in_single && !line_comment => {
                if block_comment && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    block_comment = false;
                    i += 1;
                }
            }
            b'\'' if !block_comment && !line_comment && !in_double => {
                in_single = !in_single;
            }
            b'"' if !block_comment && !line_comment && !in_single => {
                in_double = !in_double;
            }
            b'-' if !block_comment && i + 1 < bytes.len() && bytes[i + 1] == b'-' && !in_single && !in_double => {
                line_comment = true;
                i += 1;
            }
            b'\n' => {
                line_comment = false;
                out.push(ch); // go-ora 保留换行
            }
            _ => {
                if !block_comment && !line_comment && !in_single && !in_double {
                    out.push(ch);
                }
            }
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).trim().to_string()
}

/// go-ora NewStmt 同式判定：剥前导 '(' 后按大写前缀分派
pub fn detect_stmt_type(sql: &str) -> StmtType {
    let mut refined = refine_sql_text(sql);
    if refined.starts_with('(') {
        refined.remove(0);
    }
    let u = refined.to_uppercase();
    if u.starts_with("SELECT") || u.starts_with("WITH") {
        StmtType::Select
    } else if u.starts_with("INSERT")
        || u.starts_with("MERGE")
        || u.starts_with("UPDATE")
        || u.starts_with("DELETE")
    {
        StmtType::Dml
    } else if u.starts_with("DECLARE") || u.starts_with("BEGIN") {
        StmtType::PlSql
    } else {
        StmtType::Others
    }
}

/// Msg 15：服务端 Warning（go-ora NewWarningObject）
pub async fn read_warning(conn: &mut Conn) -> Result<()> {
    let ret_code = conn.read_ci(2).await? as i32;
    let length = conn.read_ci(2).await? as usize;
    let _flag = conn.read_ci(2).await?;
    if ret_code != 0 && length > 0 {
        if let Some(msg) = conn.read_clr().await? {
            warn!(
                "Oracle warning ORA-{:05}: {}",
                ret_code,
                String::from_utf8_lossy(&msg)
            );
        }
    }
    Ok(())
}

/// Msg 27：隐式结果集项（go-ora RefCursor.load 逐字段）——返回列集与
/// 服务端游标 ID（后续行数据经 [3,5,0] 续取）
pub async fn read_ref_cursor(conn: &mut Conn) -> Result<(Arc<Vec<ColumnMeta>>, u16)> {
    let _len = conn.get_byte().await?;
    let _max_row_size = conn.read_ci(4).await?;
    let col_count = conn.read_ci(4).await? as usize;
    let mut columns = Vec::with_capacity(col_count);
    if col_count > 0 {
        let _ = conn.get_byte().await?;
        for _ in 0..col_count {
            columns.push(read_column_meta(conn).await?);
        }
    }
    let _ = conn.read_dlc().await?;
    if conn.ttc_version >= 3 {
        let _ = conn.read_ci(4).await?;
        let _ = conn.read_ci(4).await?;
    }
    if conn.ttc_version >= 4 {
        let _ = conn.read_ci(4).await?;
        let _ = conn.read_ci(4).await?;
    }
    if conn.ttc_version >= 5 {
        let _ = conn.read_dlc().await?;
    }
    let cursor_id = conn.read_ci(4).await? as u16;
    if cursor_id == 0 {
        return Err(Error::Protocol("implicit cursor id = 0".into()));
    }
    Ok((Arc::new(columns), cursor_id))
}

/// Msg 16：列描述（go-ora command.go case 16 + ParameterInfo.load 的
/// TTC v6 形态逐字段移植），含段尾 DLC/int 段。列名按服务器字符集解码
///（中文列名在 852=ZHS16GBK 库上是 GBK 字节）。
pub async fn read_describe(conn: &mut Conn) -> Result<Vec<ColumnMeta>> {
    conn.ensure_in_buffer(2).await?;
    let (_prefix_len, _max_row_size, col_count) = {
        let mut reader = TtcReader::new(&mut conn.in_buffer);
        let prefix_len = reader.get_byte()? as usize;
        let _ = reader.get_bytes(prefix_len)?;
        let max_row_size = reader.get_int(4, true, true)?;
        let col_count = reader.get_int(4, true, true)? as usize;
        if col_count > 0 {
            let _ = reader.get_byte()?;
        }
        (prefix_len, max_row_size, col_count)
    };

    let mut columns = Vec::with_capacity(col_count);
    for _ in 0..col_count {
        columns.push(read_column_meta(conn).await?);
    }

    // 尾段：一个 DLC + TTC>=3 两个 int(4) + TTC>=4 两个 int(4) + TTC>=5 一个 DLC
    conn.ensure_in_buffer(2).await?;
    let mut r = TtcReader::new(&mut conn.in_buffer);
    let _ = r.get_dlc()?;
    if conn.ttc_version >= 3 {
        let _ = r.get_int64(4, true, true)?;
        let _ = r.get_int64(4, true, true)?;
    }
    if conn.ttc_version >= 4 {
        let _ = r.get_int64(4, true, true)?;
        let _ = r.get_int64(4, true, true)?;
    }
    if conn.ttc_version >= 5 {
        let _ = r.get_dlc()?;
    }
    Ok(columns)
}

/// 单列元数据（go-ora ParameterInfo.load 的 TTC v6 形态逐字段）。
/// describe（Msg 16）与隐式游标（Msg 27）共用。
pub async fn read_column_meta(conn: &mut Conn) -> Result<ColumnMeta> {
    conn.ensure_in_buffer(3).await?;
    let (data_type_byte, tns, mut precision) = {
        let mut r = TtcReader::new(&mut conn.in_buffer);
        let data_type_byte = r.get_byte()?;
        let tns = TnsType::from(data_type_byte);
        let _flag = r.get_byte()?;
        let precision = r.get_byte()?;
        (data_type_byte, tns, precision)
    };
    // 时间/数值族的 scale 是压缩 BE int(2)，其余为裸字节
    let scale: u8 = match tns {
        TnsType::Number
        | TnsType::TimeStampDty
        | TnsType::TimeStampTzDty
        | TnsType::IntervalDsDty
        | TnsType::Timestamp
        | TnsType::TimestampTz
        | TnsType::IntervalDs => conn.read_ci(2).await? as u8,
        _ => conn.get_byte().await?,
    };
    let _max_len = conn.read_ci(4).await?;
    let _max_no_of_array = conn.read_ci(4).await?;
    let _cont_flag = conn.read_ci(4).await?; // TTC<10 压缩 int(4)
    let _to_id = conn.read_dlc().await?;
    let _version = conn.read_ci(2).await?;
    let _charset_id = conn.read_ci(2).await?;
    let _charset_form = conn.get_byte().await?;
    let _max_char_len = conn.read_ci(4).await?;
    // TTC<8 无 oaccollid
    let _allow_null = conn.get_byte().await?;
    let _v7_name_len = conn.get_byte().await?; // v7 名称长度（弃）
    let name_bytes = conn.read_dlc().await?.unwrap_or_default();
    let col_name = charset::decode(&name_bytes, conn.server_charset as u32);
    let _schema = conn.read_dlc().await?;
    let _type_name = conn.read_dlc().await?;
    // TTC>=3：一个压缩 int(2)；TTC>=6：uds_flags 压缩 int(4)
    if conn.ttc_version >= 3 {
        let _ = conn.read_ci(2).await?;
        if conn.ttc_version >= 6 {
            let _uds = conn.read_ci(4).await?;
        }
    }

    // NUMBER 无精度即 FLOAT（go-ora 口径：38 位、scale=0xFF）
    if tns == TnsType::Number && precision == 0 && (scale == 0 || scale == 0xFF) {
        precision = 38;
    }

    trace!(
        "describe col '{}' type={:?}({data_type_byte}) maxlen={_max_len} mcl={_max_char_len}",
        col_name,
        tns,
    );

    Ok(ColumnMeta {
        name: col_name,
        data_type: tns,
        max_len: _max_len as usize,
        precision,
        scale,
        allow_null: _allow_null > 0,
        charset_id: _charset_id as u32,
        charset_form: _charset_form,
    })
}

/// Msg 6：行块头（go-ora resultSet.load）
pub async fn read_row_header(conn: &mut Conn, column_count: usize) -> Result<Option<Vec<bool>>> {
    // v2 case 6 = ResultSet.load：跳 1 + i2 列数 + i4 高段 + i4 行数 + i2 UAC
    // + DLC 存在位图 + DLC。位图非空时即本批行的列存在标记（v2 setBitVector
    // 据此置每列 getDataFromServer，位序与 Msg 21 相同：列 n → 字节 n/8 位
    // n%8）——服务端省略 NULL 单元格时缺了它就会按全存在去读，流直接错位
    //（真机 PLAN_TABLE 大量可空列以 invalid int size 暴露）。空/NULL 位图
    // 返回 None = 沿用现值
    conn.ensure_in_buffer(2).await?;
    let mut r = TtcReader::new(&mut conn.in_buffer);
    let _ = r.get_byte()?;
    let _col_count = r.get_int(2, true, true)?;
    let _ = r.get_int(4, true, true)?;
    let _ = r.get_int(4, true, true)?;
    let _ = r.get_int(2, true, true)?;
    let bv = r.get_dlc()?;
    let _ = r.get_dlc()?;
    Ok(bv.filter(|b| !b.is_empty()).map(|bytes| {
        (0..column_count)
            .map(|i| {
                bytes
                    .get(i / 8)
                    .map(|byte| byte & (1 << (i % 8)) != 0)
                    .unwrap_or(false)
            })
            .collect()
    }))
}

/// Msg 21：列存在位图（true = 本行该列有数据）
pub async fn read_bitvector(conn: &mut Conn, column_count: usize) -> Result<Vec<bool>> {
    conn.ensure_in_buffer(2).await?;
    let mut reader = TtcReader::new(&mut conn.in_buffer);
    let _cols_sent = reader.get_int(2, true, true)?;
    let bv_len = column_count.div_ceil(8);
    let bv_bytes = reader.get_bytes(bv_len)?;
    Ok((0..column_count)
        .map(|i| bv_bytes[i / 8] & (1 << (i % 8)) != 0)
        .collect())
}

/// 单元格 CLR 字节 → 强类型值（文本按列字符集解码：852=GBK 等）。
/// 逐单元格调用，内联收益明确（与 engines 的单元格辅助同一口径）。
#[inline]
pub fn decode_cell(tns: &TnsType, b: &[u8], charset_id: u32) -> OracleValue {
    match tns {
        TnsType::Number => match decode_number_to_decimal(b) {
            Ok(dec) => OracleValue::Number(dec),
            Err(_) => OracleValue::Text(charset::decode(b, charset_id)),
        },
        TnsType::Varchar | TnsType::Char | TnsType::Long | TnsType::LongVarChar | TnsType::NChar => {
            OracleValue::Text(charset::decode(b, charset_id))
        }
        TnsType::Date => match decode_date(b) {
            Ok(d) => OracleValue::Date(d),
            Err(_) => OracleValue::Binary(b.to_vec()),
        },
        TnsType::Timestamp | TnsType::TimeStampDty => match decode_datetime(b) {
            Ok(dt) => OracleValue::Timestamp(dt),
            Err(_) => OracleValue::Binary(b.to_vec()),
        },
        TnsType::TimestampTz | TnsType::TimeStampTzDty => match decode_datetime_tz(b) {
            Ok(tz) => OracleValue::TimestampTz(tz),
            Err(_) => OracleValue::Binary(b.to_vec()),
        },
        TnsType::Raw | TnsType::LongRaw => OracleValue::Binary(b.to_vec()),
        // 扩展类型（proto/decode_ext 的 go-ora 逐字节复刻）
        TnsType::Boolean => match decode_ext::decode_boolean(b) {
            Some(v) => OracleValue::Boolean(v),
            None => OracleValue::Binary(b.to_vec()),
        },
        TnsType::IntervalYm | TnsType::IntervalYmDty => match decode_ext::decode_interval_ym(b) {
            Some(s) => OracleValue::Text(s),
            None => OracleValue::Binary(b.to_vec()),
        },
        TnsType::IntervalDs | TnsType::IntervalDsDty => match decode_ext::decode_interval_ds(b) {
            Some(s) => OracleValue::Text(s),
            None => OracleValue::Binary(b.to_vec()),
        },
        TnsType::BFloat | TnsType::IBFloat => match decode_ext::decode_binary_float(b) {
            Some(v) => OracleValue::Float(v as f64),
            None => OracleValue::Binary(b.to_vec()),
        },
        TnsType::BDouble | TnsType::IBDouble => match decode_ext::decode_binary_double(b) {
            Some(v) => OracleValue::Float(v),
            None => OracleValue::Binary(b.to_vec()),
        },
        TnsType::Vector => match decode_ext::decode_vector(b) {
            Some(s) => OracleValue::Text(s),
            None => OracleValue::Binary(b.to_vec()),
        },
        TnsType::URowid => OracleValue::Text(decode_ext::decode_urowid_hex(b)),
        TnsType::Json => OracleValue::Text(charset::decode(b, charset_id)),
        TnsType::XmlType | TnsType::OciXmlType => OracleValue::Text(charset::decode(b, charset_id)),
        _ => OracleValue::Text(charset::decode(b, charset_id)),
    }
}

/// LOB（CLOB/BLOB）内联单元格——go-ora decodeColumnValue 的 INLINE 分支：
/// maxSize(comp4) + size(comp8) + chunkSize(comp4) + [CLOB：flag 字节 + 可选
/// charsetId(comp2) + charsetForm 字节] + 内容 CLR + 定位符 CLR。
/// maxSize==0 即 NULL。DBMS_METADATA.GET_DDL 等 CLOB 结果全走此形态。
async fn read_lob_inline(conn: &mut Conn, clob: bool) -> Result<OracleValue> {
    let max_size = conn.read_ci(4).await? as usize;
    if max_size == 0 {
        return Ok(OracleValue::Null);
    }
    let _size = conn.read_ci(8).await?;
    let _chunk_size = conn.read_ci(4).await?;
    let mut csid = 0u32;
    if clob {
        let flag = conn.get_byte().await?;
        if flag == 1 {
            csid = conn.read_ci(2).await? as u32;
        }
        let form = conn.get_byte().await?;
        // charsetId==0 时按 form 选服务器/国家字符集（go-ora 同式）
        if csid == 0 {
            csid = if form == 1 {
                conn.server_charset as u32
            } else {
                conn.server_ncharset as u32
            };
        }
    }
    let content = conn.read_clr().await?;
    let _locator = conn.read_clr().await?; // 定位符（临时 LOB 由服务端回收）
    Ok(match content {
        Some(b) if clob => OracleValue::Text(charset::decode(&b, csid)),
        Some(b) => OracleValue::Binary(b),
        None => OracleValue::Null,
    })
}

/// 读一行（Msg 7 体）：按位图逐列分派（LOB 列走内联形态，其余 CLR）；
/// 位图缺省视为全存在
pub async fn read_row(
    conn: &mut Conn,
    columns: &Arc<Vec<ColumnMeta>>,
    bit_vector: &[bool],
) -> Result<crate::queryable::Row> {
    let mut row_values = Vec::with_capacity(columns.len());
    for (i, col) in columns.iter().enumerate() {
        let present = bit_vector.get(i).copied().unwrap_or(true);
        if !present {
            row_values.push(OracleValue::Null);
            continue;
        }
        let val = match col.data_type {
            TnsType::Clob => read_lob_inline(conn, true).await?,
            TnsType::Blob | TnsType::BFile => read_lob_inline(conn, false).await?,
            _ => match conn.read_clr().await? {
                None => OracleValue::Null,
                Some(b) => decode_cell(&col.data_type, &b, col.charset_id),
            },
        };
        // LONG 族（8/24/94）单元格后跟两个压缩 int4（go-ora case 7 尾段）
        if matches!(
            col.data_type,
            TnsType::Long | TnsType::LongRaw | TnsType::LongVarChar
        ) {
            let _ = conn.read_ci(4).await?;
            let _ = conn.read_ci(4).await?;
        }
        row_values.push(val);
    }
    trace!("row decoded: {} cell(s)", row_values.len());
    Ok(crate::queryable::Row::new(columns.clone(), row_values))
}
