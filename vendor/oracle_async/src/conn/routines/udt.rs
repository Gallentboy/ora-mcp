//! UDT（用户自定义对象类型）解码——go-ora `udt.go` + `parameter.go` 的
//! udt 分支实现（go-ora 侧大部分为注释掉的实验代码，此处按其 wire 事实
//! 独立实现，供只读浏览使用）。
//!
//! wire 格式（go-ora parameter.go decodePrimValue 的 XMLType/UDT 分支）：
//! `DLC(toid) + 3 零字节 + size(comp4) + 0x01 0x01 + [size>0 时逐属性值]`
//! size==0 表示对象为 NULL（后跟 0x81 0x01）。
//!
//! 属性元数据来自数据字典：
//! ```sql
//! SELECT attr_name, attr_type_name, LENGTH, PRECISION, SCALE
//!   FROM ALL_TYPE_ATTRS WHERE UPPER(owner)=:1 AND UPPER(type_name)=:2
//!  ORDER BY attr_no
//! ```
//! 属性值本身按其 attr_type_name 映射的 TNS 类型解码（NUMBER/VARCHAR2/
//! DATE/TIMESTAMP/RAW 五类覆盖 go-ora 注释里声明的可操作集合）。

use std::sync::Arc;
use crate::conn::Conn;
use crate::error::Result;
use crate::proto::tns_types::TnsType;
use crate::queryable::row::ColumnMeta;
use crate::queryable::values::OracleValue;

/// UDT 属性元数据（ALL_TYPE_ATTRS 的一行）
#[derive(Debug, Clone)]
pub struct UdtAttribute {
    pub name: String,
    /// 属性类型名（VARCHAR2 / NUMBER / DATE / TIMESTAMP / RAW / 嵌套类型名）
    pub type_name: String,
    pub length: usize,
    pub precision: i32,
    pub scale: i32,
}

impl UdtAttribute {
    /// 属性类型名 → TNS 类型（go-ora 注释声明的可操作集合 + 常见别名）
    pub fn to_tns_type(&self) -> TnsType {
        let t = self.type_name.to_uppercase();
        match t.as_str() {
            "NUMBER" | "INTEGER" | "INT" | "DECIMAL" | "NUMERIC" | "FLOAT" => TnsType::Number,
            "VARCHAR2" | "VARCHAR" | "NVARCHAR2" | "CHAR" | "NCHAR" | "CLOB" => TnsType::Varchar,
            "DATE" => TnsType::Date,
            "TIMESTAMP" => TnsType::Timestamp,
            "TIMESTAMP WITH TIME ZONE" => TnsType::TimestampTz,
            "RAW" => TnsType::Raw,
            _ => TnsType::Varchar, // 嵌套 UDT/未知：按文本兜底（原始字节 lossy）
        }
    }
}

/// 查询某个 UDT 的属性清单（ALL_TYPE_ATTRS，按 attr_no 排序）
pub async fn load_attributes(
    conn: &mut Conn,
    owner: &str,
    type_name: &str,
) -> Result<Vec<UdtAttribute>> {
    use crate::queryable::Queryable;
    let sql = format!(
        "SELECT attr_name, attr_type_name, LENGTH, PRECISION, SCALE \
         FROM all_type_attrs \
         WHERE UPPER(owner) = UPPER('{}') AND UPPER(type_name) = UPPER('{}') \
         ORDER BY attr_no",
        owner.replace('\'', "''"),
        type_name.replace('\'', "''")
    );
    let mut rs = conn.query(&sql).await?;
    let mut attrs = Vec::new();
    while let Some(row) = rs.next_row().await? {
        let name = row.values().first().map(|v| v.to_string()).unwrap_or_default();
        let type_name = row.values().get(1).map(|v| v.to_string()).unwrap_or_default();
        let length = row
            .values()
            .get(2)
            .map(|v| v.to_string().parse::<usize>().unwrap_or(0))
            .unwrap_or(0);
        let precision = row
            .values()
            .get(3)
            .map(|v| v.to_string().parse::<i32>().unwrap_or(0))
            .unwrap_or(0);
        let scale = row
            .values()
            .get(4)
            .map(|v| v.to_string().parse::<i32>().unwrap_or(0))
            .unwrap_or(0);
        attrs.push(UdtAttribute {
            name,
            type_name,
            length,
            precision,
            scale,
        });
    }
    Ok(attrs)
}

/// 解码一个 UDT 单元格：返回 `{ATTR1: v1, ATTR2: v2}` 形态的展示串。
///
/// 调用方需先用 `load_attributes` 拿到属性清单（属性顺序即 wire 顺序）。
/// 对象为 NULL 时返回 `OracleValue::Null`。
pub async fn read_udt_value(
    conn: &mut Conn,
    attrs: &[UdtAttribute],
) -> Result<OracleValue> {
    // DLC(toid)
    let _toid = conn.read_dlc().await?;
    // 3 个零字节
    conn.ensure_in_buffer(3).await?;
    {
        let mut r = crate::io::TtcReader::new(&mut conn.in_buffer);
        let _ = r.get_bytes(3)?;
    }
    // size（对象为空则 NULL）
    let size = conn.read_ci(4).await? as usize;
    // 0x01 0x01
    conn.ensure_in_buffer(2).await?;
    {
        let mut r = crate::io::TtcReader::new(&mut conn.in_buffer);
        let _ = r.get_bytes(2)?;
    }
    if size == 0 {
        // 0x81 0x01 尾巴
        conn.ensure_in_buffer(2).await?;
        {
            let mut r = crate::io::TtcReader::new(&mut conn.in_buffer);
            let _ = r.get_bytes(2)?;
        }
        return Ok(OracleValue::Null);
    }

    let mut parts: Vec<String> = Vec::with_capacity(attrs.len());
    for attr in attrs {
        // 属性值：固定长度 CLR（go-ora GetFixedClr，按声明的 max_len 读）
        let tns = attr.to_tns_type();
        let max_len = if attr.length > 0 { attr.length } else { 4000 };
        conn.ensure_in_buffer(1).await?;
        let first = conn.in_buffer[0];
        let raw = if first == 0 || first == 0xFF || first == 0xFD {
            conn.ensure_in_buffer(1).await?;
            {
                use bytes::Buf as _;
                conn.in_buffer.advance(1);
            }
            None
        } else if first == 0xFE {
            conn.read_clr().await?
        } else {
            // 固定长度形态：长度字节后直接跟 max_len 字节数据
            conn.ensure_in_buffer(1 + max_len).await?;
            let mut r = crate::io::TtcReader::new(&mut conn.in_buffer);
            let n = r.get_byte()? as usize;
            Some(r.get_bytes(n)?)
        };
        let value = match raw {
            None => "NULL".to_string(),
            Some(b) => super::row_common::decode_cell(&tns, &b, conn.server_charset as u32)
                .to_string(),
        };
        parts.push(format!("{}: {}", attr.name, value));
    }
    Ok(OracleValue::Text(format!("{{{}}}", parts.join(", "))))
}

/// 构造属性列元数据（供需要 ColumnMeta 的调用方使用）
pub fn attributes_as_columns(attrs: &[UdtAttribute]) -> Arc<Vec<ColumnMeta>> {
    Arc::new(
        attrs
            .iter()
            .map(|a| ColumnMeta {
                name: a.name.clone(),
                data_type: a.to_tns_type(),
                max_len: if a.length > 0 { a.length } else { 4000 },
                precision: a.precision.clamp(0, 255) as u8,
                scale: a.scale.clamp(0, 255) as u8,
                allow_null: true,
                charset_id: 0,
                charset_form: 0,
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attr_type_mapping() {
        let mk = |t: &str| UdtAttribute {
            name: "X".into(),
            type_name: t.into(),
            length: 0,
            precision: 0,
            scale: 0,
        };
        assert_eq!(mk("NUMBER").to_tns_type(), TnsType::Number);
        assert_eq!(mk("VARCHAR2").to_tns_type(), TnsType::Varchar);
        assert_eq!(mk("DATE").to_tns_type(), TnsType::Date);
        assert_eq!(mk("TIMESTAMP").to_tns_type(), TnsType::Timestamp);
        assert_eq!(mk("RAW").to_tns_type(), TnsType::Raw);
        // 大小写不敏感
        assert_eq!(mk("number").to_tns_type(), TnsType::Number);
        // 未知类型按文本兜底
        assert_eq!(mk("SOME_NESTED_TYPE").to_tns_type(), TnsType::Varchar);
    }

    #[test]
    fn columns_from_attrs() {
        let attrs = vec![
            UdtAttribute {
                name: "ID".into(),
                type_name: "NUMBER".into(),
                length: 22,
                precision: 10,
                scale: 0,
            },
            UdtAttribute {
                name: "NAME".into(),
                type_name: "VARCHAR2".into(),
                length: 100,
                precision: 0,
                scale: 0,
            },
        ];
        let cols = attributes_as_columns(&attrs);
        assert_eq!(cols.len(), 2);
        assert_eq!(cols[0].name, "ID");
        assert_eq!(cols[0].data_type, TnsType::Number);
        assert_eq!(cols[1].max_len, 100);
    }
}
