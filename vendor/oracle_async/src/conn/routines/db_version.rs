//! 真实数据库版本查询（MsgCode 3, Op 0x3B）——go-ora GetDBVersion 移植。
//! TTC 协商拿到的 server_version 字符串是 banner 尾巴（如 "x86_64/Linux
//! 2.4.xx"），**不是**数字版本；ALL_USERS.ORACLE_MAINTAINED 这类版本分支
//! 必须用本消息取得的真实主版本（11g 无该列，误判 12c+ 即 ORA-00904）。

use async_trait::async_trait;
use log::{debug, info, trace};
use crate::conn::Conn;
use crate::error::{Error, Result};
use crate::io::TtcWriter;
use super::Routine;

#[derive(Debug, Clone)]
pub struct DbVersion {
    /// 数字形态，如 "11.2.0.4.0"
    pub text: String,
    pub major: u32,
    pub minor: u32,
}

#[derive(Default)]
pub struct GetDbVersionRoutine;

impl GetDbVersionRoutine {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Routine<DbVersion> for GetDbVersionRoutine {
    async fn call(&mut self, conn: &mut Conn) -> Result<DbVersion> {
        let mut w = TtcWriter::new();
        w.put_bytes(&[3, 0x3B, 0, 1]);
        w.put_uint(0x100, 2, true, true);
        w.put_bytes(&[1, 1]);
        if conn.ttc_version >= 11 {
            w.put_uint(1, 4, true, true);
        }
        conn.send_writer(w).await?;

        let msg = conn.get_byte().await?;
        if msg != 8 {
            return Err(Error::Protocol(format!(
                "DB version query: expected MsgCode 8, got {msg}"
            )));
        }
        let length = conn.read_ci(2).await? as usize;
        let info = conn
            .read_clr()
            .await?
            .map(|b| String::from_utf8_lossy(&b[..length.min(b.len())]).into_owned())
            .unwrap_or_default();
        let number = conn.read_ci(4).await? as u32;

        // 半字节解码（go-ora 同式）：主版本 = byte3，次版本 = byte2 高半字节
        let major = (number >> 24) & 0xFF;
        let minor = (number >> 20) & 0xF;
        let text = format!(
            "{}.{}.{}.{}.{}",
            (number >> 24) & 0xFF,
            (number >> 20) & 0xF,
            (number >> 12) & 0xF,
            (number >> 8) & 0xF,
            number & 0xFF
        );
        trace!("DB version raw number={number:#010x}, info={info}");

        conn.db_version_text = text.clone();
        conn.db_version_major = major;
        // Info = OCI 同源的完整 banner（如 "Oracle Database 11g Enterprise
        // Edition Release 11.2.0.4.0 - 64bit Production"）——展示层用它与
        // 原生 OCI / go-ora 严格一致
        conn.db_version_info = info.clone();
        info!("Oracle database version: {text} (info: {info})");
        debug!("DB version major={major}, minor={minor}");

        Ok(DbVersion { text, major, minor })
    }
}
