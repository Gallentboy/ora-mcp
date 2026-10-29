//! LOB 写入与操作——go-ora `lob.go` 的逐字段复刻。
//!
//! 协议总览（TTC `0x60` 消息 + operationID 区分动作）：
//! - `0x110` 创建临时 LOB（sourceLocator 预置 0x28 字节，[1]=0x54）
//! - `0x40`  写入数据（消息体 = `0x0E` + CLR(data)）
//! - `0x2`   读取数据（getData，按 sourceOffset/size 取）
//! - `0x80`  追加（append：destLocator = 目标）
//! - `0x111` 释放临时 LOB
//!
//! writeOp 的字段序（TTC>=3 路径，真机 11g 走这条）：
//! `[3,0x60,0]` + srcFlag + srcLen(comp4) + destFlag + destLen(comp4)
//! + `0,0`（TTC>=3 用 8 字节偏移取代）+ charsetFlag + sizeFlag + nullO2UFlag
//! + opID(comp4) + scnFlag + scnLen(comp4) + srcOffset(comp8) + destOffset(comp8)
//! + sendSizeFlag + 6 零字节（TTC>=4）+ sourceLocator + destLocator
//! + charsetId(2) + scn 数组 + size(8)。
//!
//! 已知边界：真机 11g 上创建临时 LOB 需要服务端允许临时段（普通用户默认
//! 可用）；本模块的真机验证依赖可写 CLOB/BLOB 列，回归测试在无该条件时
//! 只做离线编解码校验（见 tests）。

use log::{debug, trace};
use crate::conn::Conn;
use crate::error::{Error, OracleError, Result};
use crate::io::{TtcReader, TtcWriter};

/// LOB 定位符与状态（go-ora Lob）
#[derive(Debug, Clone, Default)]
pub struct LobRef {
    pub source_locator: Vec<u8>,
    pub dest_locator: Vec<u8>,
    pub source_offset: i64,
    pub dest_offset: i64,
    pub source_len: usize,
    pub dest_len: usize,
    pub charset_id: u32,
    pub size: u64,
    pub b_null_o2u: bool,
    pub is_null: bool,
    pub send_size: bool,
    pub scn: Vec<u8>,
}

impl LobRef {
    pub fn new() -> Self {
        Self::default()
    }

    /// go-ora isTemporary：locator[7]&1 或 locator[4]&0x40 或 value-based
    pub fn is_temporary(&self) -> bool {
        if self.source_locator.len() > 7 {
            let l = &self.source_locator;
            return l[7] & 1 == 1 || l[4] & 0x40 == 0x40 || l[4] & 0x20 > 0;
        }
        false
    }

    fn initialize(&mut self) {
        self.b_null_o2u = false;
        self.send_size = false;
        self.size = 0;
        self.is_null = false;
        self.source_offset = 0;
        self.dest_offset = 0;
    }
}

/// writeOp 的字段序列化（go-ora Lob.writeOp 逐字段）
fn write_op(w: &mut TtcWriter, lob: &LobRef, operation_id: u32, ttc_version: u8) {
    w.put_bytes(&[3, 0x60, 0]);
    // source locator 标志 + 长度
    if lob.source_locator.is_empty() {
        w.put_byte(0);
    } else {
        w.put_byte(1);
    }
    w.put_uint(lob.source_len as u64, 4, true, true);
    // dest locator 标志 + 长度
    if lob.dest_locator.is_empty() {
        w.put_byte(0);
    } else {
        w.put_byte(1);
    }
    w.put_uint(lob.dest_len as u64, 4, true, true);
    // 偏移（TTC<3 用 4 字节；>=3 用后面的 8 字节）
    if ttc_version < 3 {
        w.put_uint(lob.source_offset as u64, 4, true, true);
        w.put_uint(lob.dest_offset as u64, 4, true, true);
    } else {
        w.put_bytes(&[0, 0]);
    }
    // charsetId 标志
    if lob.charset_id != 0 {
        w.put_byte(1);
    } else {
        w.put_byte(0);
    }
    // sendSize 标志（TTC<3 走这里）
    if lob.send_size && ttc_version < 3 {
        w.put_byte(1);
    } else {
        w.put_byte(0);
    }
    // bNullO2U 标志
    if lob.b_null_o2u {
        w.put_byte(1);
    } else {
        w.put_byte(0);
    }
    // operationID
    w.put_uint(operation_id as u64, 4, true, true);
    // scn 标志 + 长度
    if lob.scn.is_empty() {
        w.put_byte(0);
    } else {
        w.put_byte(1);
    }
    w.put_uint(lob.scn.len() as u64, 4, true, true);
    if ttc_version >= 3 {
        w.put_uint(lob.source_offset as u64, 8, true, true);
        w.put_uint(lob.dest_offset as u64, 8, true, true);
        if lob.send_size {
            w.put_byte(1);
        } else {
            w.put_byte(0);
        }
    }
    if ttc_version >= 4 {
        w.put_bytes(&[0, 0, 0, 0, 0, 0]);
    }
    if !lob.source_locator.is_empty() {
        w.put_bytes(&lob.source_locator);
    }
    if !lob.dest_locator.is_empty() {
        w.put_bytes(&lob.dest_locator);
    }
    if lob.charset_id != 0 {
        w.put_uint(lob.charset_id as u64, 2, true, true);
    }
    if ttc_version < 3 && lob.send_size {
        w.put_uint(lob.size, 4, true, true);
    }
    for x in &lob.scn {
        w.put_uint(*x as u64, 4, true, true);
    }
    if ttc_version >= 3 && lob.send_size {
        w.put_uint(lob.size, 8, true, true);
    }
}

/// 读 LOB 响应（go-ora Lob.read）：Msg 8 回填 locator/尺寸，Msg 14 取数据，
/// Msg 4/9 结束
async fn read_lob_response(conn: &mut Conn, lob: &mut LobRef, out: &mut Vec<u8>) -> Result<()> {
    loop {
        let msg = conn.get_byte().await?;
        trace!("LOB response MsgCode: {msg}");
        match msg {
            8 => {
                // 回填 source locator（同长）
                if !lob.source_locator.is_empty() {
                    conn.ensure_in_buffer(lob.source_locator.len()).await?;
                    let mut r = TtcReader::new(&mut conn.in_buffer);
                    lob.source_locator = r.get_bytes(lob.source_locator.len())?;
                    lob.source_len = lob.source_locator.len();
                } else {
                    lob.source_len = 0;
                }
                if !lob.dest_locator.is_empty() {
                    conn.ensure_in_buffer(lob.dest_locator.len()).await?;
                    let mut r = TtcReader::new(&mut conn.in_buffer);
                    lob.dest_locator = r.get_bytes(lob.dest_locator.len())?;
                    lob.dest_len = lob.dest_locator.len();
                } else {
                    lob.dest_len = 0;
                }
                if lob.charset_id != 0 {
                    lob.charset_id = conn.read_ci(2).await? as u32;
                }
                if lob.send_size {
                    lob.size = if conn.ttc_version < 3 {
                        conn.read_ci(4).await? as u64
                    } else {
                        conn.read_ci(8).await? as u64
                    };
                }
                if lob.b_null_o2u {
                    let t = conn.read_ci(2).await?;
                    if t != 0 {
                        // 服务端标记为 NULL：只置位、**不 break**——go-ora 继续循环
                        // 读完后续 Summary/EndOfCall，否则流错位污染下一条语句。
                        lob.is_null = true;
                    }
                }
            }
            14 => {
                // 数据块：单个 CLR
                if let Some(chunk) = conn.read_clr().await? {
                    out.extend_from_slice(&chunk);
                }
            }
            4 => {
                let s = crate::conn::routines::summary::read_summary(conn).await?;
                if s.ret_code != 0 && s.ret_code != 1403 {
                    let m = String::from_utf8_lossy(&s.error_message.unwrap_or_default()).to_string();
                    return Err(Error::Server(OracleError {
                        code: s.ret_code,
                        message: m,
                    }));
                }
                break;
            }
            9 => {
                crate::conn::routines::summary::read_end_of_call(conn).await?;
                break;
            }
            15 => {
                crate::conn::routines::row_common::read_warning(conn).await?;
            }
            other => {
                trace!("Skipping LOB response message code: {other}");
            }
        }
    }
    Ok(())
}

/// 创建临时 LOB（go-ora createTemporaryClob / createTemporaryBLOB，opID 0x110）
pub async fn create_temporary(conn: &mut Conn, clob: bool) -> Result<LobRef> {
    let mut lob = LobRef::new();
    lob.source_locator = vec![0u8; 0x28];
    lob.source_locator[1] = 0x54;
    lob.source_len = lob.source_locator.len();
    lob.b_null_o2u = true;
    lob.dest_offset = if clob { 0x70 } else { 0x71 };
    lob.scn = vec![0];
    lob.size = 0xA;
    lob.send_size = true;
    lob.dest_len = 0xA;
    if clob {
        // CLOB：charsetId = 服务器字符集（go-ora 用 0xB2=178 固定值，
        // 这里用会话字符集更稳），sourceOffset 放 charsetForm
        lob.charset_id = conn.server_charset as u32;
        lob.source_offset = 1; // CharsetForm = 1（数据库字符集）
    } else {
        lob.charset_id = 1;
        lob.source_offset = 0;
    }

    let mut w = TtcWriter::new();
    write_op(&mut w, &lob, 0x110, conn.ttc_version);
    debug!(
        "Creating temporary {} LOB",
        if clob { "CLOB" } else { "BLOB" }
    );
    conn.send_writer(w).await?;
    let mut sink = Vec::new();
    read_lob_response(conn, &mut lob, &mut sink).await?;
    if lob.source_locator.is_empty() || lob.source_locator.iter().all(|&b| b == 0) {
        return Err(Error::Protocol(
            "temporary LOB creation returned empty locator".into(),
        ));
    }
    trace!("temporary LOB created: {} bytes locator", lob.source_len);
    Ok(lob)
}

/// 写入数据（go-ora putData，opID 0x40：消息体 `0x0E` + CLR(data)）
///
/// 严格对齐 go-ora：写入前**不做** open，也不改动 locator 任何字节——
/// `value_getter.go` 的临时 LOB 路径是 createTemporaryClob/BLOB → putString/
/// putData 直连，`open` 只被 bfile.go 使用。改 locator 后再发回服务端会让
/// 服务端拿到非原样的定位符（实测报 ORA-22993）。
pub async fn put_data(conn: &mut Conn, lob: &mut LobRef, data: &[u8]) -> Result<()> {
    lob.initialize();
    lob.size = data.len() as u64;
    lob.send_size = true;
    lob.source_offset = 1;

    let mut w = TtcWriter::new();
    write_op(&mut w, lob, 0x40, conn.ttc_version);
    w.put_byte(0x0E);
    w.put_clr(data);
    debug!("Put LOB data: {} bytes", data.len());
    conn.send_writer(w).await?;
    let mut sink = Vec::new();
    read_lob_response(conn, lob, &mut sink).await
}

/// 写入字符串（CLOB，go-ora putString）
///
/// 与 `put_data` 的差异是 go-ora 源码里的既有不对称：putString **不设**
/// `size`/`sendSize`（`initialize()` 清零后不再赋值），因此消息尾部的 size
/// 字段整体不发送；只有 putData 发送 `size = len(data)`。
pub async fn put_string(conn: &mut Conn, lob: &mut LobRef, text: &str) -> Result<()> {
    lob.initialize();
    let encoded = crate::proto::charset::encode(text, lob.charset_id);
    lob.source_offset = 1;

    let mut w = TtcWriter::new();
    write_op(&mut w, lob, 0x40, conn.ttc_version);
    w.put_byte(0x0E);
    w.put_clr(&encoded);
    debug!(
        "Put LOB string: {} chars / {} bytes",
        text.chars().count(),
        encoded.len()
    );
    conn.send_writer(w).await?;
    let mut sink = Vec::new();
    read_lob_response(conn, lob, &mut sink).await
}

/// 读取全部数据（go-ora getData，opID 0x2）
pub async fn get_data(conn: &mut Conn, lob: &mut LobRef) -> Result<Vec<u8>> {
    get_data_with_offset(conn, lob, 0, 0).await
}

/// 按偏移/长度读取（offset/count 均 0 = 全部；go-ora getDataWithOffsetSize）
///
/// 与 go-ora 一致：读前后都不做 open/close，只发一次 opID=2 的 writeOp。
pub async fn get_data_with_offset(
    conn: &mut Conn,
    lob: &mut LobRef,
    offset: i64,
    count: i64,
) -> Result<Vec<u8>> {
    lob.initialize();
    lob.size = count as u64;
    lob.source_offset = offset + 1;
    lob.send_size = true;

    let mut w = TtcWriter::new();
    write_op(&mut w, lob, 0x2, conn.ttc_version);
    trace!("Read LOB data: offset={offset}, count={count}");
    conn.send_writer(w).await?;
    let mut out = Vec::new();
    read_lob_response(conn, lob, &mut out).await?;
    Ok(out)
}

/// 追加到目标 LOB（go-ora append，opID 0x80）
pub async fn append(conn: &mut Conn, src: &mut LobRef, dest_locator: Vec<u8>) -> Result<()> {
    src.initialize();
    src.dest_locator = dest_locator;
    src.dest_len = src.dest_locator.len();
    let mut w = TtcWriter::new();
    write_op(&mut w, src, 0x80, conn.ttc_version);
    debug!("Append LOB (dest {} bytes)", src.dest_len);
    conn.send_writer(w).await?;
    let mut sink = Vec::new();
    read_lob_response(conn, src, &mut sink).await
}

/// 释放临时 LOB（go-ora freeTemporary，opID 0x111）
pub async fn free_temporary(conn: &mut Conn, lob: &mut LobRef) -> Result<()> {
    lob.initialize();
    let mut w = TtcWriter::new();
    write_op(&mut w, lob, 0x111, conn.ttc_version);
    debug!("Freeing temporary LOB");
    conn.send_writer(w).await?;
    let mut sink = Vec::new();
    read_lob_response(conn, lob, &mut sink).await
}

/// 打开/关闭 LOB（go-ora open/close；临时 LOB 只需置位不往返）
pub async fn open(conn: &mut Conn, lob: &mut LobRef, mode: i64, op_id: u32) -> Result<()> {
    if lob.is_temporary() {
        if lob.source_locator.get(7).map(|b| b & 8).unwrap_or(0) == 8 {
            return Err(Error::Protocol("LOB TTC error: temporary locator bit set".into()));
        }
        if mode == 2 {
            if let Some(b) = lob.source_locator.get_mut(7) {
                *b |= 0x10;
            }
        }
        return Ok(());
    }
    lob.initialize();
    lob.size = mode as u64;
    lob.send_size = true;
    let mut w = TtcWriter::new();
    write_op(&mut w, lob, op_id, conn.ttc_version);
    conn.send_writer(w).await?;
    let mut sink = Vec::new();
    read_lob_response(conn, lob, &mut sink).await
}

pub async fn close(conn: &mut Conn, lob: &mut LobRef, op_id: u32) -> Result<()> {
    lob.initialize();
    let mut w = TtcWriter::new();
    write_op(&mut w, lob, op_id, conn.ttc_version);
    conn.send_writer(w).await?;
    let mut sink = Vec::new();
    read_lob_response(conn, lob, &mut sink).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// writeOp 的线缆布局：字段序与长度必须与 go-ora 一致
    #[test]
    fn write_op_layout() {
        let lob = LobRef {
            source_locator: vec![0u8; 0x28],
            source_len: 0x28,
            charset_id: 852,
            send_size: true,
            size: 10,
            scn: vec![0],
            dest_len: 0xA,
            dest_offset: 0x70,
            ..Default::default()
        };
        let mut w = TtcWriter::new();
        write_op(&mut w, &lob, 0x110, 6);
        let b = w.freeze();

        // 消息头
        assert_eq!(&b[0..3], &[3, 0x60, 0]);
        // source 标志=1 + 长度 0x28（压缩编码：[1, 0x28]）
        assert_eq!(b[3], 1);
        assert_eq!(&b[4..6], &[1, 0x28]);
        // dest 标志=0 + 长度 0xA
        assert_eq!(b[6], 0);
        assert_eq!(&b[7..9], &[1, 0x0A]);
        // TTC>=3：两个 0 字节占位偏移
        assert_eq!(&b[9..11], &[0, 0]);
        // charsetId 标志（852 != 0 → 1）
        assert_eq!(b[11], 1);
        // sendSize 标志（TTC>=3 时这里写 0）
        assert_eq!(b[12], 0);
        // bNullO2U 标志（false → 0）
        assert_eq!(b[13], 0);
        // operationID 0x110 压缩编码：[2, 0x01, 0x10]
        assert_eq!(&b[14..17], &[2, 0x01, 0x10]);
    }

    #[test]
    fn temporary_detection() {
        // locator[7]&1 → 临时
        let mut l = LobRef::new();
        l.source_locator = vec![0u8; 0x28];
        l.source_locator[7] = 1;
        assert!(l.is_temporary());

        // locator[4]&0x40 → 临时
        let mut l = LobRef::new();
        l.source_locator = vec![0u8; 0x28];
        l.source_locator[4] = 0x40;
        assert!(l.is_temporary());

        // 普通 locator
        let mut l = LobRef::new();
        l.source_locator = vec![0u8; 0x28];
        assert!(!l.is_temporary());
    }
}
