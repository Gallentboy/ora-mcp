//! TTC 数据类型协商（MsgCode 2）：客户端能力位 + 完整类型/表示表。
//!
//! 对照 go-ora `data_type_nego.go` 的 `buildTypeNego`/`write`/`read` 逐字节移植。
//! 此前用自造迷你类型表导致真机服务器无法解析（发完 MsgCode 2 后无响应，
//! 60s 握手定时器到点断连）——类型表必须按 go-ora 的完整清单发送：
//! - 表形态由客户端 CompileTimeCaps[27]（受服务器 caps[27] 适配清零）决定：
//!   0 = 逐字节（u8 截断）+ 单 0 终止符，非 0 = 逐 u16 BE + 双 0 终止符；
//! - 表截断点由服务器 caps[7]（TTC 版本）决定：≥8 全表 / ≥7 到 1200 锚点 /
//!   更早到 1100 锚点（锚点 = 构表游标在特定条目后的值）；
//! - ServerFlags 需回显服务器标志并置 bit1（go-ora protocolNegotiation 尾部
//!   的 ServerFlags |= 2）；
//! - 时区 11 字节与客户端时区版本号按 RuntimeCap[1]&1（受服务器 runtime
//!   caps[1] 适配）与 CompileTimeCaps[37]&2 条件发送。

use async_trait::async_trait;
use log::{debug, trace};
use crate::conn::Conn;
use crate::error::{Error, Result};
use crate::io::{TtcReader, TtcWriter};
use crate::proto::caps::{CLIENT_COMPILE_TIME_CAPS, CLIENT_RUNTIME_CAPS};
use super::Routine;

/// go-ora TypeAndRep 构建器：tr[0] 语义的游标 + 两个运行时表截断锚点
struct TypeRepBuilder {
    tr: Vec<u16>,
    cursor: usize,
    rep1100: usize,
    rep1200: usize,
}

impl TypeRepBuilder {
    fn new() -> Self {
        Self {
            tr: vec![0u16; 2369],
            cursor: 1,
            rep1100: 0,
            rep1200: 0,
        }
    }

    /// ndty==0 → 二元组 (dty, 0)；否则四元组 (dty, ndty, rep, 0)
    fn add(&mut self, dty: u16, ndty: u16, rep: u16) {
        self.tr[self.cursor] = dty;
        self.tr[self.cursor + 1] = ndty;
        if ndty == 0 {
            self.cursor += 2;
        } else {
            self.tr[self.cursor + 2] = rep;
            self.tr[self.cursor + 3] = 0;
            self.cursor += 4;
        }
    }

    /// 连续自映射区间 (x, x, UNIVERSAL=1)
    fn add_range(&mut self, lo: u16, hi: u16) {
        for x in lo..=hi {
            self.add(x, x, 1);
        }
    }

    fn build() -> (Vec<u16>, usize, usize) {
        let mut b = Self::new();
        // 基础类型（NCHAR/NUMBER/LONG/DATE/RAW/LONG RAW + 整数族 + ROWID…）
        b.add(1, 1, 1);
        b.add(2, 2, 10);
        b.add(8, 8, 1);
        b.add(12, 12, 10);
        b.add(23, 23, 1);
        b.add(24, 24, 1);
        b.add_range(25, 33); // UB2..PTRW
        b.add(10, 10, 1); // TIDDEF
        b.add(11, 11, 1); // ROWID
        b.add(40, 40, 1);
        b.add(41, 41, 1);
        b.add(117, 117, 1);
        b.add(120, 120, 1);
        b.add_range(290, 294);
        b.add_range(298, 313);
        b.add_range(315, 323);
        b.add_range(327, 329);
        b.add(331, 331, 1);
        b.add_range(333, 340);
        b.add_range(341, 346);
        b.add_range(348, 349);
        b.add_range(354, 355);
        b.add(359, 359, 1);
        b.add(363, 363, 1);
        b.add_range(380, 391);
        b.add_range(393, 401);
        b.add_range(404, 407);
        b.add_range(413, 427);
        b.add_range(429, 433);
        b.add_range(449, 450);
        b.add_range(454, 486);
        b.add_range(490, 496);
        b.add_range(498, 502);
        b.add_range(509, 510);
        b.add_range(513, 514);
        b.add_range(516, 543);
        b.add(560, 560, 1);
        b.add(565, 565, 1);
        b.add_range(572, 576);
        b.add(578, 578, 1);
        b.add(563, 563, 1);
        b.add(564, 564, 1);
        b.add_range(579, 585);
        // 映射到规范类型的变体（BInteger/FLOAT/VarNum/PDN→NUMBER，VARCHAR→NCHAR…）
        b.add(3, 2, 10);
        b.add(4, 2, 10);
        b.add(5, 1, 1);
        b.add(6, 2, 10);
        b.add(7, 2, 10);
        b.add(9, 1, 1);
        b.add(15, 1, 1); // VBI
        b.add(39, 120, 1);
        b.add(58, 0, 0);
        b.add(68, 2, 10);
        b.add(69, 0, 0);
        b.add(70, 0, 0);
        b.add(74, 0, 0);
        b.add(76, 0, 0);
        b.add(91, 2, 10);
        b.add(94, 1, 1);
        b.add(95, 23, 1);
        b.add(96, 96, 1);
        b.add(97, 96, 1);
        b.add(100, 100, 1);
        b.add(101, 101, 1);
        b.add(102, 102, 1); // CURSOR
        b.add(104, 11, 1); // RDD → ROWID
        b.add(105, 0, 0);
        b.add(106, 106, 1);
        b.add(108, 109, 1);
        b.add(109, 109, 1);
        b.add(110, 111, 1);
        b.add(111, 111, 1);
        b.add(112, 112, 1); // CLOB
        b.add(113, 113, 1); // BLOB
        b.add(114, 114, 1); // BFILE
        b.add(115, 115, 1); // CFILE
        b.add(116, 102, 1); // RSET → CURSOR
        b.add(118, 0, 0);
        b.add(119, 119, 0); // JSON（NATIVE 表示）
        b.add(121, 0, 0);
        b.add(122, 0, 0);
        b.add(123, 0, 0);
        b.add(127, 127, 1); // VECTOR
        b.add(136, 0, 0);
        b.add(146, 146, 1);
        b.add(147, 0, 0);
        b.add(152, 2, 10);
        b.add(153, 2, 10);
        b.add(154, 2, 10);
        b.add(155, 1, 1);
        b.add(156, 12, 10);
        b.add(172, 2, 10);
        b.add_range(178, 183);
        b.add(184, 12, 10);
        b.add_range(185, 190);
        b.add(191, 0, 0);
        b.add(192, 0, 0);
        b.add(195, 112, 1); // DCLOB → CLOB
        b.add(196, 113, 1); // DBLOB → BLOB
        b.add(197, 114, 1); // DBFILE → BFILE
        b.add(208, 208, 1); // UROWID
        b.add(209, 0, 0);
        b.add(231, 231, 1);
        b.add(232, 231, 1);
        b.add(233, 233, 1);
        b.add(252, 252, 1);
        b.add(241, 109, 1);
        b.add(515, 0, 0);
        b.rep1100 = b.cursor;
        // 12c 扩展类型
        b.add_range(590, 592);
        b.add_range(613, 616);
        b.add(611, 611, 1);
        b.add(612, 612, 1);
        b.add_range(593, 605);
        b.add_range(622, 632);
        b.add(637, 637, 1);
        b.add(638, 638, 1);
        b.add(636, 636, 1);
        b.rep1200 = b.cursor;
        b.add_range(639, 640);
        b.tr[0] = b.cursor as u16; // go-ora TypeAndRep[0] 即游标本身
        (b.tr, b.rep1100, b.rep1200)
    }
}

/// 本地时区偏移的 11 字节 ANO/TTC 时区形态（go-ora TZBytes）
fn tz_bytes() -> [u8; 11] {
    let offset = chrono::Local::now().offset().local_minus_utc();
    let hours = (offset / 3600) as i8;
    let minutes = ((offset / 60) % 60) as i8;
    let seconds = (offset % 60) as i8;
    [
        128, 0, 0, 0,
        (hours + 60) as u8,
        (minutes + 60) as u8,
        (seconds + 60) as u8,
        128, 0, 0, 0,
    ]
}

#[derive(Default)]
pub struct DataTypeNegoRoutine;

impl DataTypeNegoRoutine {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Routine<()> for DataTypeNegoRoutine {
    async fn call(&mut self, conn: &mut Conn) -> Result<()> {
        let sc = conn.server_compile_caps.clone();
        let src = conn.server_runtime_caps.clone();
        let caps7 = sc.get(7).copied().unwrap_or(0);

        // 客户端能力位的服务端适配（buildTypeNego 的调整逻辑逐条照抄）
        let mut compile_caps = CLIENT_COMPILE_TIME_CAPS.to_vec();
        let mut runtime_caps = CLIENT_RUNTIME_CAPS.to_vec();
        if sc.len() <= 27 || sc.get(27).copied().unwrap_or(0) == 0 {
            compile_caps[27] = 0;
        }
        if caps7 < 7 {
            compile_caps[36] = 0;
        }
        if src.len() < 2 || src[1] & 1 != 1 {
            runtime_caps[1] &= 0;
        }
        if src.len() > 6 {
            if src[6] & 4 == 4 {
                runtime_caps[6] |= 4;
            }
            if src[6] & 2 == 2 {
                runtime_caps[6] |= 2;
            }
        }
        if sc.len() <= 37 || sc.get(37).copied().unwrap_or(0) & 2 != 2 {
            compile_caps[37] = 0;
            compile_caps[1] = 0;
        }

        let (tr, rep1100, rep1200) = TypeRepBuilder::build();
        let table_len = if caps7 >= 8 {
            tr[0] as usize
        } else if caps7 >= 7 {
            rep1200
        } else {
            rep1100
        };

        let mut w = TtcWriter::with_capacity(4096);
        w.put_byte(2); // MsgCode 2
        // 两个字符集字段：LE u16（go-ora PutInt(..., false, false)）
        w.put_uint(conn.server_charset as u64, 2, false, false);
        w.put_uint(conn.server_charset as u64, 2, false, false);
        w.put_byte(conn.server_flags | 2);
        w.put_byte(compile_caps.len() as u8);
        w.put_bytes(&compile_caps);
        w.put_byte(runtime_caps.len() as u8);
        w.put_bytes(&runtime_caps);
        if runtime_caps[1] & 1 == 1 {
            w.put_bytes(&tz_bytes());
            if compile_caps[37] & 2 == 2 {
                w.put_uint(0x20, 4, true, false); // clientTZVersion
            }
        }
        w.put_uint(conn.server_ncharset as u64, 2, false, false);
        // 类型/表示表：形态由客户端 caps[27]（受服务器适配）决定
        if compile_caps[27] == 0 {
            for &x in &tr[1..table_len] {
                w.put_uint(x as u64, 1, false, false);
            }
            w.put_byte(0);
        } else {
            for &x in &tr[1..table_len] {
                w.put_uint(x as u64, 2, true, false);
            }
            w.put_bytes(&[0, 0]);
        }
        debug!(
            "Sending DataType Negotiation (caps7={caps7}, table entries={} units, form={})",
            table_len - 1,
            if compile_caps[27] == 0 { "u8" } else { "u16" }
        );
        conn.send_writer(w).await?;

        // ── 响应 ──
        let msg = conn.get_byte().await?;
        if msg != 2 {
            return Err(Error::Protocol(format!(
                "expected DataType negotiation MsgCode 2, got {msg}"
            )));
        }

        // 时区（仅 RuntimeCap[1]==1 时服务器回传）
        if runtime_caps[1] == 1 {
            conn.ensure_in_buffer(11).await?;
            let tz = {
                let mut r = TtcReader::new(&mut conn.in_buffer);
                r.get_bytes(11)?
            };
            let h = tz[4] as i32 - 60;
            let m = tz[5] as i32 - 60;
            let _s = tz[6] as i32 - 60;
            conn.db_timezone = Some(format!("{h:+03}:{m:02}"));
            if compile_caps[37] & 2 == 2 {
                conn.ensure_in_buffer(4).await?;
                let mut r = TtcReader::new(&mut conn.in_buffer);
                let _server_tz_version = r.get_bytes(4)?;
            }
        }

        // 排空类型回执流（形态与发送侧一致），直到终止符
        let one_byte = compile_caps[27] == 0;
        let need = if one_byte { 1 } else { 2 };
        let mut level: u8 = 0;
        let mut drained = 0usize;
        loop {
            conn.ensure_in_buffer(need).await?;
            let mut r = TtcReader::new(&mut conn.in_buffer);
            let num: i64 = if one_byte {
                r.get_int64(1, false, false)?
            } else {
                r.get_int64(2, false, true)?
            };
            drained += 1;
            if num == 0 && level == 0 {
                break;
            }
            if num == 0 && level == 1 {
                level = 0;
                continue;
            }
            if level == 3 {
                level = 0;
                continue;
            }
            level += 1;
        }
        trace!("DataType ack stream drained ({drained} tokens)");

        // TTC 版本 = min(客户端 caps[7]=11, 服务器 caps[7])
        let client_ttc = compile_caps[7];
        conn.ttc_version = client_ttc.min(caps7);
        debug!(
            "DataType Negotiation complete: TTC version {}, db timezone {:?}",
            conn.ttc_version, conn.db_timezone
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 锁定构表游标（int16 单位，语义 = go-ora TypeAndRep[0]）：
    /// 表结构意外漂移（漏条/多条/形态错）时此测试失败。
    #[test]
    fn type_rep_table_cursor_anchors() {
        let (tr, rep1100, rep1200) = TypeRepBuilder::build();
        assert_eq!(rep1100, 1133, "1100 截断锚点");
        assert_eq!(rep1200, 1277, "1200 截断锚点");
        assert_eq!(tr[0], 1285, "全表终值游标");
        // 首条目四元组：(NCHAR=1, NCHAR=1, UNIVERSAL=1, 0)
        assert_eq!(&tr[1..5], &[1, 1, 1, 0]);
        // NUMBER 用 ORACLE 表示
        assert_eq!(&tr[5..9], &[2, 2, 10, 0]);
    }
}
