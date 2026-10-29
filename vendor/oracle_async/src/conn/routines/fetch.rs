//! 游标续取（MsgCode [3,5,0] 专用短包 + cursorID + 行数）。
//! exeOp=0x8021 下服务器会把 describe+行数据推迟到首个 fetch 包返回
//! （真机 11g 实测），故本循环必须与 exec 同构（16/6/7/21/8/4/9 全量处理），
//! 且 describe 到来时更新列集。

use std::sync::Arc;
use async_trait::async_trait;
use log::{debug, error, trace};
use crate::conn::Conn;
use crate::error::{Error, OracleError, Result};
use crate::io::TtcWriter;
use crate::queryable::row::{ColumnMeta, Row};
use super::Routine;

#[derive(Debug)]
pub struct FetchResponse {
    pub rows: Vec<Row>,
    pub has_more_rows: bool,
    /// fetch 途中收到 describe（exec 未内联返回列时的首个 fetch）时的列集
    pub columns: Option<Arc<Vec<ColumnMeta>>>,
}

pub struct FetchRoutine {
    pub cursor_id: u16,
    pub columns: Arc<Vec<ColumnMeta>>,
    pub count: u32,
}

impl FetchRoutine {
    pub fn new(cursor_id: u16, columns: Arc<Vec<ColumnMeta>>, count: u32) -> Self {
        Self {
            cursor_id,
            columns,
            count,
        }
    }
}

#[async_trait]
impl Routine<FetchResponse> for FetchRoutine {
    async fn call(&mut self, conn: &mut Conn) -> Result<FetchResponse> {
        // go-ora _fetch 的专用短包（非 TTCOEXEC）：[3, 5, 0] + cursorID + 行数。
        // 重发 0x5E 形态会报 ORA-01002（fetch out of sequence，真机实测）。
        let mut writer = TtcWriter::new();
        writer.put_bytes(&[3, 5, 0]);
        writer.put_uint(self.cursor_id as u64, 2, true, true);
        writer.put_uint(self.count as u64, 2, true, true);

        debug!("Sending Fetch for cursor {} (count: {})", self.cursor_id, self.count);
        conn.send_request(writer).await?;

        let mut rows: Vec<Row> = Vec::new();
        let mut has_more_rows = true;
        let mut bit_vector: Vec<bool> = Vec::new();
        let mut described: Option<Arc<Vec<ColumnMeta>>> = None;
        let mut columns = self.columns.clone();

        loop {
            let msg = conn.get_byte().await?;
            trace!("Fetch response MsgCode: {}", msg);
            match msg {
                16 => {
                    // describe：exec 未内联返回列时在首个 fetch 到来
                    let new_cols = Arc::new(super::row_common::read_describe(conn).await?);
                    debug!(
                        "Fetch describe: {} columns: {:?}",
                        new_cols.len(),
                        new_cols.iter().map(|c| &c.name).collect::<Vec<_>>()
                    );
                    bit_vector = vec![true; new_cols.len()];
                    described = Some(new_cols.clone());
                    columns = new_cols;
                }
                6 => {
                    // 位图非空时更新（v2 语义）
                    if let Some(bv) =
                        super::row_common::read_row_header(conn, columns.len()).await?
                    {
                        bit_vector = bv;
                    }
                }
                21 => {
                    bit_vector = super::row_common::read_bitvector(conn, columns.len()).await?;
                }
                7 => {
                    let row = super::row_common::read_row(conn, &columns, &bit_vector).await?;
                    rows.push(row);
                }
                8 => {
                    // 会话状态（与 exec 同构的全量尾段）
                    let size = conn.read_ci(2).await? as usize;
                    for _ in 0..size {
                        let _ = conn.read_ci(4).await?;
                    }
                    let _ = conn.read_ci(2).await?;
                    let kv_count = conn.read_ci(2).await? as usize;
                    for _ in 0..kv_count {
                        let _ = conn.read_dlc().await?;
                        let _ = conn.read_dlc().await?;
                        let _ = conn.read_ci(4).await?;
                    }
                    if conn.ttc_version >= 4 {
                        let qid_len = conn.read_ci(4).await? as usize;
                        if qid_len > 0 {
                            conn.ensure_in_buffer(qid_len).await?;
                            let mut r = crate::io::TtcReader::new(&mut conn.in_buffer);
                            let _ = r.get_bytes(qid_len)?;
                        }
                    }
                }
                4 => {
                    // Summary
                    let s = super::summary::read_summary(conn).await?;
                    if s.ret_code == 1403 {
                        debug!("Fetch completed (cursor reached end of data)");
                        has_more_rows = false;
                        // 游标取尽即关（不关则下一条语句被 ORA-01002 拒）
                        conn.close_cursor(self.cursor_id).await?;
                    } else if s.ret_code != 0 {
                        let err_str =
                            String::from_utf8_lossy(&s.error_message.unwrap_or_default()).to_string();
                        error!("Fetch failed with ORA-{:05}: {}", s.ret_code, err_str);
                        return Err(Error::Server(OracleError {
                            code: s.ret_code,
                            message: err_str,
                        }));
                    }
                    break;
                }
                9 => {
                    // EndOfCall：消费尾随字段后继续等真正的 4（可能是上一语句残留）
                    super::summary::read_end_of_call(conn).await?;
                }
                19 => {
                    // 服务端流控信号（v2 case 19 全语义）：清残留、回写 19、
                    // 继续读——不能落到 other 的静默跳过（不回 ACK 流就错位）
                    conn.reset_read_buffer();
                    let mut w = TtcWriter::new();
                    w.put_bytes(&[19]);
                    conn.send_writer(w).await?;
                    continue;
                }
                other => {
                    trace!("Skipping fetch response message code: {other}");
                }
            }
        }

        Ok(FetchResponse {
            rows,
            has_more_rows,
            columns: described,
        })
    }
}
