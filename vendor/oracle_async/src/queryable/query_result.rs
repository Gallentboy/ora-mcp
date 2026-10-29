use std::collections::VecDeque;
use std::sync::Arc;
use log::debug;
use crate::conn::routines::{fetch::FetchRoutine, Routine};
use crate::conn::Conn;
use crate::error::Result;
use super::row::{ColumnMeta, Row};

pub struct QueryResult<'a> {
    pub(crate) conn: &'a mut Conn,
    pub(crate) columns: Arc<Vec<ColumnMeta>>,
    pub(crate) rows_buffer: VecDeque<Row>,
    pub(crate) cursor_id: u16,
    pub(crate) rows_affected: u64,
    pub(crate) has_more_rows: bool,
    pub(crate) prefetch_count: u32,
    /// 待接续的隐式结果集（Msg 27）：主游标取尽后逐个链入（PLSQL 匿名块
    /// 的 dbms_sql.return_result / 多结果集）
    pub(crate) implicit: VecDeque<(Arc<Vec<ColumnMeta>>, u16)>,
}

impl<'a> QueryResult<'a> {
    pub fn new(
        conn: &'a mut Conn,
        columns: Arc<Vec<ColumnMeta>>,
        initial_rows: Vec<Row>,
        cursor_id: u16,
        rows_affected: u64,
        has_more_rows: bool,
    ) -> Self {
        Self {
            conn,
            columns,
            rows_buffer: VecDeque::from(initial_rows),
            cursor_id,
            rows_affected,
            has_more_rows,
            prefetch_count: 100,
            implicit: VecDeque::new(),
        }
    }

    pub fn columns(&self) -> &[ColumnMeta] {
        &self.columns
    }

    pub fn rows_affected(&self) -> u64 {
        self.rows_affected
    }

    pub fn cursor_id(&self) -> u16 {
        self.cursor_id
    }

    /// Abort query execution by sending a TNS Break Marker packet.
    pub async fn break_connection(&mut self) -> Result<()> {
        self.conn.break_connection().await
    }

    /// 关闭服务端游标（go-ora v2 `defaultStmt.Close()` 的 1:1 对应：判
    /// cursorID != 0 即发关游标包；0x11/0x69 头 + 4 字节 cursorID +
    /// simpleObject 0x93）。幂等——关完把 cursor_id 置 0。
    /// 工作台每语句用完即调（含提前放弃：行数上限/取消/出错），
    /// 否则服务端游标泄漏累积到 open_cursors 上限即 ORA-01000。
    pub async fn close(&mut self) -> Result<()> {
        // 隐式结果集同样要关（go-ora 在主游标 Close 时逐个处理）
        while let Some((_, cid)) = self.implicit.pop_front() {
            let _ = self.conn.close_cursor(cid).await;
        }
        if self.cursor_id != 0 {
            let cid = self.cursor_id;
            self.cursor_id = 0;
            self.has_more_rows = false;
            self.conn.close_cursor(cid).await?;
        }
        Ok(())
    }

    /// Fetch next row asynchronously. Automatically executes a fetch routine if the buffer is empty
    /// and the server cursor has more rows; 主游标取尽后自动链入下一个隐式结果集（Msg 27）。
    pub async fn next_row(&mut self) -> Result<Option<Row>> {
        loop {
            if let Some(row) = self.rows_buffer.pop_front() {
                return Ok(Some(row));
            }

            if self.has_more_rows && self.cursor_id != 0 {
                // Fetch next batch from Oracle
                let mut routine =
                    FetchRoutine::new(self.cursor_id, self.columns.clone(), self.prefetch_count);
                let resp = routine.call(self.conn).await?;

                self.has_more_rows = resp.has_more_rows;
                // exec 未内联返回列时，首个 fetch 才带 describe——更新列集供后续分批复用
                if let Some(cols) = resp.columns {
                    self.columns = cols;
                }
                self.rows_buffer = VecDeque::from(resp.rows);

                if let Some(row) = self.rows_buffer.pop_front() {
                    return Ok(Some(row));
                }
            }

            // 主游标结束：链入下一个隐式结果集（列集换新、游标 ID 换新）
            match self.implicit.pop_front() {
                Some((cols, cid)) => {
                    debug!("switching to implicit result set (cursor {cid})");
                    self.columns = cols;
                    self.cursor_id = cid;
                    self.has_more_rows = true;
                    continue;
                }
                None => return Ok(None),
            }
        }
    }

    /// Collect all remaining rows into a vector（取尽后按 go-ora 语义关游标）
    pub async fn collect(mut self) -> Result<Vec<Row>> {
        let mut rows = Vec::new();
        let result = async {
            while let Some(row) = self.next_row().await? {
                rows.push(row);
            }
            Ok(rows)
        }
        .await;
        // 成功与失败都关（go-ora Connection.QueryContext/ExecContext 的
        // `stmt.Close()` 收尾语义）；关闭失败不覆盖取行错误
        let _ = self.close().await;
        result
    }
}
