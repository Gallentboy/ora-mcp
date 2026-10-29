pub mod values;
pub mod row;
pub mod query_result;

pub use values::{FromValue, OracleValue};
pub use row::{ColumnMeta, Row};
pub use query_result::QueryResult;

use async_trait::async_trait;
use crate::conn::routines::{exec::ExecRoutine, Routine};
use crate::conn::Conn;
use crate::error::Result;

#[async_trait]
pub trait Queryable {
    async fn query<'a>(&'a mut self, query: &str) -> Result<QueryResult<'a>>;

    async fn exec(&mut self, query: &str) -> Result<u64>;

    /// 带绑定参数查询（`:1` / `:name` 占位符，按序绑定）
    async fn query_with_params<'a>(
        &'a mut self,
        query: &str,
        params: Vec<crate::conn::routines::bind::BindParam>,
    ) -> Result<QueryResult<'a>>;

    /// 带绑定参数执行（DML/DDL/PLSQL）
    async fn exec_with_params(
        &mut self,
        query: &str,
        params: Vec<crate::conn::routines::bind::BindParam>,
    ) -> Result<u64>;

    async fn query_first<'a>(&'a mut self, query: &str) -> Result<Option<Row>> {
        let mut res = self.query(query).await?;
        res.next_row().await
    }
}

#[async_trait]
impl Queryable for Conn {
    async fn query<'a>(&'a mut self, query: &str) -> Result<QueryResult<'a>> {
        let mut routine = ExecRoutine::new(query, true, 100);
        let resp = routine.call(self).await?;
        let mut qr = QueryResult::new(
            self,
            resp.columns,
            resp.rows,
            resp.cursor_id,
            resp.rows_affected,
            resp.has_more_rows,
        );
        // 隐式结果集（Msg 27）排队待链：主游标取尽后逐个接续
        qr.implicit = resp
            .implicit
            .into_iter()
            .map(|ic| (ic.columns, ic.cursor_id))
            .collect();
        Ok(qr)
    }

    async fn exec(&mut self, query: &str) -> Result<u64> {
        let mut routine = ExecRoutine::new(query, false, 0);
        let resp = routine.call(self).await?;
        // 非 query 路径的隐式游标无人消费：立即关闭（防下条语句 ORA-01002）
        for ic in &resp.implicit {
            let _ = self.close_cursor(ic.cursor_id).await;
        }
        Ok(resp.rows_affected)
    }

    async fn query_with_params<'a>(
        &'a mut self,
        query: &str,
        params: Vec<crate::conn::routines::bind::BindParam>,
    ) -> Result<QueryResult<'a>> {
        // 占位符个数校验：错位比报错更危险（值会绑到错误的列上）
        crate::conn::routines::bind::validate_param_count(query, &params)?;
        let mut routine = ExecRoutine::with_params(query, true, 100, params);
        let resp = routine.call(self).await?;
        let mut qr = QueryResult::new(
            self,
            resp.columns,
            resp.rows,
            resp.cursor_id,
            resp.rows_affected,
            resp.has_more_rows,
        );
        qr.implicit = resp
            .implicit
            .into_iter()
            .map(|ic| (ic.columns, ic.cursor_id))
            .collect();
        Ok(qr)
    }

    async fn exec_with_params(
        &mut self,
        query: &str,
        params: Vec<crate::conn::routines::bind::BindParam>,
    ) -> Result<u64> {
        crate::conn::routines::bind::validate_param_count(query, &params)?;
        let mut routine = ExecRoutine::with_params(query, false, 0, params);
        let resp = routine.call(self).await?;
        for ic in &resp.implicit {
            let _ = self.close_cursor(ic.cursor_id).await;
        }
        Ok(resp.rows_affected)
    }
}
