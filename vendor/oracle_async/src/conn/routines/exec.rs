use std::sync::Arc;
use async_trait::async_trait;
use log::{debug, error, trace};
use crate::conn::Conn;
use crate::error::{Error, OracleError, Result};
use crate::io::{TtcReader, TtcWriter};
use crate::proto::tns_types::TnsType;
use crate::queryable::row::{ColumnMeta, Row};
use super::row_common::{self, StmtType};
use super::Routine;

/// 隐式结果集项（Msg 27 / RefCursor）：列集 + 服务端游标 ID，
/// 行数据经 [3,5,0] 续取
#[derive(Debug)]
pub struct ImplicitCursor {
    pub columns: Arc<Vec<ColumnMeta>>,
    pub cursor_id: u16,
}

#[derive(Debug)]
pub struct ExecResponse {
    pub columns: Arc<Vec<ColumnMeta>>,
    pub rows: Vec<Row>,
    pub rows_affected: u64,
    pub cursor_id: u16,
    pub has_more_rows: bool,
    /// PL/SQL 匿名块的隐式结果集（dbms_sql.return_result，Msg 27）
    pub implicit: Vec<ImplicitCursor>,
    /// 出参回读值（下标与传入的 params 对齐；Input 位置为 Null）
    pub output_values: Vec<crate::queryable::OracleValue>,
}

pub struct ExecRoutine<'a> {
    pub sql: &'a str,
    pub is_select: bool,
    pub prefetch_rows: u32,
    /// 绑定参数（空 = 无绑定，走原有内联路径）
    pub params: Vec<super::bind::BindParam>,
    /// 自动提交（DML/PLSQL 时置 exeOp 的 0x100 位，go-ora autoCommit）
    pub auto_commit: bool,
}

impl<'a> ExecRoutine<'a> {
    pub fn new(sql: &'a str, is_select: bool, prefetch_rows: u32) -> Self {
        Self {
            sql,
            is_select,
            prefetch_rows,
            params: Vec::new(),
            auto_commit: false,
        }
    }

    /// 带绑定参数构造（参数个数须与 SQL 占位符一致，由调用方或
    /// bind::validate_param_count 校验）
    pub fn with_params(
        sql: &'a str,
        is_select: bool,
        prefetch_rows: u32,
        params: Vec<super::bind::BindParam>,
    ) -> Self {
        Self {
            sql,
            is_select,
            prefetch_rows,
            params,
            auto_commit: false,
        }
    }

    /// 设置自动提交（DML/PLSQL 生效）
    pub fn auto_commit(mut self, on: bool) -> Self {
        self.auto_commit = on;
        self
    }
}

#[async_trait]
impl<'a> Routine<ExecResponse> for ExecRoutine<'a> {
    async fn call(&mut self, conn: &mut Conn) -> Result<ExecResponse> {
        // 语句类型由 SQL 文本判定（go-ora NewStmt 同式；调用方的 is_select
        // 仅作日志参考，exeOp/al8i4 以判定结果为准）
        let stmt_type = row_common::detect_stmt_type(self.sql);
        let is_plsql = stmt_type == StmtType::PlSql;

        let mut writer = TtcWriter::new();
        // TTCOEXEC message code (3, 0x5E, 0)
        writer.put_bytes(&[3, 0x5E, 0]);

        // exeOp（go-ora getExeOption 位定义，真机 trace 锚定）：
        // bit0 = parse、bit3(0x8) = 有绑定参数、bit5 = execute、
        // bit8(0x100) = autoCommit（DML/PLSQL）、
        // bit10(0x400) = PLSQL/有 RETURNING 且有参数时的参数重定义标志、
        // bit15(0x8000) = 非 PLSQL 无 RETURNING、bit18(0x40000) = PLSQL。
        // 首次执行：SELECT/DML/DDL = 0x8021，PLSQL = 0x40021；
        // 带参数再加 0x8（真机：普通带参查询 0x8029），
        // PLSQL 带参数再加 0x400（真机：NLS 块为 0x40529，缺它服务器断连）。
        // 注意 0x40 是「既不 parse 也不 execute」标志，不可误置（真机 ORA-01002）。
        let has_params = !self.params.is_empty();
        let mut exe_op: u64 = if is_plsql { 0x40021 } else { 0x8021 };
        if has_params {
            exe_op |= 0x8;
            if is_plsql {
                exe_op |= 0x400;
            }
        }
        if self.auto_commit && matches!(stmt_type, StmtType::Dml | StmtType::PlSql) {
            exe_op |= 0x100;
        }
        writer.put_uint(exe_op, 4, true, true);
        writer.put_uint(0, 2, true, true); // cursorID = 0 (new cursor)
        writer.put_byte(1); // new cursor flag

        // Parse length & flag——SQL 按服务器字符集编码（852=ZHS16GBK 库上
        // 中文字面量/标识符必需；ASCII 恒无损）
        let sql_bytes = crate::proto::charset::encode(self.sql, conn.server_charset as u32);
        writer.put_uint(sql_bytes.len() as u64, 4, true, true);
        writer.put_byte(1);

        writer.put_uint(13, 2, true, true); // al8i4 size = 13
        writer.put_bytes(&[0, 0]);

        // 行数分支条件（go-ora：exeOp 无 0x40 且有 0x20|0x1 且 stmtType==SELECT）
        if stmt_type == StmtType::Select {
            writer.put_byte(0);
            writer.put_uint(self.prefetch_rows as u64, 4, true, true);
        } else {
            writer.put_bytes(&[0, 0]);
        }

        // Long fetch size（go-ora INLINE 模式 0x3FFFFFFF，真机 trace 锚定）
        writer.put_uint(0x3FFF_FFFF, 4, true, true);
        // 参数段标记（go-ora basicWrite：`if len(Pars)>0 && !define` 才写
        // 1 + 压缩个数；否则两个 0）。真机锚定：三参查询此处为 01 01 03。
        // 参数**值**在 al8i4 之后的 MsgCode 7 段写（bind::write_params）。
        if has_params {
            writer.put_byte(1);
            writer.put_uint(self.params.len() as u64, 2, true, true);
        } else {
            writer.put_bytes(&[0, 0]);
        }
        // Define flags
        writer.put_bytes(&[0, 0, 0, 0, 0]);
        writer.put_bytes(&[0, 0]);

        // TTC Version capabilities padding
        if conn.ttc_version >= 4 {
            writer.put_bytes(&[0, 0, 1]);
        }
        if conn.ttc_version >= 5 {
            writer.put_bytes(&[0, 0, 0, 0, 0]);
        }
        if conn.ttc_version >= 7 {
            writer.put_bytes(&[0, 0, 0]);
        }
        if conn.ttc_version >= 8 {
            writer.put_bytes(&[0, 0, 0, 0, 0]);
        }
        if conn.ttc_version >= 9 {
            writer.put_bytes(&[0, 0]);
        }

        // SQL text as CLR
        writer.put_clr(&sql_bytes);

        // al8i4 array (13 integers)——PLSQL 与 DML/OTHERS 均 [1]=1，
        // 仅 SELECT 走 INLINE 延迟行语义（[1]=0、[7]=1）
        let mut al8i4 = [0u64; 13];
        al8i4[0] = 1; // execute
        if stmt_type == StmtType::Select {
            // go-ora INLINE 语义：parse 轮 al8i4[1]=0（行数据延迟到 fetch/LOB 预取轮）
            al8i4[1] = 0;
            al8i4[7] = 1; // select flag
        } else {
            al8i4[1] = 1;
        }
        al8i4[9] = 0x8000; // execute 位置位时恒带（go-ora basicWrite 尾段）

        for val in al8i4 {
            writer.put_uint(val, 4, true, true);
        }

        // 绑定参数段（go-ora writePars）：参数定义 + MsgCode 7 值段，
        // 位置在 al8i4 之后（与 define 列定义体同一位置约定）
        if !self.params.is_empty() {
            super::bind::write_params(
                &mut writer,
                &self.params,
                conn.server_charset as u32,
                conn.ttc_version,
                true,
            )?;
        }

        debug!(
            "Sending TTCOEXEC (Op {exe_op:#07x}, {:?}, {} param(s)) for SQL: '{}'",
            stmt_type,
            self.params.len(),
            self.sql
        );
        conn.send_request(writer).await?;

        // Read response stream
        let mut columns: Vec<ColumnMeta> = Vec::new();
        let mut rows: Vec<Row> = Vec::new();
        let mut has_more_rows = true;
        let mut bit_vector: Vec<bool> = Vec::new();
        let mut implicit: Vec<ImplicitCursor> = Vec::new();
        // Msg 8 的前两个 int4 = 快照 SCN（LOB 预取轮的 al8i4[5]/[6] 需回放）
        let mut scn: [u64; 2] = [0; 2];
        // 出参（OUT/INOUT）回读值，下标与 params 对齐
        let mut output_values: Vec<crate::queryable::OracleValue> =
            vec![crate::queryable::OracleValue::Null; self.params.len()];

        let (cursor_id, rows_affected);
        loop {
            let msg = conn.get_byte().await?;
            trace!("Exec response MsgCode: {}", msg);
            match msg {
                16 => {
                    // 列描述（共享解析件；row_common 内为 ParameterInfo.load 移植）
                    columns = super::row_common::read_describe(conn).await?;
                    debug!("Describe returned {} columns: {:?}", columns.len(), columns.iter().map(|c| &c.name).collect::<Vec<_>>());
                    bit_vector = vec![true; columns.len()];
                }
                21 => {
                    // BitVector (indicating which columns are present in current row)
                    bit_vector = super::row_common::read_bitvector(conn, columns.len()).await?;
                }
                6 => {
                    // Resultset row chunk header：位图非空时更新（v2 语义）
                    if let Some(bv) =
                        super::row_common::read_row_header(conn, columns.len()).await?
                    {
                        bit_vector = bv;
                    }
                }
                7 => {
                    // 行数据到达。有出参（OUT/INOUT）时本消息体是「出参值区」
                    // 而非行数据（go-ora case 7 的 containOutputPars 分支）：
                    // 按序读每个非 Input 参数的 CLR，再跟一个压缩 int2。
                    if !self.params.is_empty()
                        && self
                            .params
                            .iter()
                            .any(|p| p.direction != super::bind::Direction::Input)
                    {
                        for (idx, p) in self.params.iter().enumerate() {
                            if p.direction == super::bind::Direction::Input {
                                continue;
                            }
                            let raw = conn.read_clr().await?;
                            let value = match raw {
                                Some(b) => super::row_common::decode_cell(
                                    &p.data_type.unwrap_or(crate::proto::TnsType::NChar),
                                    &b,
                                    conn.server_charset as u32,
                                ),
                                None => crate::queryable::OracleValue::Null,
                            };
                            output_values[idx] = value;
                            // 每个出参值后跟一个压缩 int2（go-ora
                            // calculateParameterValue 尾段）
                            let _ = conn.read_ci(2).await?;
                        }
                        continue;
                    }
                    // Row data row arrival
                    let cols_arc = Arc::new(columns.clone());
                    let row = super::row_common::read_row(conn, &cols_arc, &bit_vector).await?;
                    rows.push(row);
                }
                8 => {
                    // Session state / SCN / 会话属性（go-ora command.go case 8 全量：
                    // size×int4 + GetInt2 + 键值字典 + TTC>=4 的 queryID 段）
                    let size = conn.read_ci(2).await? as usize;
                    for (x, _) in (0..size).enumerate() {
                        let v = conn.read_ci(4).await? as u64;
                        if let Some(slot) = scn.get_mut(x) {
                            *slot = v; // 快照 SCN（LOB 预取轮回放）
                        }
                    }
                    let _ = conn.read_ci(2).await?;
                    let kv_count = conn.read_ci(2).await? as usize;
                    for _ in 0..kv_count {
                        conn.ensure_in_buffer(1).await?;
                        let _ = conn.read_dlc().await?; // key
                        conn.ensure_in_buffer(1).await?;
                        let _ = conn.read_dlc().await?; // value
                        let _ = conn.read_ci(4).await?; // flag/num
                    }
                    if conn.ttc_version >= 4 {
                        let qid_len = conn.read_ci(4).await? as usize;
                        if qid_len > 0 {
                            conn.ensure_in_buffer(qid_len).await?;
                            let mut r = TtcReader::new(&mut conn.in_buffer);
                            let _ = r.get_bytes(qid_len)?; // queryID（弃）
                        }
                    }
                }
                27 => {
                    // 隐式结果集（go-ora case 27 + RefCursor.load）：
                    // count + N 个内嵌游标描述（列集 + 服务端游标 ID）
                    let count = conn.read_ci(4).await? as usize;
                    debug!("Implicit result sets: {count}");
                    for _ in 0..count {
                        let (cols, cid) = row_common::read_ref_cursor(conn).await?;
                        implicit.push(ImplicitCursor {
                            columns: cols,
                            cursor_id: cid,
                        });
                    }
                }
                15 => {
                    // 服务端 Warning（go-ora case 15 + NewWarningObject）
                    row_common::read_warning(conn).await?;
                }
                19 => {
                    // 服务端流控信号（v2 case 19 全语义）：先清输入残留
                    //（ResetBuffer），回写单字节 19 后继续读——服务端会重开
                    // 干净的响应流。原实现把它并入 case 11 的绑定方向载荷一起
                    // 解析，读走不存在的字段导致流错位——真机上长 SQL /
                    // 含中文语句的响应流会以「invalid int size」类解码错误暴露
                    conn.reset_read_buffer();
                    let mut w = TtcWriter::new();
                    w.put_bytes(&[19]);
                    conn.send_writer(w).await?;
                    continue;
                }
                11 => {
                    // 绑定方向（v2 case 11 = ResultSet.load 头 + 每列方向字节）：
                    // 跳 1 + i2 列数低段 + i4 列数高段（×0x100 组合，v2 原式）
                    // + i4 行数 + i2 UAC + DLC + DLC
                    conn.ensure_in_buffer(1).await?;
                    let mut r = TtcReader::new(&mut conn.in_buffer);
                    let _ = r.get_byte()?;
                    let n1 = r.get_int(2, true, true)? as i64;
                    let n2 = r.get_int(4, true, true)? as i64;
                    let _ = r.get_int(4, true, true)?;
                    let _ = r.get_int(2, true, true)?;
                    let _ = r.get_dlc()?;
                    let _ = r.get_dlc()?;
                    let col_count = (n1 + n2 * 0x100) as usize;
                    for _ in 0..col_count {
                        conn.ensure_in_buffer(1).await?;
                        let mut r = TtcReader::new(&mut conn.in_buffer);
                        let _dir = r.get_byte()?;
                    }
                }
                4 => {
                    // Summary object (Command Complete)
                    let s = super::summary::read_summary(conn).await?;
                    cursor_id = s.cursor_id;
                    rows_affected = s.cur_row_number as u64;

                    if s.ret_code == 1403 {
                        // ORA-01403: no data found (end of rows)
                        // ORA-01403 = 游标取尽（正常 EOF，非错误）：本轮行数据
                        // 已收，后续 next_row 走 [3,5,0] 续取或结束
                        // 逐游标日志（每条查询取尽都打）：DEBUG 下太吵，降 TRACE
                        trace!("Cursor exhausted (ORA-01403 normal EOF)");
                        has_more_rows = false;
                    } else if s.ret_code != 0 {
                        let msg_str =
                            String::from_utf8_lossy(&s.error_message.unwrap_or_default()).to_string();
                        error!("SQL execution failed with ORA-{:05}: {}", s.ret_code, msg_str);
                        return Err(Error::Server(OracleError {
                            code: s.ret_code,
                            message: msg_str,
                        }));
                    } else {
                        debug!(
                            "Execution succeeded. CursorID: {}, Affected: {}, Fetched rows: {}",
                            cursor_id, rows_affected, rows.len()
                        );
                    }
                    break;
                }
                9 => {
                    // EndOfCall：消费 EOS/FSAP 尾随字段。可能是上一语句的
                    // 残留（本轮已见 4 时 4 已 break，这里只会是残留）——
                    // 消费后继续等本语句真正的 4
                    super::summary::read_end_of_call(conn).await?;
                }
                other => {
                    trace!("Skipping exec response message code: {other}");
                }
            }
        }

        // ── LOB 内联预取第二轮（go-ora queryLobPrefetch）──
        // 含 LOB 列的 SELECT：轮1（define=false）不带行数据，需以 exeOp=0x8050
        // （不 parse 不 execute + define）重发，LOB 列改写为 LONG 形态后行数据
        // 以分块 CLR 内联返回。真机 11g 实测（TO_CLOB/GET_DDL）。
        if self.is_select
            && columns
                .iter()
                .any(|c| matches!(c.data_type, TnsType::Clob | TnsType::Blob | TnsType::BFile))
        {
            // 预取行数（go-ora 同式，用改写前类型）：0x20000 / Σ(LOB→86, LONG→2, 其余 MaxLen) + 1
            let max_row_size: usize = columns
                .iter()
                .map(|c| match c.data_type {
                    TnsType::Clob | TnsType::Blob | TnsType::BFile => 86,
                    TnsType::Long | TnsType::LongRaw | TnsType::LongVarChar => 2,
                    _ => c.max_len.max(1),
                })
                .sum();
            let fetch_count = (0x20000usize / max_row_size.max(1)) + 1;

            // 列改写（go-ora writeDefine）：CLOB→LongVarChar、BLOB/BFILE→LongRaw
            for c in &mut columns {
                match c.data_type {
                    TnsType::Clob => {
                        c.data_type = TnsType::LongVarChar;
                        c.max_len = 0x3FFF_FFFF;
                    }
                    TnsType::Blob | TnsType::BFile => {
                        c.data_type = TnsType::LongRaw;
                        c.max_len = 0x3FFF_FFFF;
                    }
                    _ => {
                        c.max_len = 0x7FFF_FFFF;
                    }
                }
            }

            let mut w = TtcWriter::with_capacity(256);
            w.put_bytes(&[3, 0x5E, 0]);
            w.put_uint(0x8050, 4, true, true); // !parse !execute + define + 0x8000
            w.put_uint(cursor_id as u64, 2, true, true);
            w.put_byte(0); // 复用游标
            w.put_bytes(&[0, 1]); // parse=false
            w.put_uint(13, 2, true, true);
            w.put_bytes(&[0, 0]);
            w.put_bytes(&[0, 0]); // 0x8050 含 0x40 → 无行数分支
            w.put_uint(0x3FFF_FFFF, 4, true, true); // long fetch（INLINE）
            w.put_bytes(&[0, 0]); // 无参数
            w.put_bytes(&[0, 0, 0, 0, 0]);
            // define 标记 + 列数（列定义体在 al8i4 之后——go-ora basicWrite 尾段）
            w.put_byte(1);
            w.put_uint(columns.len() as u64, 2, true, true);
            if conn.ttc_version >= 4 {
                w.put_bytes(&[0, 0, 1]);
            }
            if conn.ttc_version >= 5 {
                w.put_bytes(&[0, 0, 0, 0, 0]);
            }
            if conn.ttc_version >= 7 {
                w.put_bytes(&[0, 0, 0]);
            }
            if conn.ttc_version >= 8 {
                w.put_bytes(&[0, 0, 0, 0, 0]);
            }
            if conn.ttc_version >= 9 {
                w.put_bytes(&[0, 0]);
            }
            // al8i4：[1]=预取行数、[5]/[6]=轮1 SCN 回放、[7]=select
            let al8i4 = [
                0u64,
                fetch_count as u64,
                0,
                0,
                0,
                scn[0],
                scn[1],
                1,
                0,
                0,
                0,
                0,
                0,
            ];
            for v in al8i4 {
                w.put_uint(v, 4, true, true);
            }
            // define 列定义体（ParameterInfo.write）
            for c in &columns {
                // type, flag=3, prec=0, scale=0, maxlen, mnoae=0, cont=0,
                // toid=0, version=0, charsetId, charsetForm, maxcharlen=0
                w.put_byte(u8::from(c.data_type));
                w.put_byte(3);
                w.put_byte(0);
                w.put_byte(0);
                w.put_uint(c.max_len as u64, 4, true, true);
                w.put_uint(0, 4, true, true);
                w.put_uint(0, 4, true, true);
                w.put_byte(0); // ToID null
                w.put_uint(0, 2, true, true); // version
                w.put_uint(c.charset_id as u64, 2, true, true);
                w.put_byte(c.charset_form);
                w.put_uint(0, 4, true, true); // maxCharLen
            }

            debug!(
                "LOB prefetch round-2: cursor={cursor_id}, {} define col(s), fetch={fetch_count}",
                columns.len()
            );
            conn.send_writer(w).await?;

            // 第二轮响应：行数据（LOB 已是 LONG 形态的内联 CLR）直至 Summary
            rows.clear();
            has_more_rows = true;
            loop {
                let msg = conn.get_byte().await?;
                trace!("LOB prefetch MsgCode: {}", msg);
                match msg {
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
                        let cols_arc = Arc::new(columns.clone());
                        let row =
                            super::row_common::read_row(conn, &cols_arc, &bit_vector).await?;
                        rows.push(row);
                    }
                    8 => {
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
                                let mut r = TtcReader::new(&mut conn.in_buffer);
                                let _ = r.get_bytes(qid_len)?;
                            }
                        }
                    }
                    4 => {
                        let s = super::summary::read_summary(conn).await?;
                        if s.ret_code == 1403 {
                            has_more_rows = false;
                            conn.close_cursor(s.cursor_id).await?;
                        } else if s.ret_code != 0 {
                            let msg_str = String::from_utf8_lossy(
                                &s.error_message.unwrap_or_default(),
                            )
                            .to_string();
                            return Err(Error::Server(OracleError {
                                code: s.ret_code,
                                message: msg_str,
                            }));
                        }
                        break;
                    }
                    9 => {
                        super::summary::read_end_of_call(conn).await?;
                    }
                    other => {
                        trace!("Skipping LOB prefetch message code: {other}");
                    }
                }
            }
            debug!("LOB prefetch complete: {} row(s)", rows.len());
        }

        Ok(ExecResponse {
            columns: Arc::new(columns),
            rows,
            rows_affected,
            cursor_id,
            has_more_rows,
            implicit,
            output_values,
        })
    }
}
