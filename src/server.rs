//! MCP 工具层：8 个工具 + ServerHandler 装配。
//!
//! 工具面（对齐原 Oracle SQLcl MCP 的核心子集，砍掉 Liquibase/AWR/APEX/agents/skills）：
//! - 连接：connections_list / connect / disconnect
//! - 查询：query（只读守卫）
//! - 执行：execute_sql（DDL/DML/PLSQL，程序单元编译后查 USER_ERRORS）
//! - 元数据：list_objects / get_ddl（DBMS_METADATA）
//! - 诊断：explain_plan（EXPLAIN PLAN + DBMS_XPLAN）

use rmcp::{
    ErrorData as McpError,
    handler::server::wrapper::Parameters,
    model::CallToolResult,
    schemars,
    tool, tool_handler, tool_router,
};
use serde::Deserialize;
use serde_json::json;

use crate::config::ConnectionDef;
use crate::db::ExecOutcome;
use crate::error::DbError;
use crate::state::AppState;

/// 本服务器支持的对象类型（需求范围：表/视图/存储过程/函数/序列）。
const OBJECT_TYPES: [&str; 5] = ["TABLE", "VIEW", "PROCEDURE", "FUNCTION", "SEQUENCE"];

pub struct OraMcp {
    state: AppState,
}

#[tool_router]
impl OraMcp {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    // ------------------------------------------------------------------
    // 连接管理
    // ------------------------------------------------------------------

    /// List the saved named database connections defined in the server config.
    /// Optionally filter by a case-insensitive substring of the connection name.
    /// Passwords are never returned.
    #[tool(description = "List the saved named database connections. Use this tool when the connection name is not already known.")]
    async fn connections_list(
        &self,
        Parameters(args): Parameters<ConnectionsListArgs>,
    ) -> Result<CallToolResult, McpError> {
        let items = self.state.list_connections(args.name.as_deref());
        Ok(text_result(json!({
            "count": items.len(),
            "connections": items,
        })))
    }

    /// Register a new named connection at runtime and persist it to the config file,
    /// then connect to it immediately. Use when the user provides a connection string
    /// (e.g. `hr/hr@dbhost.example.com:1521/ORCLPDB1` or `user/password@host:port/service`).
    /// Derive a short kebab-case name from host/service if the user did not give one.
    /// Duplicates are REJECTED: an error is returned if the name already exists, or if
    /// another connection already targets the same user/host/port/service — call
    /// `connections_list` first and reuse existing connections via `connect`.
    /// The password is stored locally in plaintext in the config file.
    /// If the database is unreachable the connection is still saved — report the
    /// `connect_error` to the user and suggest retrying `connect` later.
    #[tool(description = "Register and save a new database connection (user/password/dsn), then connect to it. Use when the user provides a connection string like hr/hr@host:1521/service. Duplicates are rejected: same name, or same user/host/port/service under another name, both error out — call connections_list first and reuse via `connect`.")]
    async fn add_connection(
        &self,
        Parameters(args): Parameters<AddConnectionArgs>,
    ) -> Result<CallToolResult, McpError> {
        let name = args.connection_name.trim().to_string();
        if name.is_empty() {
            return Err(McpError::invalid_params("connection_name must not be empty", None));
        }
        crate::db::validate_dsn(&args.dsn).map_err(DbError::into_mcp)?;

        let def = ConnectionDef {
            user: args.user.trim().to_string(),
            password: Some(args.password.clone()),
            dsn: args.dsn.trim().to_string(),
        };
        // 同名 / 同目标重复在锁内原子拒绝；返回的错误消息面向 LLM 可自解释
        let outcome = self
            .state
            .try_add_connection(&name, def.clone())
            .map_err(|msg| McpError::invalid_params(msg, None))?;
        let (saved, saved_to, save_error) = (
            outcome.saved,
            outcome.saved_to.map(|p| p.display().to_string()),
            outcome.save_error,
        );
        tracing::info!(
            "add_connection: {name} as {} @ {} (saved={saved})",
            def.user,
            def.dsn
        );

        // 立即连接验证；失败不回滚——连接已登记，库恢复后可重试 connect
        match crate::db::Db::connect(&def.user, args.password.as_str(), &def.dsn).await {
            Ok((db, banner)) => {
                let info = db.session_info().await.map_err(DbError::into_mcp)?;
                self.state.set_session(&name, db, banner.clone()).await;
                Ok(text_result(json!({
                    "saved": saved,
                    "saved_to": saved_to,
                    "save_error": save_error,
                    "connected": true,
                    "connection_name": name,
                    "user": info.username,
                    "schema": info.schema,
                    "database": info.database,
                    "dsn": def.dsn,
                    "database_banner": banner,
                })))
            }
            Err(e) => {
                tracing::warn!("add_connection `{name}` connect check failed: {e}");
                Ok(text_result(json!({
                    "saved": saved,
                    "saved_to": saved_to,
                    "save_error": save_error,
                    "connected": false,
                    "connect_error": e.to_string(),
                    "note": "connection registered; the database is unreachable right now — retry `connect` later",
                })))
            }
        }
    }

    /// Connect to a database using a saved named connection.
    /// On success returns the session context including the database banner/version,
    /// which should be used to write version-compatible SQL.
    #[tool(description = "Connect to a saved named Oracle database connection. Call this tool before any database query.")]
    async fn connect(
        &self,
        Parameters(args): Parameters<ConnectArgs>,
    ) -> Result<CallToolResult, McpError> {
        // 幂等复用检查：如果当前会话已经是该连接，且池测活（ping）健康，直接复用，不重建连接池
        if let Some((banner, info)) = self.state.check_reusable_session(&args.connection_name).await {
            tracing::info!(
                "connect: reusing active session for `{}` (pool healthy)",
                args.connection_name
            );
            return Ok(text_result(json!({
                "connected": true,
                "connection_name": args.connection_name,
                "reused_existing_session": true,
                "user": info.username,
                "schema": info.schema,
                "database": info.database,
                "database_banner": banner,
            })));
        }

        let (_, def) = self.state.get_connection(&args.connection_name).ok_or_else(|| {
            McpError::invalid_params(
                format!(
                    "connection `{}` not found; call `connections_list` to see available ones",
                    args.connection_name
                ),
                None,
            )
        })?;
        let password = def.effective_password(&args.connection_name).ok_or_else(|| {
            McpError::invalid_params(
                format!(
                    "no password for connection `{}`: set `password` in the config file \
                     or the ORA_MCP_PASSWORD_{} (or legacy SQLCL_MCP_PASSWORD_{}) environment variable",
                    args.connection_name,
                    env_suffix(&args.connection_name),
                    env_suffix(&args.connection_name)
                ),
                None,
            )
        })?;

        tracing::info!(
            "connect: {} as {} @ {}",
            args.connection_name,
            def.user,
            def.dsn
        );
        let (db, banner) = crate::db::Db::connect(&def.user, &password, &def.dsn)
            .await
            .map_err(DbError::into_mcp)?;
        let info = db.session_info().await.map_err(DbError::into_mcp)?;
        self.state.set_session(&args.connection_name, db, banner.clone()).await;

        Ok(text_result(json!({
            "connected": true,
            "connection_name": args.connection_name,
            "user": info.username,
            "schema": info.schema,
            "database": info.database,
            "dsn": def.dsn,
            "database_banner": banner,
        })))
    }

    /// Disconnect the current database session. Safe to call when already disconnected.
    #[tool(description = "Disconnect the current database session.")]
    async fn disconnect(
        &self,
        Parameters(_): Parameters<DisconnectArgs>,
    ) -> Result<CallToolResult, McpError> {
        match self.state.take_session().await {
            Some(session) => {
                let name = session.name.clone();
                let since = session.connected_at;
                session.db.close();
                tracing::info!("disconnect: {name}");
                Ok(text_result(json!({
                    "disconnected": true,
                    "connection_name": name,
                    "connected_since": since.to_rfc3339(),
                })))
            }
            None => Ok(text_result(
                json!({ "disconnected": false, "note": "no active session" }),
            )),
        }
    }

    /// Query connection and pool statistics for the active database session or a specified connection name.
    /// Returns local pool metrics (max_size, allocated, idle available, in-use, waiting)
    /// and Oracle server-side session metrics (current user sessions, active sessions, total sessions).
    #[tool(description = "Query connection pool and server session statistics (idle, in-use, waiting, total server sessions).")]
    async fn connection_stats(
        &self,
        Parameters(args): Parameters<ConnectionStatsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let requested_name = args.connection_name.as_deref();

        // 尝试获取当前活跃会话
        let session = self.state.session().await.ok();

        if let Some(session) = &session {
            if requested_name.is_none() || requested_name == Some(session.name()) {
                let pool_stats = session.db().pool_stats();
                let user_name = session.db().session_info().await.map(|i| i.username).unwrap_or_default();
                let server_stats = session.db().server_stats(&user_name).await;

                return Ok(text_result(json!({
                    "connection_name": session.name(),
                    "is_active_session": true,
                    "pool": pool_stats,
                    "server_sessions": server_stats,
                })));
            }
        }

        // 如果没有活跃会话，或者请求了非活跃的已存连接
        if let Some(name) = requested_name {
            if let Some((_, def)) = self.state.get_connection(name) {
                return Ok(text_result(json!({
                    "connection_name": name,
                    "is_active_session": false,
                    "dsn": def.dsn,
                    "user": def.user,
                    "note": "Connection is registered in config but not currently active. Call `connect` first to inspect pool metrics.",
                })));
            } else {
                return Err(McpError::invalid_params(
                    format!("connection `{name}` not found in saved connections"),
                    None,
                ));
            }
        }

        Err(DbError::NotConnected.into_mcp())
    }

    // ------------------------------------------------------------------
    // 查询 / 执行
    // ------------------------------------------------------------------

    /// Execute a read-only SQL statement (SELECT or WITH).
    /// Returns columns, rows as JSON values, and a truncated flag.
    /// The result is capped at max_rows rows; narrow the query when truncated.
    #[tool(description = "Execute a read-only SQL query (SELECT / WITH) and return rows. DDL, DML and PLSQL must use `execute_sql`.")]
    async fn query(
        &self,
        Parameters(args): Parameters<QueryArgs>,
    ) -> Result<CallToolResult, McpError> {
        let max_rows = args.effective_max_rows();
        let session = self.state.session().await.map_err(DbError::into_mcp)?;
        tracing::info!("query ({}): {}", session.name(), OneLine(&args.sql, 120));
        let result = session
            .db()
            .query(&args.sql, max_rows)
            .await
            .map_err(DbError::into_mcp)?;
        Ok(query_result_json(&result))
    }

    /// Execute a write statement: DDL (CREATE/ALTER/DROP), DML (INSERT/UPDATE/DELETE/MERGE)
    /// or an anonymous PLSQL block (BEGIN...END;). Successful DML and PLSQL blocks are
    /// committed automatically. For stored program units (procedure/function/package/
    /// trigger/view) compiler errors from USER_ERRORS are reported. DBMS_OUTPUT is not
    /// captured.
    #[tool(description = "Execute DDL, DML, or an anonymous PLSQL block against the connected database (auto-committed on success; compiler errors reported). Read-only queries must use `query`.")]
    async fn execute_sql(
        &self,
        Parameters(args): Parameters<ExecuteSqlArgs>,
    ) -> Result<CallToolResult, McpError> {
        let session = self.state.session().await.map_err(DbError::into_mcp)?;
        tracing::info!(
            "execute_sql ({}): {}",
            session.name(),
            OneLine(&args.sql, 120)
        );
        let outcome = session
            .db()
            .execute(&args.sql)
            .await
            .map_err(DbError::into_mcp)?;
        Ok(text_result(match outcome {
            ExecOutcome::DdlOk => json!({ "status": "ok", "kind": "ddl" }),
            ExecOutcome::RowsAffected { count } => {
                json!({ "status": "ok", "kind": "dml", "rows_affected": count, "committed": true })
            }
            ExecOutcome::Plsql { dbms_output } => {
                json!({ "status": "ok", "kind": "plsql", "dbms_output": dbms_output, "committed": true })
            }
        }))
    }

    /// Execute an entire SQL script file (equivalent to CLI `@file.sql`).
    /// Automatically splits statements by `;` and `/` (for PL/SQL blocks and procedures),
    /// commits each statement on success, and supports both UTF-8 and GBK/GB18030 encodings.
    #[tool(description = "Execute an entire SQL script file (equivalent to CLI `@file.sql`). Automatically handles statement boundaries, PL/SQL blocks, commits, and reports execution details.")]
    async fn execute_sql_file(
        &self,
        Parameters(args): Parameters<ExecuteSqlFileArgs>,
    ) -> Result<CallToolResult, McpError> {
        let path = std::path::Path::new(&args.file_path);
        if !path.is_file() {
            return Err(McpError::invalid_params(
                format!("SQL file not found or not a regular file: {}", args.file_path),
                None,
            ));
        }

        let bytes = std::fs::read(path).map_err(|e| {
            McpError::invalid_params(format!("failed to read file {}: {e}", args.file_path), None)
        })?;

        // 优先尝试 UTF-8 解码；若包含非法字符，自动回退到 GB18030（Oracle 中文脚本经典编码）
        let script_text = match String::from_utf8(bytes.clone()) {
            Ok(s) => s,
            Err(_) => {
                let (cow, _, had_errors) = encoding_rs::GB18030.decode(&bytes);
                if had_errors {
                    tracing::warn!("file {} had decode errors under both UTF-8 and GB18030", args.file_path);
                }
                cow.into_owned()
            }
        };

        let stmts = crate::sql_splitter::split_oracle_script(&script_text);
        if stmts.is_empty() {
            return Ok(text_result(json!({
                "file_path": args.file_path,
                "total_statements": 0,
                "message": "file is empty or contains only comments",
            })));
        }

        let stop_on_error = args.stop_on_error.unwrap_or(true);
        let session = self.state.session().await.map_err(DbError::into_mcp)?;
        tracing::info!(
            "execute_sql_file ({}): executing {} statements from {}",
            session.name(),
            stmts.len(),
            args.file_path
        );

        let mut executed_count = 0;
        let mut succeeded_count = 0;
        let mut failed_count = 0;
        let mut errors = Vec::new();

        for (idx, stmt) in stmts.iter().enumerate() {
            executed_count += 1;
            let res = if crate::db::is_readonly_stmt(&stmt.sql) {
                session.db().query(&stmt.sql, 1).await.map(|_| ExecOutcome::DdlOk)
            } else {
                session.db().execute(&stmt.sql).await
            };

            match res {
                Ok(_) => {
                    succeeded_count += 1;
                }
                Err(e) => {
                    failed_count += 1;
                    let err_str = e.to_string();
                    tracing::warn!(
                        "statement #{} in {} failed: {}",
                        idx + 1,
                        args.file_path,
                        err_str
                    );
                    errors.push(json!({
                        "statement_index": idx + 1,
                        "sql_preview": OneLine(&stmt.sql, 100).to_string(),
                        "error": err_str,
                    }));
                    if stop_on_error {
                        break;
                    }
                }
            }
        }

        Ok(text_result(json!({
            "file_path": args.file_path,
            "total_statements": stmts.len(),
            "executed_count": executed_count,
            "succeeded_count": succeeded_count,
            "failed_count": failed_count,
            "stop_on_error": stop_on_error,
            "stopped_early": stop_on_error && failed_count > 0 && executed_count < stmts.len(),
            "errors": errors,
        })))
    }

    // ------------------------------------------------------------------
    // 元数据
    // ------------------------------------------------------------------

    /// List schema objects of type TABLE, VIEW, PROCEDURE, FUNCTION or SEQUENCE.
    /// `filter` is a SQL LIKE pattern on the object name (default matches everything).
    #[tool(description = "List schema objects (tables, views, procedures, functions, sequences) with name, type and status.")]
    async fn list_objects(
        &self,
        Parameters(args): Parameters<ListObjectsArgs>,
    ) -> Result<CallToolResult, McpError> {
        let types: Vec<&str> = match &args.object_type {
            Some(t) => {
                let t = t.to_ascii_uppercase();
                if !OBJECT_TYPES.contains(&t.as_str()) {
                    return Err(McpError::invalid_params(
                        format!("object_type must be one of {OBJECT_TYPES:?}"),
                        None,
                    ));
                }
                // 泛型生命周期：借道 String 的 'static 泄漏（白名单值，仅 5 个）
                vec![Box::leak(t.into_boxed_str())]
            }
            None => OBJECT_TYPES.to_vec(),
        };
        let filter = args.filter.clone().unwrap_or_else(|| "%".to_string());

        let session = self.state.session().await.map_err(DbError::into_mcp)?;
        tracing::info!("list_objects ({}): types={:?}", session.name(), types);
        let result = session
            .db()
            .list_objects(&types, &filter)
            .await
            .map_err(DbError::into_mcp)?;
        Ok(query_result_json(&result))
    }

    /// Get the DDL of a table, view, procedure, function or sequence
    /// (via DBMS_METADATA.GET_DDL).
    #[tool(description = "Get the CREATE DDL statement of a table, view, procedure, function or sequence.")]
    async fn get_ddl(
        &self,
        Parameters(args): Parameters<GetDdlArgs>,
    ) -> Result<CallToolResult, McpError> {
        let object_type = args.object_type.to_ascii_uppercase();
        if !OBJECT_TYPES.contains(&object_type.as_str()) {
            return Err(McpError::invalid_params(
                format!("object_type must be one of {OBJECT_TYPES:?}"),
                None,
            ));
        }
        let session = self.state.session().await.map_err(DbError::into_mcp)?;
        tracing::info!(
            "get_ddl ({}): {} {}",
            session.name(),
            object_type,
            args.object_name
        );
        let ddl = session
            .db()
            .get_ddl(&object_type, &args.object_name, args.owner.as_deref())
            .await
            .map_err(DbError::into_mcp)?;
        Ok(CallToolResult::success(vec![rmcp::model::ContentBlock::text(
            ddl,
        )]))
    }

    // ------------------------------------------------------------------
    // 执行计划
    // ------------------------------------------------------------------

    /// Generate the execution plan of a SQL statement using
    /// EXPLAIN PLAN FOR + DBMS_XPLAN.DISPLAY. Format: BASIC / TYPICAL / ALL
    /// (default ALL, which includes predicates and cardinality estimates).
    #[tool(description = "Show the Oracle execution plan of a SQL statement (EXPLAIN PLAN). Use it to analyze query performance.")]
    async fn explain_plan(
        &self,
        Parameters(args): Parameters<ExplainPlanArgs>,
    ) -> Result<CallToolResult, McpError> {
        let format = args.effective_format();
        let session = self.state.session().await.map_err(DbError::into_mcp)?;
        tracing::info!(
            "explain_plan ({}): {}",
            session.name(),
            OneLine(&args.sql, 120)
        );
        let plan = session
            .db()
            .explain_plan(&args.sql, &format)
            .await
            .map_err(DbError::into_mcp)?;
        Ok(CallToolResult::success(vec![rmcp::model::ContentBlock::text(
            plan,
        )]))
    }
}

#[tool_handler(name = "ora-mcp", version = "1.0.0")]
impl rmcp::ServerHandler for OraMcp {}

// ----------------------------------------------------------------------
// 参数类型（schemars 文档注释 = 参数描述，会进 JSON Schema）
// ----------------------------------------------------------------------

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ConnectionsListArgs {
    /// Case-insensitive substring filter on the connection name. Optional.
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ConnectArgs {
    /// The saved connection name to connect with.
    pub connection_name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AddConnectionArgs {
    /// A short unique name for the connection (kebab-case recommended).
    /// Derive from host/service when the user did not provide one.
    pub connection_name: String,
    /// Database username.
    pub user: String,
    /// Database password.
    pub password: String,
    /// Easy connect string: host[:port][/service], e.g. dbhost.example.com:1521/ORCLPDB1.
    pub dsn: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct DisconnectArgs {}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ConnectionStatsArgs {
    /// Optional connection name. If omitted, returns stats for the currently active database session.
    pub connection_name: Option<String>,
}

/// 单条查询返回行数上限。默认 200，上限 2000（保护 LLM 上下文窗口）。
const DEFAULT_MAX_ROWS: usize = 200;
const HARD_MAX_ROWS: usize = 2000;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct QueryArgs {
    /// The read-only SQL statement (SELECT or WITH).
    pub sql: String,
    /// Maximum number of rows to return (default 200, capped at 2000).
    pub max_rows: Option<usize>,
}

impl QueryArgs {
    #[inline(always)]
    fn effective_max_rows(&self) -> usize {
        self.max_rows.unwrap_or(DEFAULT_MAX_ROWS).clamp(1, HARD_MAX_ROWS)
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExecuteSqlArgs {
    /// The statement to execute: DDL, DML, or an anonymous PLSQL block.
    pub sql: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExecuteSqlFileArgs {
    /// Absolute or relative path to the .sql file to execute.
    pub file_path: String,
    /// Whether to stop execution immediately when a statement fails (default true).
    pub stop_on_error: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListObjectsArgs {
    /// One of TABLE, VIEW, PROCEDURE, FUNCTION, SEQUENCE. Optional (all types).
    pub object_type: Option<String>,
    /// SQL LIKE pattern on the object name, e.g. `EMP%`. Default matches everything.
    pub filter: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetDdlArgs {
    /// One of TABLE, VIEW, PROCEDURE, FUNCTION, SEQUENCE.
    pub object_type: String,
    /// The object name.
    pub object_name: String,
    /// Owner schema; defaults to the current user.
    pub owner: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ExplainPlanArgs {
    /// The SQL statement to explain.
    pub sql: String,
    /// DBMS_XPLAN display format: BASIC, TYPICAL or ALL. Default ALL.
    pub format: Option<String>,
}

impl ExplainPlanArgs {
    fn effective_format(&self) -> String {
        let f = self
            .format
            .clone()
            .unwrap_or_else(|| "ALL".to_string())
            .to_ascii_uppercase();
        if matches!(f.as_str(), "BASIC" | "TYPICAL" | "ALL" | "SERIAL") {
            f
        } else {
            "ALL".to_string()
        }
    }
}

// ----------------------------------------------------------------------
// 小工具函数
// ----------------------------------------------------------------------

/// 统一以 JSON 文本内容返回（对 LLM 最易读、也带结构）。
#[inline(always)]
fn text_result(v: serde_json::Value) -> CallToolResult {
    CallToolResult::success(vec![rmcp::model::ContentBlock::text(v.to_string())])
}

fn query_result_json(r: &crate::db::QueryResult) -> CallToolResult {
    text_result(json!({
        "columns": r.columns,
        "rows": r.rows,
        "row_count": r.row_count,
        "truncated": r.truncated,
    }))
}

/// 惰性单行流式格式化包装器（零堆分配，避免在非目标日志级别下提前分配 String）：
/// 1. 只有当 tracing 真正需要将该字段格式化输出时，Display::fmt 才会执行；
/// 2. 格式化过程零堆分配（直接向 Formatter 流式写入，无中间 Vec 或 String 分配）；
/// 3. 若当前日志级别被过滤，本包装器仅为栈上两个指针，开销为 0。
#[derive(Clone, Copy)]
pub struct OneLine<'a>(pub &'a str, pub usize);

impl<'a> std::fmt::Display for OneLine<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (s, max) = (self.0, self.1);
        let mut written = 0;
        let mut has_pending_space = false;

        for c in s.trim().chars() {
            if c.is_whitespace() {
                if written > 0 {
                    has_pending_space = true;
                }
            } else {
                if has_pending_space {
                    if written + 1 > max {
                        return f.write_str("...");
                    }
                    f.write_str(" ")?;
                    written += 1;
                    has_pending_space = false;
                }
                if written + c.len_utf8() > max {
                    return f.write_str("...");
                }
                write!(f, "{c}")?;
                written += c.len_utf8();
            }
        }
        Ok(())
    }
}

/// 连接名 -> 密码环境变量后缀（与 config.rs 的规则保持一致）。
#[inline]
fn env_suffix(name: &str) -> String {
    name.to_ascii_uppercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_one_line_formatting() {
        let sql = "   SELECT   *   \n  FROM \t  dual   WHERE 1=1  ";
        let formatted = format!("{}", OneLine(sql, 50));
        assert_eq!(formatted, "SELECT * FROM dual WHERE 1=1");

        let truncated = format!("{}", OneLine(sql, 15));
        assert_eq!(truncated, "SELECT * FROM d...");
    }
}
