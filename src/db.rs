//! 数据库访问层：对 `ora_async` 驱动的 deadpool 连接池封装。
//!
//! 这是全项目唯一 import 驱动的模块；工具层只依赖本模块的类型。
//!
//! 池化语义（deadpool managed）：
//! - `create` = `Conn::connect(opts)`；`recycle` = `conn.ping()` 健康检查
//! - 每次工具调用从池里借一条连接（`pool.get()`），用完自动归还
//! - 断掉的连接在归还时被 ping 拒绝、丢弃，下次 get 自动重建——单条坏连接不再废掉整个会话
//! - 并发工具调用各借各的连接，不再互相阻塞（TTC 单连接串行的时代过去了）
//!
//! 驱动约束（源自适配报告，以 vendor 源码为准）：
//! - 连接串仅支持 easy connect（host[:port]/service），不支持 TNS 别名
//! - `QueryResult` 排他借用连接；截断/出错路径必须显式 `close()`，防 ORA-01000
//! - 自动提交默认关：DML/PLSQL 成功后在**借出的那条连接上**显式 `commit()`
//! - OUT 参数在公共 Queryable 层被丢弃 → DBMS_OUTPUT 无法捕获（已知边界）

use deadpool::managed::{Manager, Metrics, Pool, RecycleError, RecycleResult};
use ora_async::Queryable as _;
use serde::Serialize;
use serde_json::{Value, json};

use crate::error::DbError;

/// 每个数据源的池大小上限。
const POOL_MAX_SIZE: usize = 8;

/// 断线自动重连的最大尝试次数（含首次；池里可能积压多条死连接）。
const WIRE_RETRY_ATTEMPTS: usize = 3;

/// 心跳默认间隔（秒）。防火墙/服务器空闲超时通常在分钟级，60s 一拍足够保活，
/// 开销为一次协议往返。可用环境变量 ORA_MCP_HEARTBEAT_SECS 覆盖（下限 5s）。
const HEARTBEAT_INTERVAL_SECS: u64 = 60;

#[inline]
fn heartbeat_interval() -> std::time::Duration {
    let secs = std::env::var("ORA_MCP_HEARTBEAT_SECS")
        .or_else(|_| std::env::var("SQLCL_MCP_HEARTBEAT_SECS"))
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|s| *s >= 5)
        .unwrap_or(HEARTBEAT_INTERVAL_SECS);
    std::time::Duration::from_secs(secs)
}

/// deadpool 管理器：建连 + ping 回收。
struct ConnManager {
    opts: ora_async::Opts,
}

impl Manager for ConnManager {
    type Type = ora_async::Conn;
    type Error = ora_async::Error;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        ora_async::Conn::connect(self.opts.clone()).await
    }

    async fn recycle(
        &self,
        conn: &mut Self::Type,
        _metrics: &Metrics,
    ) -> RecycleResult<Self::Error> {
        conn.ping().await.map_err(RecycleError::Backend)
    }
}

/// 查询结果：列元数据 + 行数据（已转为 JSON 值）。
#[derive(Debug, Serialize)]
pub struct QueryResult {
    pub columns: Vec<ColumnInfo>,
    pub rows: Vec<Vec<Value>>,
    pub row_count: usize,
    /// 达到 max_rows 上限被截断时为 true，提示 LLM 加过滤条件或分页。
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct ColumnInfo {
    pub name: String,
    /// Oracle 线缆类型名（Number/Varchar2/...，来自 TnsType Debug）。
    pub type_name: String,
}

/// 写操作（DDL/DML/PLSQL）执行结果。
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExecOutcome {
    /// CREATE/DROP/ALTER 等 DDL。
    DdlOk,
    /// INSERT/UPDATE/DELETE/MERGE（已提交）。
    RowsAffected { count: u64 },
    /// 匿名 PLSQL 块（已提交）。
    /// 驱动公共 API 拿不到 OUT 参数，DBMS_OUTPUT 暂无法捕获，恒为空。
    Plsql { dbms_output: Vec<String> },
}

/// 单元格文本/二进制的截断上限（保护 LLM 上下文窗口）。
const CELL_TEXT_MAX: usize = 4000;
const CELL_BINARY_MAX: usize = 512;

/// 一个数据源的连接池。
///
/// `Clone` 是廉价的（Pool 内部是 Arc）；借还并发安全。
#[derive(Clone)]
pub struct Db {
    pool: Pool<ConnManager>,
}

impl Db {
    /// 建立连接池并探测数据库 banner。
    ///
    /// 立即借出一条连接完成真实建连（凭据/网络错误在此暴露），
    /// 借出的对象 drop 后自动归还池中复用。
    pub async fn connect(
        user: &str,
        password: &str,
        dsn: &str,
    ) -> Result<(Self, String), DbError> {
        let (host, port, service) = parse_dsn(dsn)?;
        let mut builder = ora_async::Opts::builder()
            .host(host)
            .port(port)
            .username(user)
            .password(password)
            .connect_timeout(std::time::Duration::from_secs(15));
        if let Some(svc) = service {
            builder = builder.service_name(svc);
        }
        let pool = Pool::builder(ConnManager {
            opts: builder.build(),
        })
        .max_size(POOL_MAX_SIZE)
        .build()
        .map_err(|e| DbError::Connect(format!("connection pool build failed: {e}")))?;

        let db = Self { pool };
        let banner = db.fetch_banner().await?;
        spawn_heartbeat(db.pool.clone());
        Ok((db, banner))
    }

    /// 对连接池借出一条连接进行协议级 ping 测活。
    pub async fn ping(&self) -> Result<(), DbError> {
        let mut conn = self.checkout_raw().await.map_err(db_error_from)?;
        conn.ping().await.map_err(db_error_from)
    }

    async fn fetch_banner(&self) -> Result<String, DbError> {
        // v$version 需要权限，失败不阻断连接
        let banner = self
            .retry_on_wire(|| {
                Box::pin(async {
                    let mut conn = self.checkout_raw().await?;
                    Ok(conn
                        .query_first("SELECT banner FROM v$version WHERE ROWNUM = 1")
                        .await
                        .ok()
                        .flatten()
                        .and_then(|row| row.get::<String>(0).ok()))
                })
            })
            .await?;
        Ok(banner.unwrap_or_else(|| "unknown (no v$ privileges or non-CDB)".to_string()))
    }

    /// 从池里借一条连接（deadpool Object，drop 归还 + ping 回收）。
    /// 错误类型对齐驱动（包成 Io），让 retry_on_wire 与终态分类统一处理。
    async fn checkout_raw(
        &self,
    ) -> Result<deadpool::managed::Object<ConnManager>, ora_async::Error> {
        self.pool.get().await.map_err(|e| {
            ora_async::Error::Io(std::io::Error::other(format!(
                "connection pool: {e} (database unreachable or credentials rejected)"
            )))
        })
    }

    /// 断线自动重连：每次尝试各自借连接执行；传输层断线（Io/Protocol）
    /// 丢弃换新连接重试，最多 [WIRE_RETRY_ATTEMPTS] 次（池中可能积压多条
    /// 被闲置掐死的连接，一次重试未必清完），重试仍失败才把错误抛给 LLM。
    /// 服务器错误（ORA-xxx）/认证错误是确定性失败，不重试。
    // needless_lifetimes 在此为误报：'a 承载闭包返回 future 对捕获的借用，
    // 省略后 impl-trait 参数位置的 '_ 无处绑定（E0106）
    #[allow(clippy::needless_lifetimes)]
    async fn retry_on_wire<'a, T>(
        &'a self,
        mut attempt: impl FnMut() -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, ora_async::Error>> + Send + 'a>,
        >,
    ) -> Result<T, DbError> {
        for i in 1..=WIRE_RETRY_ATTEMPTS {
            match attempt().await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    if is_broken_wire(&e) && i < WIRE_RETRY_ATTEMPTS {
                        tracing::warn!(
                            "连接中断（{e}），丢弃换新连接重试 {}/{}",
                            i,
                            WIRE_RETRY_ATTEMPTS - 1
                        );
                        continue;
                    }
                    return Err(db_error_from(e));
                }
            }
        }
        // 逻辑不可达：最后一次尝试必走 return 分支
        Err(DbError::Sql("retry loop exhausted".into()))
    }

    /// 执行只读查询（SELECT/WITH，双保险再查一次首词）。
    pub async fn query(&self, sql: &str, max_rows: usize) -> Result<QueryResult, DbError> {
        require_readonly(sql)?;
        self.run_query(sql, Vec::new(), max_rows).await
    }

    /// 执行写操作：DDL / DML / 匿名 PLSQL 块（成功后提交）。
    ///
    /// 断线重试只覆盖**语句阶段**——未提交事务会随断线被服务器回滚，重发安全。
    /// **提交阶段**断线不自动重试：提交可能已生效，盲目重发会重复执行；
    /// 此时返回"提交状态未知"错误，让 LLM/用户重新查询确认。
    pub async fn execute(&self, sql: &str) -> Result<ExecOutcome, DbError> {
        if is_readonly_stmt(sql) {
            return Err(DbError::Sql(
                "read-only statement: use the `query` tool for SELECT/WITH".into(),
            ));
        }
        // Ok(Ok(n)) = 语句+提交成功；Ok(Err(msg)) = 提交阶段失败（终态，不重试）；
        // Err(e) = 语句阶段失败（断线则换连接重试）
        let outcome = self
            .retry_on_wire(|| {
                Box::pin(async {
                    let mut conn = self.checkout_raw().await?;
                    // query() 当万能入口：列空 = 非查询语句，rows_affected() 有效
                    let mut rs = conn.query(sql).await?;
                    let affected = rs.rows_affected();
                    let _ = rs.close().await;
                    // 驱动默认不自动提交：DML/PLSQL 显式提交，DDL 隐式提交、再 commit 无害
                    match conn.commit().await {
                        Ok(()) => Ok(Ok(affected)),
                        Err(e) => Ok(Err(e.to_string())),
                    }
                })
            })
            .await?;

        let affected = match outcome {
            Ok(n) => n,
            Err(commit_err) => {
                return Err(DbError::Sql(format!(
                    "语句已执行，但提交阶段连接中断（{commit_err}）。\
                     提交状态未知：请重新查询确认数据，必要时手动重做"
                )))
            }
        };

        // CREATE OR REPLACE 程序单元：精准检查当前编译对象的 USER_ERRORS 状态
        if let Some(unit_name) = extract_program_unit_name(sql) {
            let errors = self.fetch_user_errors(&unit_name).await?;
            if !errors.is_empty() {
                return Err(DbError::Compile(errors));
            }
        }

        Ok(classify_exec(sql, affected))
    }

    /// 列出 schema 对象（user_objects），filter 为 LIKE 模式（绑定参数防注入）。
    pub async fn list_objects(
        &self,
        types: &[&str],
        filter: &str,
    ) -> Result<QueryResult, DbError> {
        let list = types
            .iter()
            .map(|t| format!("'{t}'"))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT object_name, object_type, status FROM user_objects \
             WHERE object_type IN ({list}) AND object_name LIKE :1 \
             ORDER BY object_type, object_name"
        );
        self.run_query(
            &sql,
            vec![
                ora_async::BindParam::input(ora_async::BindValue::Text(filter.to_string()))
            ],
            500,
        )
        .await
    }

    /// 取对象 DDL（DBMS_METADATA.GET_DDL，CLOB 会被驱动内联为 Text）。
    pub async fn get_ddl(
        &self,
        object_type: &str,
        object_name: &str,
        owner: Option<&str>,
    ) -> Result<String, DbError> {
        use ora_async::{BindParam, BindValue, OracleValue};
        let (sql, params) = match owner {
            Some(o) => (
                "SELECT DBMS_METADATA.GET_DDL(:1, :2, :3) AS ddl FROM dual".to_string(),
                vec![
                    BindParam::input(BindValue::Text(object_type.to_string())),
                    BindParam::input(BindValue::Text(object_name.to_string())),
                    BindParam::input(BindValue::Text(o.to_string())),
                ],
            ),
            None => (
                "SELECT DBMS_METADATA.GET_DDL(:1, :2) AS ddl FROM dual".to_string(),
                vec![
                    BindParam::input(BindValue::Text(object_type.to_string())),
                    BindParam::input(BindValue::Text(object_name.to_string())),
                ],
            ),
        };
        // 只读查询：断线自动换连接重试（绑定参数每次尝试克隆，开销可忽略）
        let ddl = self
            .retry_on_wire(|| {
                Box::pin(async {
                    let mut conn = self.checkout_raw().await?;
                    let mut rs = conn.query_with_params(&sql, params.clone()).await?;
                    let ddl = rs
                        .next_row()
                        .await?
                        .and_then(|row| row.take_values().into_iter().next())
                        .and_then(|v| match v {
                            OracleValue::Text(s) => Some(s),
                            OracleValue::Null => None,
                            other => Some(other.to_string()),
                        })
                        .unwrap_or_default();
                    let _ = rs.close().await;
                    Ok(ddl)
                })
            })
            .await?;
        Ok(ddl)
    }

    /// EXPLAIN PLAN FOR + DBMS_XPLAN.DISPLAY，返回格式化计划文本。
    /// format 已由 server 层校验（BASIC/TYPICAL/ALL/SERIAL）。
    pub async fn explain_plan(&self, sql: &str, format: &str) -> Result<String, DbError> {
        use ora_async::OracleValue;
        require_readonly(sql)?;

        // 整体断线重试安全：EXPLAIN PLAN 只写 PLAN_TABLE，重复执行无业务副作用
        let plan = self
            .retry_on_wire(|| {
                Box::pin(async {
                    let mut conn = self.checkout_raw().await?;
                    // EXPLAIN PLAN 是写 PLAN_TABLE 的 DML，语句本身可能很长，直接拼接
                    conn.exec(&format!("EXPLAIN PLAN FOR {sql}")).await?;
                    conn.commit().await?;

                    let mut rs = conn
                        .query(&format!(
                            "SELECT * FROM TABLE(DBMS_XPLAN.DISPLAY(NULL, NULL, '{format}'))"
                        ))
                        .await?;
                    let mut lines = Vec::new();
                    while let Some(row) = rs.next_row().await? {
                        // 首列 PLAN_TABLE_OUTPUT
                        if let Some(v) = row.take_values().into_iter().next() {
                            match v {
                                OracleValue::Text(s) => lines.push(s),
                                OracleValue::Null => {}
                                other => lines.push(other.to_string()),
                            }
                        }
                    }
                    let _ = rs.close().await;
                    Ok(lines.join("\n"))
                })
            })
            .await?;
        Ok(plan)
    }

    /// 会话环境上下文。
    pub async fn session_info(&self) -> Result<SessionInfo, DbError> {
        let row = self
            .run_query(
                "SELECT USER, \
                        SYS_CONTEXT('USERENV','CURRENT_SCHEMA'), \
                        SYS_CONTEXT('USERENV','DB_NAME') \
                 FROM dual",
                Vec::new(),
                1,
            )
            .await?;
        let extract = |i: usize| -> String {
            row.rows
                .first()
                .and_then(|r| r.get(i))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        Ok(SessionInfo {
            username: extract(0),
            schema: extract(1),
            database: extract(2),
        })
    }

    /// 关闭整个池（活跃连接用完后丢弃，不再新建）。
    #[inline(always)]
    pub fn close(&self) {
        self.pool.close();
    }

    /// 通用查询执行（只读）：借连接 → 执行（可选绑定）→ 限行收集 → 关游标 → 归还。
    /// 断线自动换连接重试（绑定参数每次尝试克隆，开销可忽略）。
    async fn run_query(
        &self,
        sql: &str,
        params: Vec<ora_async::BindParam>,
        max_rows: usize,
    ) -> Result<QueryResult, DbError> {
        self.retry_on_wire(|| {
            Box::pin(async {
                let mut conn = self.checkout_raw().await?;
                let mut rs = if params.is_empty() {
                    conn.query(sql).await?
                } else {
                    conn.query_with_params(sql, params.clone()).await?
                };

                let columns = rs
                    .columns()
                    .iter()
                    .map(|c| ColumnInfo {
                        name: c.name.clone(),
                        type_name: format!("{:?}", c.data_type),
                    })
                    .collect();

                let mut rows = Vec::new();
                let mut truncated = false;
                loop {
                    match rs.next_row().await {
                        Ok(Some(row)) => {
                            rows.push(
                                row.take_values()
                                    .into_iter()
                                    .map(value_to_json)
                                    .collect::<Vec<_>>(),
                            );
                            if rows.len() >= max_rows {
                                truncated = true;
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            // 出错路径同样必须关游标
                            let _ = rs.close().await;
                            return Err(e);
                        }
                    }
                }
                let _ = rs.close().await;

                Ok(QueryResult {
                    row_count: rows.len(),
                    columns,
                    rows,
                    truncated,
                })
            })
        })
        .await
    }

    /// 获取当前本地连接池的状态（死锁无争用，原子读取内存计数）
    pub fn pool_stats(&self) -> PoolStats {
        let status = self.pool.status();
        let in_use = status.size.saturating_sub(status.available);
        PoolStats {
            pool_max_size: status.max_size,
            pool_allocated: status.size,
            pool_idle: status.available,
            pool_in_use: in_use,
            pool_waiting: status.waiting,
        }
    }

    /// 查询数据库服务器全局会话统计（自动查询 v$session，若账号无权限自动降级为 None）
    pub async fn server_stats(&self, username: &str) -> ServerStats {
        let user_upper = username.trim().to_ascii_uppercase();
        let sql = format!(
            "SELECT \
                COUNT(*), \
                SUM(CASE WHEN username = '{user}' THEN 1 ELSE 0 END), \
                SUM(CASE WHEN status = 'ACTIVE' THEN 1 ELSE 0 END) \
             FROM v$session",
            user = user_upper
        );
        match self.run_query(&sql, Vec::new(), 1).await {
            Ok(qr) => {
                let parse_col = |idx: usize| -> Option<u64> {
                    qr.rows.first()?.get(idx)?.as_str()?.parse::<u64>().ok()
                };
                ServerStats {
                    server_total_sessions: parse_col(0),
                    server_current_user_sessions: parse_col(1),
                    server_active_sessions: parse_col(2),
                }
            }
            Err(_) => ServerStats {
                server_current_user_sessions: None,
                server_active_sessions: None,
                server_total_sessions: None,
            },
        }
    }
}

/// 数据库会话身份信息。
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub username: String,
    pub schema: String,
    pub database: String,
}

/// 本地连接池指标
#[derive(Debug, Clone, Serialize)]
pub struct PoolStats {
    pub pool_max_size: usize,
    pub pool_allocated: usize,
    pub pool_idle: usize,
    pub pool_in_use: usize,
    pub pool_waiting: usize,
}

/// 数据库服务器端会话指标
#[derive(Debug, Clone, Serialize)]
pub struct ServerStats {
    pub server_current_user_sessions: Option<u64>,
    pub server_active_sessions: Option<u64>,
    pub server_total_sessions: Option<u64>,
}

/// 校验连接串格式（add_connection 提前报错用）。
#[inline(always)]
pub fn validate_dsn(dsn: &str) -> Result<(), DbError> {
    parse_dsn(dsn).map(|_| ())
}

/// 连接目标四元组（host, port, service, user），全部归一化到小写、去空白，
/// 用于 add_connection 的重复检测：域名/service 名/Oracle 用户名实际均不区分大小写。
/// host 额外做 `localhost` → `127.0.0.1` 归一（最常见的等价写法）；
/// DNS 别名（如 db01.example.com 与别名解析）不做外部网络解析判定，属已知边界。
pub fn target_key(
    user: &str,
    dsn: &str,
) -> Result<(String, u16, Option<String>, String), DbError> {
    let (host, port, service) = parse_dsn(dsn)?;
    let host = match host.trim().to_ascii_lowercase().as_str() {
        "localhost" => "127.0.0.1".to_string(),
        other => other.to_string(),
    };
    Ok((
        host,
        port,
        service.map(|s| s.trim().to_ascii_lowercase()),
        user.trim().to_ascii_lowercase(),
    ))
}

/// 解析 easy connect 串：`host[:port][/service]`。
/// 驱动不支持 TNS 别名/描述串，这里是最小子集（不支持 IPv6 字面量）。
fn parse_dsn(dsn: &str) -> Result<(String, u16, Option<String>), DbError> {
    let dsn = dsn.trim();
    if dsn.is_empty() {
        return Err(DbError::Connect("empty dsn".into()));
    }
    let (host_port, service) = match dsn.split_once('/') {
        Some((hp, svc)) => (hp, Some(svc.to_string())),
        None => (dsn, None),
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => {
            let port = p
                .parse::<u16>()
                .map_err(|_| DbError::Connect(format!("invalid port in dsn `{dsn}`")))?;
            (h.to_string(), port)
        }
        None => (host_port.to_string(), 1521),
    };
    if host.is_empty() {
        return Err(DbError::Connect(format!("missing host in dsn `{dsn}`")));
    }
    if !is_host_like(&host) {
        return Err(DbError::Connect(format!(
            "invalid host `{host}` in dsn `{dsn}` (expected hostname or IP)"
        )));
    }
    if let Some(svc) = &service {
        if !is_host_like(svc) {
            return Err(DbError::Connect(format!(
                "invalid service name `{svc}` in dsn `{dsn}`"
            )));
        }
    }
    Ok((host, port, service))
}

/// host/service 名仅允许字母数字与 . - _（拒绝空格、感叹号等垃圾输入）。
#[inline(always)]
fn is_host_like(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// 驱动错误 → 用户可读文本。
/// 服务器错误走中文码表（19c 全量译文，缺消息文件形态重组为可读文案）；
/// 其余（网络/协议/监听器拒绝串）嗅探 ORA-xxxxx 接码表，无码原样透传。
#[inline]
fn driver_err_text(e: ora_async::Error) -> String {
    match e {
        ora_async::Error::Server(oe) => crate::ora_errors::server_text(oe.code, &oe.message),
        other => crate::ora_errors::sniff(&other.to_string()),
    }
}

/// 只读守卫：拒绝非 SELECT/WITH 开头的语句。
fn require_readonly(sql: &str) -> Result<(), DbError> {
    if is_readonly_stmt(sql) {
        Ok(())
    } else {
        let first = first_word(sql);
        Err(DbError::Sql(format!(
            "read-only tool: statement starts with `{first}`; \
             use the `execute_sql` tool for DDL/DML/PLSQL"
        )))
    }
}

#[inline(always)]
pub(crate) fn is_readonly_stmt(sql: &str) -> bool {
    matches!(first_word(sql).as_str(), "SELECT" | "WITH")
}

#[inline]
fn first_word(sql: &str) -> String {
    sql.trim_start()
        .split(|c: char| c.is_whitespace() || c == '(')
        .find(|s| !s.is_empty())
        .unwrap_or_default()
        .to_ascii_uppercase()
}

/// 提取正在 CREATE/ALTER 的存储程序单元名称（全大写、无 schema 前缀）。
/// 仅针对 PROCEDURE, FUNCTION, PACKAGE, TRIGGER, VIEW, TYPE。
fn extract_program_unit_name(sql: &str) -> Option<String> {
    let mut words = sql
        .lines()
        .map(|l| {
            let line = l.trim();
            if let Some(idx) = line.find("--") {
                &line[..idx]
            } else {
                line
            }
        })
        .flat_map(|l| l.split_whitespace());

    let first = words.next()?.to_ascii_uppercase();
    if first != "CREATE" && first != "ALTER" {
        return None;
    }

    let mut target_name = None;
    while let Some(w) = words.next() {
        let upper = w.to_ascii_uppercase();
        if matches!(
            upper.as_str(),
            "PROCEDURE" | "FUNCTION" | "PACKAGE" | "TRIGGER" | "VIEW" | "TYPE"
        ) {
            let mut next = words.next()?;
            if next.eq_ignore_ascii_case("BODY") {
                next = words.next()?;
            }
            target_name = Some(next);
            break;
        }
    }

    let raw = target_name?;
    let name_part = raw.split('(').next()?.trim();
    let unqual = if let Some((_, n)) = name_part.rsplit_once('.') {
        n
    } else {
        name_part
    };
    let clean = unqual.trim_matches(|c| c == '"' || c == '\'');
    if clean.is_empty() {
        None
    } else {
        Some(clean.to_ascii_uppercase())
    }
}

impl Db {
    /// 取 USER_ERRORS 针对特定程序单元的编译错误明细（只读路径，自带断线重试）。
    async fn fetch_user_errors(&self, unit_name: &str) -> Result<String, DbError> {
        let r = self
            .run_query(
                "SELECT name, line, position, text FROM user_errors                  WHERE name = :1                  ORDER BY sequence",
                vec![ora_async::BindParam::input(ora_async::BindValue::Text(
                    unit_name.to_string(),
                ))],
                100,
            )
            .await?;
        let cell = |row: &Vec<Value>, i: usize| -> String {
            row.get(i)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let mut out = String::new();
        for row in &r.rows {
            out.push_str(&format!(
                "{} line {}:{} {}
",
                cell(row, 0),
                cell(row, 1),
                cell(row, 2),
                cell(row, 3)
            ));
        }
        Ok(out)
    }
}

/// 池保活心跳：周期性借出一条连接 ping 后归还。
///
/// - 保活对象是"池里的一条"：多数场景只有一条热连接被反复刷新即够用
///   （MCP 工具调用基本串行）；偶有多条闲置连接错过心跳被掐，
///   由 retry_on_wire 的断线重试兜底——两机制互补
/// - 池关闭（disconnect/切换数据源）→ get 返回 Closed → 任务自愈退出，无泄漏
/// - 借出失败（库不可达）只 warn 不退出，下拍重试——库恢复后自动续上
fn spawn_heartbeat(pool: Pool<ConnManager>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(heartbeat_interval());
        ticker.tick().await; // tokio 首拍立即到点，跳过
        loop {
            ticker.tick().await;
            match pool.get().await {
                Ok(mut conn) => {
                    if let Err(e) = conn.ping().await {
                        tracing::warn!("心跳 ping 失败（该连接归还时将被丢弃）：{e}");
                    } else {
                        tracing::debug!("心跳 ping 成功");
                    }
                }
                Err(deadpool::managed::PoolError::Closed) => {
                    tracing::debug!("连接池已关闭，心跳任务退出");
                    break;
                }
                Err(e) => {
                    tracing::warn!("心跳借连接失败（库不可达？下拍重试）：{e}");
                }
            }
        }
    });
}

/// 传输层断线判定：这类失败换新连接重试是安全的；
/// 服务器错误（ORA-xxx）/认证错误是确定性失败，不重试。
fn is_broken_wire(e: &ora_async::Error) -> bool {
    matches!(
        e,
        ora_async::Error::Io(_) | ora_async::Error::Protocol(_)
    )
}

/// 驱动错误终态分类：借连接失败（池无法建新连接）是连接类错误，
/// 其余按 SQL 执行错误走中文码表。
fn db_error_from(e: ora_async::Error) -> DbError {
    if let ora_async::Error::Io(io) = &e {
        let msg = io.to_string();
        if msg.contains("connection pool:") {
            return DbError::Connect(msg);
        }
    }
    DbError::Sql(driver_err_text(e))
}

/// 按首关键词分类写操作结果。
fn classify_exec(sql: &str, affected: u64) -> ExecOutcome {
    match first_word(sql).as_str() {
        "INSERT" | "UPDATE" | "DELETE" | "MERGE" => ExecOutcome::RowsAffected { count: affected },
        "BEGIN" | "DECLARE" => ExecOutcome::Plsql {
            dbms_output: Vec::new(),
        },
        _ => ExecOutcome::DdlOk,
    }
}

/// OracleValue → JSON 值（对 LLM 上下文友好：NUMBER 保精度转字符串、大文本截断）。
fn value_to_json(v: ora_async::OracleValue) -> Value {
    use ora_async::OracleValue;
    match v {
        OracleValue::Null => Value::Null,
        OracleValue::Int(i) => json!(i),
        OracleValue::Float(f) => json!(f),
        // NUMBER 以字符串返回：rust_decimal 精度无损，JSON number 会丢尾数
        OracleValue::Number(d) => json!(d.to_string()),
        OracleValue::Text(s) => json!(truncate_text(s)),
        OracleValue::Binary(b) => json!(binary_preview(&b)),
        OracleValue::Date(d) => json!(d.to_string()),
        OracleValue::Timestamp(t) => json!(t.to_string()),
        OracleValue::TimestampTz(t) => json!(t.to_rfc3339()),
        OracleValue::Boolean(b) => json!(b),
        // 游标值不该出现在平铺行里；驱动会展开隐式结果集
        OracleValue::Cursor(_) => Value::Null,
    }
}

#[inline]
fn truncate_text(s: String) -> String {
    if s.chars().count() <= CELL_TEXT_MAX {
        return s;
    }
    let head: String = s.chars().take(CELL_TEXT_MAX).collect();
    format!("{head}...[truncated]")
}

#[inline]
fn binary_preview(b: &[u8]) -> String {
    if b.len() <= CELL_BINARY_MAX {
        hex::encode(b)
    } else {
        format!(
            "{}...[{} bytes total]",
            hex::encode(&b[..CELL_BINARY_MAX]),
            b.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_vs_server_error_classification() {
        let io_err = ora_async::Error::Io(std::io::Error::other("peer closed"));
        let proto_err = ora_async::Error::Protocol("desync".into());
        let ora_err = ora_async::Error::Server(ora_async::OracleError {
            code: 942,
            message: "table or view does not exist".into(),
        });
        assert!(is_broken_wire(&io_err));
        assert!(is_broken_wire(&proto_err));
        // ORA 错误是确定性失败，绝不重试
        assert!(!is_broken_wire(&ora_err));
    }

    #[test]
    fn pool_failure_maps_to_connect_error() {
        let e = ora_async::Error::Io(std::io::Error::other(
            "connection pool: backend (database unreachable)",
        ));
        assert!(matches!(db_error_from(e), DbError::Connect(_)));
        let e = ora_async::Error::Server(ora_async::OracleError {
            code: 1017,
            message: "invalid username/password".into(),
        });
        assert!(matches!(db_error_from(e), DbError::Sql(_)));
    }
}
