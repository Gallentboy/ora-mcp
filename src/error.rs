//! 错误类型与到 MCP `ErrorData` 的映射。
//!
//! 对 LLM 友好是第一原则：错误消息自解释，让模型能向用户解释原因并自行修正重试。

use rmcp::ErrorData;

/// 数据库层统一错误。
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// 未建立连接。
    #[error("not connected to any database. Call the `connect` tool first")]
    NotConnected,
    /// 连接失败（含 ORA- 错误）。
    #[error("connection failed: {0}")]
    Connect(String),
    /// SQL 执行失败（含 ORA- 错误）。
    #[error("SQL execution failed: {0}")]
    Sql(String),
    /// PLSQL 编译错误（附 USER_ERRORS 详情）。
    #[error("PLSQL compiled with errors:\n{0}")]
    Compile(String),
}

impl DbError {
    /// 映射到 MCP 协议错误：数据库侧错误用 invalid_params（模型可修正重试）。
    /// 同时落一条 warn 日志——工具错误只回给客户端不落盘的话，排查全靠猜。
    pub fn into_mcp(self) -> ErrorData {
        if !matches!(self, DbError::NotConnected) {
            tracing::warn!("db error: {self}");
        }
        match &self {
            DbError::NotConnected => ErrorData::invalid_params(self.to_string(), None),
            DbError::Connect(_) | DbError::Sql(_) | DbError::Compile(_) => {
                ErrorData::invalid_params(self.to_string(), None)
            }
        }
    }
}
