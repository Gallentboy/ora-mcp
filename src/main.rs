//! ora-mcp：Oracle 数据库 MCP server（纯 Rust，stdio 传输）。
//!
//! stdout 被 MCP JSON-RPC 独占；日志双输出 stderr + 二进制同级滚动文件（logging.rs）。

mod config;
mod db;
mod error;
mod ora_errors;
mod oracle_messages;
mod logging;
mod server;
mod sql_splitter;
mod state;

use rmcp::{ServiceExt, transport::io::stdio};

#[tokio::main]
async fn main() {
    // panic=abort 默认跳过析构：安装钩子在终止前将 panic 详情记录到日志和 stderr，便于诊断
    std::panic::set_hook(Box::new(|info| {
        tracing::error!("PANIC: {info}");
        // 非阻塞文件写入层可能来不及刷盘，额外向 stderr 进行一次同步直写
        use std::io::Write;
        let _ = std::io::stderr().write_all(format!("PANIC: {info}\n").as_bytes());
    }));

    // guard 活到进程退出：drop 会丢弃非阻塞队列里未刷盘的日志
    let _log_guard = logging::init();

    let (book, path) = config::ConnectionBook::load();
    match &path {
        Some(p) => tracing::info!("connections config: {}", p.display()),
        None => tracing::info!("connections config: not located, starting with empty book"),
    }

    let handler = server::OraMcp::new(state::AppState::new(book));
    let (stdin, stdout) = stdio();
    let running = match handler.serve((stdin, stdout)).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("MCP server failed to start: {e}");
            std::process::exit(1);
        }
    };
    tracing::info!("ora-mcp v{} serving on stdio", env!("CARGO_PKG_VERSION"));

    match running.waiting().await {
        Ok(reason) => tracing::info!("server stopped: {reason:?}"),
        Err(e) => tracing::error!("server task failed: {e}"),
    }
}
