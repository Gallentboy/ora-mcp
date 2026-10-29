//! tracing 双输出日志：stderr + 二进制同级目录的按天滚动文件。
//!
//! - stderr 层：终端/调试可见，MCP 客户端可捕获
//! - 文件层：`<二进制所在目录>/mcp.log.YYYY-MM-DD`，非阻塞后台线程写入，
//!   不依赖客户端收集，日志一定在
//! - 每行带进程 PID（启动时取一次，全局复用）——多进程共用同一目录的
//!   滚动文件时按 PID 区分来源
//! - 级别：`RUST_LOG` 控制（默认 info），两层共用同一过滤器
//! - `log` 门面桥接（vendor 驱动 ora_async 内部的 log:: 记录）由
//!   tracing-subscriber 的默认 tracing-log 特性自动完成，无需手动 LogTracer
//! - stdout 始终留给 MCP JSON-RPC（clippy print_stdout = deny 强制）
//!
//! 已知边界：tracing-appender 只滚动不清理，旧文件需自行删除；
//! panic=abort 下后台线程缓冲中的最后几条可能丢失（日志量极小，影响可忽略）。

use std::sync::OnceLock;

use tracing::{Event, Subscriber};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{
    EnvFilter,
    fmt,
    fmt::{FmtContext, FormatEvent, FormatFields, format::Writer},
    layer::SubscriberExt,
    registry::LookupSpan,
    util::SubscriberInitExt,
};

/// 进程 PID：首次使用时取一次，全局复用。
static PID: OnceLock<u32> = OnceLock::new();

#[inline(always)]
fn pid() -> u32 {
    *PID.get_or_init(std::process::id)
}

/// 统一事件格式：`时间 [PID] 级别 目标: 消息`（stderr 与文件层共用）。
struct PidFormatter;

impl<S, N> FormatEvent<S, N> for PidFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let meta = event.metadata();
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        write!(
            writer,
            "{ts} [{}] {:<5} {}: ",
            pid(),
            meta.level(),
            meta.target()
        )?;
        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

/// 持有 non_blocking 的 WorkerGuard：drop 时丢弃未刷日志，必须活到进程退出。
/// 文件层初始化失败时为 None（纯 stderr 模式，无需刷盘）。
pub struct LogGuard {
    _guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

/// 初始化日志。返回的 guard 由 main 持有至退出。
/// 文件层初始化失败（目录不可写等）不阻断启动，退化为纯 stderr。
pub fn init() -> LogGuard {
    // log 门面桥接由 tracing-subscriber 的 init() 内置完成（tracing-log 默认特性）
    let filter = || {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
    };

    match crate::config::exe_dir() {
        Some(dir) => {
            let appender = RollingFileAppender::builder()
                .rotation(Rotation::DAILY)
                .filename_prefix("mcp.log")
                .build(&dir);
            match appender {
                Ok(appender) => {
                    let (writer, guard) = tracing_appender::non_blocking(appender);
                    tracing_subscriber::registry()
                        .with(filter())
                        .with(fmt::layer().with_writer(std::io::stderr).event_format(PidFormatter))
                        .with(
                            fmt::layer()
                                .with_ansi(false)
                                .with_writer(writer)
                                .event_format(PidFormatter),
                        )
                        .init();
                    return LogGuard {
                        _guard: Some(guard),
                    };
                }
                Err(e) => {
                    // 初始化失败时还没有 tracing 可用，先兜底到 eprintln
                    #[allow(clippy::print_stderr)]
                    {
                        eprintln!(
                            "ora-mcp: file log init failed in {}: {e}; stderr only",
                            dir.display()
                        );
                    }
                }
            }
        }
        None => {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("ora-mcp: cannot locate binary directory; stderr only");
            }
        }
    }

    // 退化路径：纯 stderr，无文件层，无需 guard
    fmt().with_env_filter(filter()).event_format(PidFormatter).init();
    LogGuard { _guard: None }
}
