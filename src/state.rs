//! 服务器共享状态：连接簿 + 当前会话。
//!
//! - 连接簿：`std::sync::RwLock`（临界区内无 await）；add_connection 运行时可写
//! - 会话：tokio RwLock，单活跃会话语义（connect 切换数据源）
//! - Db 是 deadpool 池的廉价 Clone 包装：并发工具调用各借各的连接

use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

use crate::config::{BookLock, ConnectionBook, ConnectionDef, ConnectionSummary};
use crate::db::Db;
use crate::error::DbError;

/// add_connection 的落盘结果（server 层透传给 LLM）。
pub struct AddOutcome {
    pub saved: bool,
    pub saved_to: Option<std::path::PathBuf>,
    pub save_error: Option<String>,
}

/// 活跃会话：连接名 + 建立时间 + 连接池 + 数据库版本 banner。
pub struct Session {
    pub name: String,
    pub connected_at: DateTime<Utc>,
    pub db: Db,
    pub banner: String,
}

#[derive(Clone)]
pub struct AppState {
    book: Arc<std::sync::RwLock<ConnectionBook>>,
    session: Arc<RwLock<Option<Session>>>,
}

impl AppState {
    pub fn new(book: ConnectionBook) -> Self {
        Self {
            book: Arc::new(std::sync::RwLock::new(book)),
            session: Arc::new(RwLock::new(None)),
        }
    }

    #[inline(always)]
    pub fn list_connections(&self, filter: Option<&str>) -> Vec<ConnectionSummary> {
        self.book.read().unwrap_or_else(|e| e.into_inner()).list(filter)
    }

    #[inline]
    pub fn get_connection(&self, name: &str) -> Option<(String, ConnectionDef)> {
        let book = self.book.read().unwrap_or_else(|e| e.into_inner());
        book.get(name)
            .map(|(n, def)| (n.clone(), def.clone()))
    }

    /// 新增连接。多进程安全：文件锁（`.connections.lock`）内完成
    /// 重读最新 → 同名/目标查重 → 插入 → 落盘，整个临界区不被其他进程插入。
    ///
    /// 拒绝两种重复：
    /// 1. 同名（精确匹配，替换已禁用）
    /// 2. 相同 host/port/service/user 的既有连接（换名字混入也算重复）；
    ///    比较大小写不敏感——域名、service 名、Oracle 用户名实际均不区分大小写
    pub fn try_add_connection(
        &self,
        name: &str,
        def: ConnectionDef,
    ) -> Result<AddOutcome, String> {
        let mut book = self.book.write().unwrap_or_else(|e| e.into_inner());

        // 跨进程互斥；锁失败降级为无锁（原子 rename 仍保证文件不损坏，但可能丢并发更新）
        let lock = book.path.as_ref().and_then(|p| BookLock::acquire_exclusive(p));

        // 锁内重读磁盘最新视图：避免基于启动时的旧快照覆盖掉其他进程新增的连接
        if let Some(path) = book.path.clone() {
            if path.is_file() {
                match ConnectionBook::read_from(&path) {
                    Ok(mut fresh) => {
                        fresh.path = Some(path);
                        *book = fresh;
                    }
                    Err(e) => {
                        tracing::warn!("reload connections before add failed: {e}; 基于内存视图继续")
                    }
                }
            }
        }

        if book.entries().contains_key(name) {
            return Err(format!(
                "connection name `{name}` already exists (replacing is disabled); \
                 call `connections_list` and pick a different name"
            ));
        }

        let new_key = crate::db::target_key(&def.user, &def.dsn).map_err(|e| e.to_string())?;
        for (existing_name, existing) in book.entries() {
            match crate::db::target_key(&existing.user, &existing.dsn) {
                Ok(key) if key == new_key => {
                    return Err(format!(
                        "an existing connection `{existing_name}` already targets the same \
                         database (user/host/port/service); use `connect {existing_name}` \
                         instead, or choose a genuinely different target"
                    ));
                }
                Ok(_) => {}
                // 手写配置里可能混入解析不了的 dsn，跳过它不阻塞新增
                Err(e) => tracing::warn!(
                    "skip duplicate check for legacy connection `{existing_name}`: {e}"
                ),
            }
        }

        if !book.insert_new(name, def) {
            return Err(format!("connection name `{name}` already exists"));
        }

        // 保存也在锁内：查重/插入/落盘对其他进程原子可见
        let (saved, saved_to, save_error) = match book.save() {
            Ok(p) => (true, Some(p), None),
            Err(e) => {
                tracing::error!("persist connection `{name}` failed: {e}");
                (false, None, Some(e))
            }
        };
        drop(lock);
        Ok(AddOutcome {
            saved,
            saved_to,
            save_error,
        })
    }

    /// 幂等复用检查：如果当前会话已经连着目标库，且连接池测活（ping）依然健康，
    /// 直接复用已有连接池，无需销毁重建和重新走 TCP 认证握手。
    pub async fn check_reusable_session(&self, name: &str) -> Option<(String, crate::db::SessionInfo)> {
        let guard = self.session.read().await;
        if let Some(session) = guard.as_ref() {
            if session.name == name && session.db.ping().await.is_ok() {
                if let Ok(info) = session.db.session_info().await {
                    return Some((session.banner.clone(), info));
                }
            }
        }
        None
    }

    /// 取当前会话的只读句柄；未连接返回 NotConnected。
    pub async fn session(&self) -> Result<SessionRef<'_>, DbError> {
        let guard = self.session.read().await;
        if guard.is_none() {
            return Err(DbError::NotConnected);
        }
        Ok(SessionRef { _guard: guard })
    }

    /// 建立会话（替换已有会话，旧池先关闭）。
    pub async fn set_session(&self, name: &str, db: Db, banner: String) {
        let old = self.session.write().await.replace(Session {
            name: name.to_string(),
            connected_at: Utc::now(),
            db,
            banner,
        });
        if let Some(old) = old {
            old.db.close();
        }
    }

    /// 关闭并取走当前会话，返回其名称（用于结果汇报）。
    #[inline(always)]
    pub async fn take_session(&self) -> Option<Session> {
        self.session.write().await.take()
    }
}

/// 会话只读借用守卫：持有 RwLock 读锁期间可安全并发查询。
pub struct SessionRef<'a> {
    _guard: tokio::sync::RwLockReadGuard<'a, Option<Session>>,
}

impl SessionRef<'_> {
    #[inline]
    pub fn name(&self) -> &str {
        match self._guard.as_ref() {
            Some(s) => &s.name,
            None => "",
        }
    }

    pub fn db(&self) -> &Db {
        match self._guard.as_ref() {
            Some(s) => &s.db,
            None => unreachable!("SessionRef 只在会话存在时构造"),
        }
    }
}
