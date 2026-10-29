//! 连接配置：默认二进制格式 `.connections`（二进制同级目录），TOML 仅环境变量显式指定时使用。
//!
//! 查找顺序：
//! 1. `$SQLCL_MCP_CONNECTIONS` 指定的文件——文件名是 `.connections` 则二进制格式，
//!    其余（如 `.toml`）按明文 TOML（高级用户自己写配置的入口）
//! 2. `<二进制所在目录>/.connections`（默认，bincode 二进制 + chmod 600）
//!
//! 安全边界：二进制格式带盐+XOR 混淆，cat/strings 出来全乱码；但盐随文件同行，
//! 属防翻看非加密，密码仍可被刻意恢复；600 权限保证仅当前 OS 用户可读。
//! 真正加密需接 OS 钥匙串（未实现）。
//! 多进程：写入（add_connection）由 `.connections.lock` 文件锁互斥，锁内重读最新后再查重/插入/保存。

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

/// 单个命名连接定义。password 序列化进文件（本地明文，与手写配置一致）；
/// 对 LLM 展示一律走 [ConnectionSummary]，密码永不外泄。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionDef {
    pub user: String,
    /// 明文密码。可省略，运行时回退读 `SQLCL_MCP_PASSWORD_<NAME>`。
    #[serde(default)]
    pub password: Option<String>,
    /// easy connect 串（host[:port]/service）。
    pub dsn: String,
}

impl ConnectionDef {
    /// 解析生效密码：文件密码 > 环境变量（优先 ORA_MCP_，兼容老 SQLCL_MCP_）。
    pub fn effective_password(&self, name: &str) -> Option<String> {
        if let Some(p) = &self.password {
            return Some(p.clone());
        }
        if let Ok(v) = std::env::var(password_env_var(name)) {
            if !v.is_empty() {
                return Some(v);
            }
        }
        let legacy_key = format!(
            "SQLCL_MCP_PASSWORD_{}",
            name.to_ascii_uppercase()
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect::<String>()
        );
        std::env::var(legacy_key).ok().filter(|v| !v.is_empty())
    }
}

/// 密码环境变量名（如 ORA_MCP_PASSWORD_HR_DEV）。
#[inline(always)]
pub fn password_env_var(name: &str) -> String {
    format!(
        "ORA_MCP_PASSWORD_{}",
        name.to_ascii_uppercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>()
    )
}

/// connections_list 返回给 LLM 的条目——绝不包含密码。
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionSummary {
    pub name: String,
    pub user: String,
    pub dsn: String,
}

/// 连接簿：全部命名连接 + 落盘路径。
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ConnectionBook {
    /// name -> def；BTreeMap 保证列表输出稳定有序。
    #[serde(default)]
    pub connections: BTreeMap<String, ConnectionDef>,
    /// 配置文件路径；内存态字段，不参与序列化。
    #[serde(skip)]
    pub path: Option<PathBuf>,
}

impl ConnectionBook {
    /// 从配置路径加载。文件不存在时返回空簿（LLM 会看到 connections_list 为空，
    /// 还可以走 `add_connection` 现场注册；MCP server 一旦启动失败客户端诊断很困难）。
    pub fn load() -> (Self, Option<PathBuf>) {
        let path = Self::config_path();
        match &path {
            Some(p) if p.is_file() => {
                // 共享锁：与写者的 EX 互斥、与其他读者的 SH 并存。
                // read_from 内部不加锁——写路径在 EX 内的重读不能嵌套 SH（自锁死）。
                let _shared = BookLock::acquire_shared(p);
                match Self::read_from(p) {
                    Ok(mut book) => {
                        book.path = Some(p.clone());
                        (book, Some(p.clone()))
                    }
                    Err(e) => {
                        tracing::warn!("connections 配置解析失败 {p:?}: {e}; 使用空配置");
                        (Self::empty_at(p), Some(p.clone()))
                    }
                }
            }
            Some(p) => {
                tracing::info!("connections 配置不存在 {p:?}; 使用空配置");
                (Self::empty_at(p), Some(p.clone()))
            }
            None => {
                tracing::info!("无法定位二进制目录; 使用空配置");
                (Self::default(), None)
            }
        }
    }

    /// 读取指定路径（add_connection 锁内重读最新视图用）。
    pub fn read_from(path: &Path) -> Result<Self, String> {
        Self::load_binary(path)
    }

    /// 二进制格式：魔数（含版本）+ 16 字节随机盐 + XOR 混淆后的 bincode 负载。
    const BINARY_MAGIC: &[u8] = b"ORAMCP2";
    /// 兼容历史版本的魔数
    const LEGACY_MAGIC: &[u8] = b"SQLCLMCP2";
    const SALT_LEN: usize = 16;

    fn load_binary(path: &Path) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("read: {e}"))?;
        let body = if let Some(p) = bytes.strip_prefix(Self::BINARY_MAGIC) {
            p
        } else if let Some(p) = bytes.strip_prefix(Self::LEGACY_MAGIC) {
            p
        } else {
            return Err("not a valid .connections file (magic mismatch)".into());
        };
        if body.len() < Self::SALT_LEN {
            return Err("truncated .connections file".into());
        }
        let (salt, payload) = body.split_at(Self::SALT_LEN);
        let mut payload = payload.to_vec();
        xor_keystream(salt, &mut payload);
        bincode::deserialize(&payload).map_err(|e| format!("deserialize: {e}"))
    }

    #[inline]
    fn empty_at(path: &Path) -> Self {
        Self {
            path: Some(path.to_path_buf()),
            ..Self::default()
        }
    }

    fn config_path() -> Option<PathBuf> {
        exe_dir().map(|d| d.join(".connections"))
    }

    /// 名称过滤（大小写不敏感子串匹配）。
    pub fn list(&self, filter: Option<&str>) -> Vec<ConnectionSummary> {
        self.connections
            .iter()
            .filter(|(name, _)| match filter {
                Some(f) if !f.is_empty() => name.to_lowercase().contains(&f.to_lowercase()),
                _ => true,
            })
            .map(|(name, def)| ConnectionSummary {
                name: name.clone(),
                user: def.user.clone(),
                dsn: def.dsn.clone(),
            })
            .collect()
    }

    #[inline(always)]
    pub fn get(&self, name: &str) -> Option<(&String, &ConnectionDef)> {
        self.connections.get_key_value(name)
    }

    /// 全量条目视图（重复检测遍历用）。
    #[inline(always)]
    pub fn entries(&self) -> &BTreeMap<String, ConnectionDef> {
        &self.connections
    }

    /// 插入新连接；名称已存在返回 false 且不改动（同名替换已禁用）。
    /// 调用方（AppState::try_add_connection）在同一把写锁内先做查重。
    #[inline]
    pub fn insert_new(&mut self, name: &str, def: ConnectionDef) -> bool {
        if self.connections.contains_key(name) {
            return false;
        }
        self.connections.insert(name.to_string(), def);
        true
    }

    /// 原子落盘（tmp + rename，写一半崩溃不损坏现有配置）。
    /// 二进制格式追加 chmod 600（仅当前 OS 用户可读）；TOML 保持明文。
    pub fn save(&self) -> Result<PathBuf, String> {
        let path = self.path.clone().ok_or("no config path to save")?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        }
        let tmp = {
            let mut s = path.as_os_str().to_os_string();
            s.push(".tmp");
            PathBuf::from(s)
        };
        let payload = bincode::serialize(self).map_err(|e| format!("serialize: {e}"))?;
        let salt = random_salt();
        let mut payload = payload;
        xor_keystream(&salt, &mut payload);
        let mut bytes = Self::BINARY_MAGIC.to_vec();
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&payload);
        std::fs::write(&tmp, bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("chmod 600 {}: {e}", tmp.display()))?;
        }
        std::fs::rename(&tmp, &path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("rename to {}: {e}", path.display())
        })?;
        Ok(path)
    }
}

/// 二进制所在目录（默认配置与日志的同级目录）。logging.rs 复用。
#[inline(always)]
pub(crate) fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(|p| p.to_path_buf())
}

/// SHA-256 计数器密钥流异或（盐随文件存储：混淆非加密，保证 cat/strings 不可读）。
fn xor_keystream(salt: &[u8], data: &mut [u8]) {
    use sha2::{Digest, Sha256};
    for (i, chunk) in data.chunks_mut(32).enumerate() {
        let mut h = Sha256::new();
        h.update(salt);
        h.update((i as u64).to_le_bytes());
        let block = h.finalize();
        for (b, k) in chunk.iter_mut().zip(block.iter()) {
            *b ^= k;
        }
    }
}

/// 16 字节随机盐（RandomState 每次构造都是进程随机种子，无 rand 依赖）。
fn random_salt() -> [u8; 16] {
    use std::hash::{BuildHasher, Hasher, RandomState};
    let mut salt = [0u8; 16];
    let fill = |buf: &mut [u8]| {
        let mut h = RandomState::new().build_hasher();
        // 先喂点东西再 finish：空输入也可能退化
        h.write(buf);
        buf.copy_from_slice(&h.finish().to_le_bytes());
    };
    fill(&mut salt[0..8]);
    fill(&mut salt[8..16]);
    salt
}

/// 配置文件跨进程写锁（`.connections.lock`，flock 排他）。
/// Drop 自动释放；拿锁失败不阻断（退化为无锁写，仍原子不损坏）。
pub struct BookLock(std::fs::File);

impl Drop for BookLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

impl BookLock {
    /// 写锁（LOCK_EX）：重读 + 查重 + 插入 + 落盘的整个临界区独占。
    pub fn acquire_exclusive(config_path: &Path) -> Option<BookLock> {
        Self::acquire(config_path, true)
    }

    /// 读锁（LOCK_SH）：多进程可并存读；写者持 EX 时阻塞直至释放。
    /// 注意：绝不能在已持 EX 的同进程里再取 SH——flock 按 fd 记账，
    /// 同进程不同 fd 的 EX/SH 互相冲突，会自锁死。
    pub fn acquire_shared(config_path: &Path) -> Option<BookLock> {
        Self::acquire(config_path, false)
    }

    fn acquire(config_path: &Path, exclusive: bool) -> Option<BookLock> {
        use fs2::FileExt;
        let mut lock_path = config_path.as_os_str().to_os_string();
        lock_path.push(".lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(PathBuf::from(lock_path))
            .ok()?;
        let locked = if exclusive {
            file.lock_exclusive()
        } else {
            file.lock_shared()
        };
        if locked.is_err() {
            return None; // 拿不到锁：退化为无锁（rename 原子性仍保证读到完整文件）
        }
        Some(BookLock(file))
    }
}
