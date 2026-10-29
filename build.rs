//! 构建脚本：Oracle 错误消息表（19c 全量中文译文）构建期编译进二进制。
//!
//! 把 assets/oracle-errors/zh-CN.json 压成「blob + 定长索引」两个二进制，
//! 运行期经 include_bytes! 嵌入 .rodata，按需分页（稀疏查询只触达被查的
//! 那几条，堆分配为零）。
//!
//! blob 布局：每条 = `message \x1f cause \x1f action`（UTF-8），首尾相接。
//! idx 布局：每条 10 字节小端 —— u16 code / u32 offset / u32 len，按 code 升序。
//!
//! 校验全部硬失败（fail → 构建中断）：数据被改坏时宁可编不过，
//! 也不要运行时查出错误的中文解释。
//!
//! 迁移自 veloterm build.rs（两项目共用同一份数据源）。

fn main() {
    build_oracle_error_table();
}

/// 构建期硬失败：打印诊断并终止构建。
fn fail(msg: String) -> ! {
    use std::io::Write;
    let _ = std::io::stderr().write_all(msg.as_bytes());
    let _ = std::io::stderr().write_all(b"\n");
    std::process::exit(1);
}

fn build_oracle_error_table() {
    use std::fmt::Write as _;

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let src = std::path::Path::new(&manifest_dir)
        .join("assets")
        .join("oracle-errors")
        .join("zh-CN.json");
    println!("cargo:rerun-if-changed={}", src.display());

    let text = match std::fs::read_to_string(&src) {
        Ok(t) => t,
        Err(e) => fail(format!(
            "[oracle-errors] 数据文件读取失败: {} ({e})",
            src.display()
        )),
    };

    // 只取 entries 数组：_meta 仅作文档用途
    let doc: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => fail(format!(
            "[oracle-errors] JSON 解析失败: {e}\n  文件: {}",
            src.display()
        )),
    };
    let Some(arr) = doc.get("entries").and_then(|v| v.as_array()) else {
        fail("[oracle-errors] 缺少 entries 数组".to_string());
    };
    // _meta.entry_count 与实际条数必须一致（数据被截断/替换的早期信号）
    if let Some(declared) = doc
        .get("_meta")
        .and_then(|m| m.get("entry_count"))
        .and_then(|v| v.as_u64())
    {
        if declared as usize != arr.len() {
            fail(format!(
                "[oracle-errors] _meta.entry_count({declared}) 与实际条数({}) 不符",
                arr.len()
            ));
        }
    }
    let mut entries: Vec<(String, String, String, String)> = Vec::with_capacity(arr.len());
    for e in arr {
        let mut fields = ["", "", "", ""];
        for (slot, key) in fields.iter_mut().zip(["code", "message", "cause", "action"]) {
            match e.get(key).and_then(|v| v.as_str()) {
                Some(v) => *slot = v,
                None => fail(format!("[oracle-errors] 条目缺字段 {key}: {e:?}")),
            }
        }
        let [code, message, cause, action] = fields;
        entries.push((
            code.to_string(),
            message.to_string(),
            cause.to_string(),
            action.to_string(),
        ));
    }
    if entries.is_empty() {
        fail("[oracle-errors] entries 解析为空：JSON 结构可能变了".to_string());
    }

    // 按 code 数值升序（二分查找前提）
    let mut rows: Vec<(u16, String, String, String)> = Vec::with_capacity(entries.len());
    for (code, msg, cause, action) in entries {
        let num: u32 = match code.strip_prefix("ORA-").and_then(|n| n.parse().ok()) {
            Some(n) => n,
            None => fail(format!("[oracle-errors] 非法错误码格式: {code}")),
        };
        if num > u16::MAX as u32 {
            fail(format!("[oracle-errors] 错误码超出 u16 范围: {code}"));
        }
        rows.push((num as u16, msg, cause, action));
    }
    rows.sort_by_key(|r| r.0);

    // 去重校验：重复 code 会让二分结果不确定
    for w in rows.windows(2) {
        if let [a, b] = w {
            if a.0 == b.0 {
                fail(format!("[oracle-errors] 重复错误码: ORA-{:05}", a.0));
            }
        }
    }

    // 组装 blob + idx（每条 10 字节：u16 code + u32 offset + u32 len）
    let mut blob: Vec<u8> = Vec::with_capacity(5 * 1024 * 1024);
    let mut idx: Vec<u8> = Vec::with_capacity(rows.len() * 10);
    for (code, msg, cause, action) in &rows {
        // 分隔符冲突校验：字段内出现 \x1f 会让三段切分错位
        for (name, field) in [("message", msg), ("cause", cause), ("action", action)] {
            if field.as_bytes().contains(&0x1f) {
                fail(format!(
                    "[oracle-errors] ORA-{code:05} 的 {name} 含分隔符 \\x1f"
                ));
            }
        }
        let start = blob.len() as u32;
        blob.extend_from_slice(msg.as_bytes());
        blob.push(0x1f);
        blob.extend_from_slice(cause.as_bytes());
        blob.push(0x1f);
        blob.extend_from_slice(action.as_bytes());
        let len = blob.len() as u32 - start;
        idx.extend_from_slice(&code.to_le_bytes());
        idx.extend_from_slice(&start.to_le_bytes());
        idx.extend_from_slice(&len.to_le_bytes());
    }

    // 自洽校验：idx 条数 × 10 == idx 字节数；末条 off+len == blob 长度
    if idx.len() != rows.len() * 10 {
        fail(format!(
            "[oracle-errors] 索引长度({})与条目数({})不符",
            idx.len(),
            rows.len()
        ));
    }
    let tail = match idx.len().checked_sub(8).and_then(|n| idx.get(n..)) {
        Some(t) => t,
        None => fail("[oracle-errors] 索引过短".to_string()),
    };
    let (tail_off, tail_len) = match tail {
        [a, b, c, d, e, f, g, h] => (
            u32::from_le_bytes([*a, *b, *c, *d]) as usize,
            u32::from_le_bytes([*e, *f, *g, *h]) as usize,
        ),
        _ => fail("[oracle-errors] 索引尾部残缺".to_string()),
    };
    if tail_off + tail_len != blob.len() {
        fail(format!(
            "[oracle-errors] 末条区间({}..{})未覆盖到 blob 末尾({})",
            tail_off,
            tail_off + tail_len,
            blob.len()
        ));
    }

    let out_dir = match std::env::var("OUT_DIR") {
        Ok(v) => v,
        Err(e) => fail(format!("[oracle-errors] 读不到 OUT_DIR: {e}")),
    };
    let out = std::path::Path::new(&out_dir);
    if let Err(e) = std::fs::write(out.join("oracle_errors.blob"), &blob) {
        fail(format!("[oracle-errors] blob 写入失败: {e}"));
    }
    if let Err(e) = std::fs::write(out.join("oracle_errors.idx"), &idx) {
        fail(format!("[oracle-errors] idx 写入失败: {e}"));
    }

    let mut note = String::new();
    let _ = write!(
        note,
        "[oracle-errors] {} 条 · blob {} KB · idx {} KB",
        rows.len(),
        blob.len() / 1024,
        idx.len() / 1024
    );
    println!("cargo:warning={note}");
}
