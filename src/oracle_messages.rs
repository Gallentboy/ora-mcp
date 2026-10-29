//! Oracle 错误消息全量中文译文（19c，20362 条）——构建期嵌入、零堆分配的
//! 稀疏查找。迁移自 veloterm（两项目共用同一份 assets 数据源）。
//!
//! ## 数据来源与性质
//!
//! 数据由 `assets/oracle-errors/zh-CN.json` 在构建期压成 blob + 索引两个
//! 二进制（见 `build.rs::build_oracle_error_table`）。内容是 **Oracle 19c
//! 英文错误消息的机器辅助中文翻译，非 Oracle 官方译文**——Oracle 官方文档站
//! 不提供中文错误消息（实测 zh-cn/zh/cn/zhs 四种 locale 路径均 404）。
//!
//! ## 内存特性（设计目标）
//!
//! `BLOB`（约 3.6 MB）与 `INDEX`（约 198 KB）经 `include_bytes!` 落在可执行
//! 文件的只读段，按需分页：查一条错误只触达二分路径上的少量索引元素与该条
//! 的 blob 字节，**堆分配为零**（返回借用切片）。不建 HashMap、不做缓存。
//!
//! ## 布局
//!
//! - `BLOB`：每条 = `message \x1f cause \x1f action`（UTF-8 首尾相接）
//! - `INDEX`：每条 10 字节小端 —— `u16 code / u32 offset / u32 len`，按 code 升序
//!
//! 分隔符 `\x1f`（ASCII Unit Separator）在构建期已校验不与数据冲突。

/// 全部译文（`message \x1f cause \x1f action` 首尾相接）
static BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/oracle_errors.blob"));
/// 定长索引（10 字节/条：u16 code + u32 offset + u32 len，小端，按 code 升序）
static INDEX: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/oracle_errors.idx"));

/// 每条索引记录的字节宽度（u16 code + u32 offset + u32 len = 10）
const IDX_ENTRY: usize = 10;
/// 字段分隔符（ASCII Unit Separator）
const SEP: u8 = 0x1f;

/// 一条错误消息的三个可读字段（均借用静态数据，无分配）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OracleMessage<'a> {
    pub message: &'a str,
    pub cause: &'a str,
    pub action: &'a str,
}

/// 取索引第 `i` 条记录：(code, offset, len)；越界返回 None
fn idx_record(i: usize) -> Option<(u16, u32, u32)> {
    let start = i.checked_mul(IDX_ENTRY)?;
    let rec = INDEX.get(start..start.checked_add(IDX_ENTRY)?)?;
    match rec {
        [c0, c1, o0, o1, o2, o3, l0, l1, l2, l3] => Some((
            u16::from_le_bytes([*c0, *c1]),
            u32::from_le_bytes([*o0, *o1, *o2, *o3]),
            u32::from_le_bytes([*l0, *l1, *l2, *l3]),
        )),
        _ => None,
    }
}

/// 查一条 Oracle 错误消息（`code` 为 ORA 后面的数字，如 ORA-00942 → 942）。
///
/// 未收录返回 `None`——调用方应回落到 `oracle_ora_hint` 的精简中文摘要表
///（该表只有 80 条，覆盖最高频场景）。
///
/// 复杂度：二分 log2(20362) ≈ 15 次比较；命中后一次切片 + 两次分隔符切分，
/// 全程零分配。
pub fn lookup(code: u16) -> Option<OracleMessage<'static>> {
    let count = INDEX.len() / IDX_ENTRY;
    if count == 0 {
        return None;
    }

    // 手写二分：索引是定长字节数组，直接按偏移取 code 比较（不物化结构体）
    let mut lo = 0usize;
    let mut hi = count;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let (mid_code, _, _) = idx_record(mid)?;
        if mid_code < code {
            lo = mid + 1;
        } else if mid_code > code {
            hi = mid;
        } else {
            return slice_entry(mid);
        }
    }
    None
}

/// 从索引第 `i` 条取出一条记录并切分 blob
fn slice_entry(i: usize) -> Option<OracleMessage<'static>> {
    let (_, off, len) = idx_record(i)?;
    let off = off as usize;
    let len = len as usize;

    let end = off.checked_add(len)?;
    let entry = BLOB.get(off..end)?;

    // 三段切分：splitn 不分配，from_utf8 借用
    let mut parts = entry.splitn(3, |b| *b == SEP);
    let message = std::str::from_utf8(parts.next()?).ok()?;
    let cause = std::str::from_utf8(parts.next()?).ok()?;
    let action = std::str::from_utf8(parts.next()?).ok()?;
    Some(OracleMessage {
        message,
        cause,
        action,
    })
}

/// 供测试与诊断：返回 (条目数, blob 字节数)
#[cfg(test)]
pub fn stats() -> (usize, usize) {
    (INDEX.len() / IDX_ENTRY, BLOB.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 全部索引记录的 code（按索引顺序），供测试断言用
    fn all_codes() -> Vec<u16> {
        let count = INDEX.len() / IDX_ENTRY;
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            if let Some((c, _, _)) = idx_record(i) {
                out.push(c);
            }
        }
        out
    }

    /// 数据规模锚定：条目数与 blob 尺寸（构建期生成的资产若被截断/替换，
    /// 这里第一时间失败）
    #[test]
    fn stats_match_expected_scale() {
        let (count, blob_len) = stats();
        assert_eq!(count, 20362, "条目数应为 19c 全量 ORA 错误数");
        // 中文译文纯文本约 3.59 MB（三个字段 + 分隔符）；给宽松区间，
        // 容忍翻译微调带来的少量增减
        assert!(
            (3_400_000..3_900_000).contains(&blob_len),
            "blob 字节数异常: {blob_len}"
        );
    }

    /// 高频码命中：四字段齐全、内容为中文
    #[test]
    fn lookup_common_codes() {
        // ORA-00942: table or view does not exist
        let m = lookup(942).expect("ORA-00942 应被收录");
        assert_eq!(m.message, "表或视图不存在");
        assert!(!m.cause.is_empty(), "cause 不应为空");
        assert!(!m.action.is_empty(), "action 不应为空");
        assert!(m
            .cause
            .chars()
            .any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)));

        // ORA-00001: unique constraint violated
        let m = lookup(1).expect("ORA-00001 应被收录");
        assert!(m.message.contains("唯一约束"));
    }

    /// 边界：首条（ORA-00000）与末条（ORA-65535）
    #[test]
    fn lookup_boundaries() {
        let first = lookup(0).expect("ORA-00000 应被收录");
        assert!(!first.message.is_empty());
        let last = lookup(65535).expect("ORA-65535 应被收录");
        assert!(!last.message.is_empty());
    }

    /// 未收录的号返回 None（不能误命中邻近条目）
    #[test]
    fn lookup_missing_code_returns_none() {
        let codes = all_codes();
        let hole = (0u16..=u16::MAX)
            .find(|c| codes.binary_search(c).is_err())
            .expect("应存在未收录的号");
        assert!(lookup(hole).is_none(), "ORA-{hole:05} 不该命中");
    }

    /// 索引严格升序（二分前提）且无重复
    #[test]
    fn index_is_strictly_ascending() {
        let codes = all_codes();
        assert_eq!(codes.len(), stats().0, "索引条数与 stats 不符");
        for w in codes.windows(2) {
            if let [a, b] = w {
                assert!(a < b, "索引非严格升序：ORA-{a:05} 之后是 ORA-{b:05}");
            }
        }
    }

    /// 抽样验证三段切分干净：无残留分隔符、均为合法 UTF-8、区间自洽
    #[test]
    fn sampled_entries_are_well_formed() {
        let (count, blob_len) = stats();
        let step = (count / 100).max(1);
        let mut checked = 0;
        for i in (0..count).step_by(step) {
            let Some((code, _, _)) = idx_record(i) else {
                continue;
            };
            let m = lookup(code).expect("索引里的 code 应可查回");
            for field in [m.message, m.cause, m.action] {
                assert!(
                    !field.as_bytes().contains(&SEP),
                    "ORA-{code:05} 字段含残留分隔符"
                );
            }
            checked += 1;
        }
        assert!(checked >= 90, "抽样数偏少: {checked}");

        // 索引末条必须精确覆盖到 blob 末尾（否则说明有字节未被索引）
        let last = count.saturating_sub(1);
        let (_, off, len) = idx_record(last).expect("末条索引");
        assert_eq!(
            off as usize + len as usize,
            blob_len,
            "索引未覆盖到 blob 末尾"
        );
    }
}
