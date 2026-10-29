//! ORA 错误码中文文案组装：19c 全量译文表（oracle_messages）优先，
//! 未收录回落 87 条精简摘要表；「缺消息文件」形态（服务器无 .msb，
//! 报 `Message NNN not found; No message file...`）重组为可读中文。
//! 迁移自 veloterm oracle_engine.rs（两项目 ORA 语义一致，按需同步）。

use crate::oracle_messages;

/// 错误码的完整中文解释：优先查 19c 全量译文表（含 message/cause/action），
/// 未收录时回落精简摘要表（一句话说明）。
#[derive(Debug, Clone, Copy)]
pub(crate) struct OracleErrorText {
    /// 错误消息本身（如「表或视图不存在」）
    pub message: &'static str,
    /// 原因说明（全量表才有；精简表恒为空）
    pub cause: &'static str,
    /// 处理建议（全量表才有；精简表恒为空）
    pub action: &'static str,
}

/// 查错误码的中文解释：全量表 → 精简表 → None。
#[inline]
pub(crate) fn oracle_error_text(code: i32) -> Option<OracleErrorText> {
    if let Ok(small) = u16::try_from(code) {
        if let Some(m) = oracle_messages::lookup(small) {
            return Some(OracleErrorText {
                message: m.message,
                cause: m.cause,
                action: m.action,
            });
        }
    }
    oracle_ora_hint(code).map(|hint| OracleErrorText {
        message: hint,
        cause: "",
        action: "",
    })
}

/// 把中文解释组装成结构化多行：消息（占位符已替换实参）/ 原因 / 处理建议 /
/// 残余实参（占位符耗尽后剩下的 arguments，仍具定位价值）。
fn format_error_text(code: i32, text: &OracleErrorText, args: &[String]) -> String {
    let (message, rest) = substitute_placeholders(text.message, args);
    let mut out = format!("ORA-{code:05}：{message}");
    if !text.cause.is_empty() {
        out.push_str("\n原因：");
        out.push_str(text.cause);
    }
    if !text.action.is_empty() {
        out.push_str("\n处理建议：");
        out.push_str(text.action);
    }
    if !rest.is_empty() {
        out.push_str(&format!("（其余参数：{}）", rest.join("、")));
    }
    out
}

/// 把译文里的占位符替换为服务器实参。
///
/// 数据源的机器翻译把 Oracle 原文的 `%s` 写成了字面 "string"
///（6274 条，如 ORA-00001 `违反了唯一约束 (string.string)`）；而服务器的
/// arguments 数组恰好按占位符出现顺序传回实参——按洞逐个填入即可还原
/// 真实消息（如 `(AP_FAP.TAP_PK)`）。洞多于实参时剩余洞保留 "string" 原样
///（说明服务器没传全）；实参多于洞时剩余实参由调用方追加，不丢信息。
fn substitute_placeholders(message: &str, args: &[String]) -> (String, Vec<String>) {
    let mut rest = args.iter();
    let mut out = String::with_capacity(message.len());
    let mut parts = message.split("string");
    if let Some(first) = parts.next() {
        out.push_str(first);
    }
    for part in parts {
        match rest.next() {
            Some(arg) => out.push_str(arg),
            None => out.push_str("string"),
        }
        out.push_str(part);
    }
    (out, rest.cloned().collect())
}

/// 服务器错误（ORA 码 + 原文）→ 展示文案。
pub(crate) fn server_text(code: i32, raw: &str) -> String {
    let text = oracle_error_text(code);
    // 「缺消息文件」形态：服务器文案本身没有信息量，换成内置中文文案
    if raw.contains("No message file") || raw.contains("not found;") {
        let args = extract_error_arguments(raw);
        return match text {
            Some(t) => format_error_text(code, &t, &args),
            None => {
                let extra = if args.is_empty() {
                    String::new()
                } else {
                    format!("（相关参数：{}）", args.join("、"))
                };
                format!("ORA-{code:05}：详见 Oracle 官方错误文档{extra}")
            }
        };
    }
    match text {
        // 服务器原文可读：原文一行 + 中文解释（避免原文已含该中文时重复）
        Some(t) if !raw.contains(t.message) => {
            let mut out = format!("ORA-{code:05}: {raw}");
            out.push_str("\n中文：");
            out.push_str(t.message);
            if !t.cause.is_empty() {
                out.push_str("\n原因：");
                out.push_str(t.cause);
            }
            if !t.action.is_empty() {
                out.push_str("\n处理建议：");
                out.push_str(t.action);
            }
            out
        }
        _ => {
            if raw.is_empty() {
                format!("ORA-{code:05}")
            } else if raw.starts_with("ORA-") {
                raw.to_string()
            } else {
                format!("ORA-{code:05}: {raw}")
            }
        }
    }
}

/// 无结构化码的错误文本（如监听器拒绝串）→ 嗅探 ORA-xxxxx 接中文码表。
pub(crate) fn sniff(msg: &str) -> String {
    if let Some(pos) = msg.find("ORA-") {
        let code_str = &msg[pos + 4..];
        let digits: String = code_str
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Ok(code) = digits.parse::<i32>() {
            if let Some(text) = oracle_error_text(code) {
                if msg.contains("No message file") {
                    return format_error_text(code, &text, &[]);
                }
                let mut out = msg.to_string();
                out.push_str("\n中文：");
                out.push_str(text.message);
                if !text.cause.is_empty() {
                    out.push_str("\n原因：");
                    out.push_str(text.cause);
                }
                if !text.action.is_empty() {
                    out.push_str("\n处理建议：");
                    out.push_str(text.action);
                }
                return out;
            }
        }
    }
    msg.to_string()
}

/// 从 OCI 错误文案里提取 `arguments: ["X", "Y"]` 段（剥引号）——缺消息文件时
/// 这段是仅存的真实定位信息（出错标识符、类型名等），并用于占位符替换。
fn extract_error_arguments(raw: &str) -> Vec<String> {
    let Some(start) = raw.find("arguments: [") else {
        return Vec::new();
    };
    let rest = &raw[start + "arguments: [".len()..];
    let Some(end) = rest.find(']') else {
        return Vec::new();
    };
    rest[..end]
        .split(',')
        .map(|a| a.trim().trim_matches('"').to_string())
        .filter(|a| !a.is_empty())
        .collect()
}

/// 常见 ORA 错误码内置文案（覆盖连接/认证/SQL 执行/DDL/PLSQL 高频路径）。
/// go-ora 的 translate() 只兜 16 个码、其余仅回 `ORA-xxxxx`；本表更宽，
/// 缺消息文件的服务器（OCI 形态最常见）也能给出可读中文。
/// 未收录的码在 oracle_err 里回落为纯码，不会误导。
#[inline(always)]
fn oracle_ora_hint(code: i32) -> Option<&'static str> {
    Some(match code {
        // 约束 / 数据完整性
        1 => "违反唯一约束",
        2290 => "违反检查约束（值不满足 CHECK 条件）",
        2291 => "违反完整性约束（引用的父记录不存在）",
        2292 => "违反完整性约束（存在引用该行的子记录）",
        1400 => "无法插入 NULL（非空列缺值）",
        1438 => "列值超出精度/小数位上限",
        1722 => "无效数字（字符串转数字失败或溢出）",
        1843 => "日期格式与 NLS_DATE_FORMAT 不匹配",
        1858 => "日期时间字段无效（如 2 月 30 日）",
        12899 => "列值过大（超出字段长度）",
        // SQL 语法 / 语义
        900 => "无效的 SQL 语句",
        904 => "标识符无效（列名/别名拼写错误，或该列在当前版本不存在）",
        905 => "关键字拼写错误",
        906 => "缺少左括号",
        907 => "缺少右括号",
        909 => "缺少 FROM 关键字",
        911 => "无效字符（常见：多余分号或中文标点）",
        917 => "无效的 SQL 语句（常见：列数与值数不匹配）",
        918 => "列名有歧义（多表同名列未限定）",
        920 => "无效的关系运算符",
        923 => "未找到 FROM 关键字（常见：SELECT 列表缺逗号）",
        926 => "缺少 INTO 关键字",
        933 => "SQL 命令未正确结束（常见：末尾多余分号）",
        934 => "绑定变量未声明",
        936 => "缺少表达式",
        937 => "表达式类型不匹配",
        942 => "表或视图不存在（检查 schema 前缀与权限）",
        947 => "SELECT 列表表达式个数不匹配",
        949 => "VALUES 子句列数不匹配",
        956 => "缺少 GROUP BY 表达式",
        979 => "违反唯一约束（另一用户已在同一行上修改）",
        1008 => "未找到该表（可能已被删除或无权访问）",
        1017 => "用户名或密码无效",
        1031 => "权限不足（缺少对应对象的访问权限）",
        1033 => "Oracle 正在启动或关闭中",
        1034 => "Oracle 不可用（实例未启动）",
        1045 => "用户缺少 CREATE SESSION 权限",
        1064 => "会话被终止（KILL SESSION）",
        1092 => "等待资源超时（表被锁）",
        1093 => "会话被其它会话等待（死锁）",
        1403 => "未找到数据（NO_DATA_FOUND）",
        1422 => "精度过高（数值超出声明精度）",
        1476 => "除数等于零",
        1652 => "表空间不足（无法扩展）",
        1654 => "无法扩展表空间",
        1756 => "表空间或数据文件不存在",
        24381 => "数组批量操作中部分行出错",
        28000 => "账户已被锁定",
        28001 => "密码已过期",
        28002 => "密码即将过期",
        28040 => "登录失败（协议或凭据协商失败）",
        28041 => "认证协议内部错误",
        28045 => "要求的认证服务不可用",
        // 会话 / 游标 / 通信
        1001 => "无效的游标（游标已关闭或已取尽）",
        1002 => "取数越界（fetch out of sequence，游标状态已失效）",
        1013 => "用户取消操作",
        3113 => "通信通道文件结束（连接被服务端断开）",
        3114 => "未连接到 Oracle",
        3115 => "通信通道未打开",
        3135 => "连接丢失（connection lost contact）",
        12152 => "Oracle 服务器挂断连接（可能被防火墙/超时切断）",
        12154 => "无法解析连接标识符（检查服务名）",
        12170 => "连接超时",
        12203 => "TNS 无法连接目标",
        12206 => "TNS 未找到可用的监听器",
        12506 => "监听器基于服务 ACL 拒绝了连接",
        12528 => "TNS 监听器拒绝了连接（服务受限）",
        12505 => "监听器不认识该 SID/服务（检查服务名）",
        12514 => "监听器当前不认识请求的服务（检查服务名是否正确）",
        12516 => "监听器无可用处理器（实例进程数已满）",
        12541 => "无监听器（目标端口未监听）",
        12543 => "目标主机不可达",
        12545 => "连接失败（目标主机不存在）",
        12560 => "TNS 协议适配器错误（服务器端问题）",
        12571 => "TNS 包写入器失败（连接中断）",
        12631 => "用户名检索失败（外部认证）",
        // PL/SQL / 过程
        20000 => "自定义应用错误（RAISE_APPLICATION_ERROR）",
        6502 => "PL/SQL 数字或值错误（溢出/精度）",
        6508 => "PL/SQL 遇到未处理的异常",
        6510 => "PL/SQL 编译错误（检查过程和函数体）",
        6511 => "PL/SQL 编译单元分析错误",
        6531 => "PL/SQL 参数个数或类型不匹配",
        6533 => "PL/SQL 编译错误（符号未声明）",
        6550 => "PL/SQL 内部错误",
        6553 => "PL/SQL 无法在只读事务中执行 DML",
        20001 => "自定义应用错误（RAISE_APPLICATION_ERROR 自定义码）",
        _ => return None,
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    /// 用户实际遇到的形态：服务器无消息文件，ORA-00904 只剩占位文案 + 标识符参数。
    /// 重组后必须给出中文解释并带上出错的标识符。
    #[test]
    fn no_message_file_form_gets_chinese_text_with_args() {
        let out = server_text(
            904,
            "Message 904 not found; No message file for product=RDBMS, facility=ORA; arguments: [\"TABLE_NAME\"]",
        );
        assert!(out.starts_with("ORA-00904"), "got: {out}");
        assert!(out.contains("标识符无效"), "got: {out}");
        assert!(out.contains("TABLE_NAME"), "got: {out}");
    }

    /// 占位符替换：机器翻译把 %s 写成了字面 string，实参须按洞填入。
    /// ORA-00932 双占位符（expected/got），ORA-00001 双占位符相邻（schema.obj）。
    #[test]
    fn placeholders_are_substituted_with_arguments() {
        let out = server_text(
            932,
            "Message 932 not found; No message file; arguments: [\"CHAR\", \"NUMBER\"]",
        );
        assert!(out.contains("应为 CHAR，却得到 NUMBER"), "got: {out}");
        // 替换成功后不应再出现字面 string，也不该重复追加参数
        assert!(!out.contains("应为 string"), "got: {out}");

        let out = server_text(
            1,
            "Message 1 not found; No message file; arguments: [\"AP_FAP\", \"TAP_PK\"]",
        );
        assert!(out.contains("(AP_FAP.TAP_PK)"), "got: {out}");
    }

    /// 实参多于占位符：填完后剩余实参追加，不丢信息。
    #[test]
    fn extra_arguments_are_appended() {
        let out = server_text(
            932,
            "Message 932 not found; No message file; arguments: [\"CHAR\", \"NUMBER\", \"EXTRA\"]",
        );
        assert!(out.contains("应为 CHAR，却得到 NUMBER"), "got: {out}");
        assert!(out.contains("EXTRA"), "got: {out}");
    }

    /// 服务器原文可读（如 JDBC/正常库）：保留原文 + 追加中文解释。
    #[test]
    fn readable_server_text_appends_chinese() {
        let out = server_text(942, "table or view does not exist");
        assert!(out.contains("ORA-00942: table or view does not exist"));
        assert!(out.contains("中文："));
    }

    /// 未收录码回落：给码 + 提示，不误导。
    #[test]
    fn unknown_code_falls_back_gracefully() {
        let out = server_text(99999, "whatever");
        assert!(out.contains("ORA-99999"));
    }
}
