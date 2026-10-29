//! 专为 Oracle 脚本设计的 SQL 语句解析切分器。
//!
//! 支持真实世界中复杂的混合 Oracle SQL 脚本：
//! 1. 普通 DDL/DML 语句以分号 `;` 结尾
//! 2. PL/SQL 存储过程、函数、包、触发器、匿名块（`CREATE ... PROCEDURE` / `DECLARE` / `BEGIN` 等）
//!    以独立一行的 `/` 结尾，内部包含的业务分号不切断
//! 3. 严格跳过单引号字符串 `'...'`、双引号标识符 `"..."`、单行注释 `--` 和块注释 `/* ... */`
//! 4. 自动去除普通语句末尾的分号（避免 Oracle TTC 报 ORA-00911: 无效字符）

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptStatement {
    pub sql: String,
}

pub fn split_oracle_script(script: &str) -> Vec<ScriptStatement> {
    let mut stmts = Vec::new();
    let mut current = String::with_capacity(1024);

    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_block_comment = false;
    let mut in_line_comment = false;

    // 是否当前正在收集一个 PL/SQL 块（必须由独立行的 / 结束）
    let mut collecting_plsql = false;

    for line in script.lines() {
        let trimmed_line = line.trim();

        // 当在非引号、非块注释状态下，如果遇到了独立行的 /
        if !in_single_quote && !in_double_quote && !in_block_comment && trimmed_line == "/" {
            let stmt = current.trim();
            if !stmt.is_empty() {
                stmts.push(ScriptStatement {
                    sql: stmt.to_string(),
                });
                current.clear();
            }
            collecting_plsql = false;
            continue;
        }

        let chars: Vec<char> = line.chars().collect();
        let len = chars.len();
        let mut i = 0;

        while i < len {
            let c = chars[i];
            let next = if i + 1 < len { Some(chars[i + 1]) } else { None };

            if in_line_comment {
                i += 1;
                continue;
            }

            if in_block_comment {
                current.push(c);
                if c == '*' && next == Some('/') {
                    in_block_comment = false;
                    current.push('/');
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }

            if in_single_quote {
                current.push(c);
                if c == '\'' {
                    if next == Some('\'') {
                        current.push('\'');
                        i += 2;
                        continue;
                    } else {
                        in_single_quote = false;
                    }
                }
                i += 1;
                continue;
            }

            if in_double_quote {
                current.push(c);
                if c == '"' {
                    in_double_quote = false;
                }
                i += 1;
                continue;
            }

            // 检查进入注释或引号
            if c == '-' && next == Some('-') {
                in_line_comment = true;
                i += 2;
                continue;
            }
            if c == '/' && next == Some('*') {
                in_block_comment = true;
                current.push(c);
                current.push('*');
                i += 2;
                continue;
            }
            if c == '\'' {
                in_single_quote = true;
                current.push(c);
                i += 1;
                continue;
            }
            if c == '"' {
                in_double_quote = true;
                current.push(c);
                i += 1;
                continue;
            }

            // 如果当前还没确定是 PL/SQL，检查当前积累的字符是否触发了 PL/SQL 关键字
            if !collecting_plsql && is_plsql_prefix(&current) {
                collecting_plsql = true;
            }

            // 遇到分号
            if c == ';' {
                if collecting_plsql {
                    // PL/SQL 块内部的分号不切断
                    current.push(c);
                } else {
                    // 普通 SQL 分隔符
                    let stmt = current.trim();
                    if !stmt.is_empty() {
                        stmts.push(ScriptStatement {
                            sql: clean_sql_stmt(stmt),
                        });
                        current.clear();
                    }
                }
                i += 1;
                continue;
            }

            current.push(c);
            i += 1;
        }

        // 行结束，单行注释重置
        in_line_comment = false;
        current.push('\n');

        // 再次检查行尾状态是否触发了 PL/SQL
        if !collecting_plsql && is_plsql_prefix(&current) {
            collecting_plsql = true;
        }
    }

    // 处理文件末尾残留语句
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        if collecting_plsql {
            stmts.push(ScriptStatement {
                sql: trimmed.to_string(),
            });
        } else {
            let s = clean_sql_stmt(trimmed);
            if !s.is_empty() {
                stmts.push(ScriptStatement { sql: s });
            }
        }
    }

    stmts
}

/// 剥掉末尾的分号（Oracle 执行普通 SQL / DDL 时末尾带分号会报 ORA-00911）
fn clean_sql_stmt(sql: &str) -> String {
    let mut s = sql.trim();
    if s.ends_with(';') {
        s = s[..s.len() - 1].trim();
    }
    s.to_string()
}

/// 检查缓冲区里的 SQL 前缀是否是 PL/SQL 声明
fn is_plsql_prefix(sql: &str) -> bool {
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

    let first = match words.next() {
        Some(w) => w.to_ascii_uppercase(),
        None => return false,
    };

    if first == "DECLARE" || first == "BEGIN" {
        return true;
    }

    if first == "CREATE" {
        let mut second = words.next().map(|w| w.to_ascii_uppercase());
        if second.as_deref() == Some("OR") {
            let _ = words.next(); // "REPLACE"
            second = words.next().map(|w| w.to_ascii_uppercase());
        } else if second.as_deref() == Some("EDITIONABLE") || second.as_deref() == Some("NONEDITIONABLE") {
            let next_word = words.next().map(|w| w.to_ascii_uppercase());
            if next_word.as_deref() == Some("OR") {
                let _ = words.next(); // "REPLACE"
                second = words.next().map(|w| w.to_ascii_uppercase());
            } else {
                second = next_word;
            }
        }

        if let Some(sec) = second {
            return matches!(
                sec.as_str(),
                "PROCEDURE" | "FUNCTION" | "PACKAGE" | "TRIGGER" | "TYPE"
            );
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mixed_script_splitting() {
        let script = r#"
            -- 创建表
            CREATE TABLE demo_tab (
                id NUMBER,
                name VARCHAR2(100)
            );

            INSERT INTO demo_tab VALUES (1, 'Hello; World');
            INSERT INTO demo_tab VALUES (2, 'Foo /* bar */ baz');

            -- 创建存储过程
            CREATE OR REPLACE PROCEDURE my_proc IS
            BEGIN
                NULL;
            END;
            /

            -- 匿名块
            BEGIN
                UPDATE demo_tab SET name = 'Updated' WHERE id = 1;
            END;
            /

            SELECT * FROM demo_tab;
        "#;

        let stmts = split_oracle_script(script);
        assert_eq!(stmts.len(), 6);

        assert!(stmts[0].sql.starts_with("CREATE TABLE demo_tab"));
        assert!(!stmts[0].sql.ends_with(';'));

        assert!(stmts[1].sql.contains("'Hello; World'"));
        assert!(!stmts[1].sql.ends_with(';'));

        assert!(stmts[2].sql.contains("'Foo /* bar */ baz'"));
        assert!(!stmts[2].sql.ends_with(';'));

        // 存储过程保留完整体与内部的分号
        assert!(stmts[3].sql.starts_with("CREATE OR REPLACE PROCEDURE my_proc"));
        assert!(stmts[3].sql.ends_with("END;"));

        // 匿名块
        assert!(stmts[4].sql.starts_with("BEGIN"));
        assert!(stmts[4].sql.ends_with("END;"));

        // 最后的 select
        assert!(stmts[5].sql.starts_with("SELECT * FROM demo_tab"));
        assert!(!stmts[5].sql.ends_with(';'));
    }
}
