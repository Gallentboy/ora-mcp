# ora-mcp

纯 Rust 编写的 Oracle 数据库 MCP 服务器（Model Context Protocol），为大模型（Claude Desktop、Cursor、Cline、ZCode 等）提供轻量、快速、开箱即用的 Oracle 数据库操作能力。

- **零依赖与单二进制**：纯 Rust 原生实现 TNS/TTC 协议，**无需安装 Java 运行时，无需安装 Oracle Instant Client（无 C 动态库依赖）**，编译产物仅一个独立二进制文件。
- **协议层**：基于官方 [rmcp](https://crates.io/crates/rmcp) 3.8 规范（stdio 传输）。
- **连接池与高可用**：基于 [deadpool](https://crates.io/crates/deadpool) 0.13 managed 连接池，自带**断线自动换新重试**（最多 3 次）、**60 秒心跳保活**、以及 `connect` 工具的**幂等测活复用**。
- **ORA 中文智能翻译**：内置 19c 全量 20362 条错误译文 + 87 条精简兜底；当服务器未安装消息文件报 `Message NNN not found` 时，自动重组为中文三段式（消息/原因/建议）并将服务器真实参数按占位符注入还原。

---

## 工具清单（11 个）

| 工具 | 说明 |
|---|---|
| `connections_list` | 列出已保存的命名连接（密码永不返回），支持名称子串过滤 |
| `add_connection` | **运行时新增连接并落盘**：传入连接串（如 `hr/hr@host:1521/service`）自动解析并注册，立即测活；重复一律拒绝（同名或相同的 user/host/port/service 均阻断） |
| `connect` | 按名称连接数据库，返回版本 banner 上下文；自带**幂等测活复用**，已连接且健康时直接复用不重建池 |
| `disconnect` | 断开当前会话（关闭连接池） |
| `connection_stats` | **查询连接与池状态**：同时汇报客户端池指标（容量上限、已建连接、空闲、在用、排队数）与 Oracle 服务端会话指标（用户会话数、全库活跃会话数、全库总会话数） |
| `query` | 只读查询（SELECT/WITH），带行数上限保护、NUMBER 精度无损转换、大文本/二进制截断保护 |
| `execute_sql` | 执行 DDL、DML、匿名 PL/SQL 块（自动提交事务）；程序单元编译自动精准定位该对象的 `USER_ERRORS` |
| `execute_sql_file` | **执行 SQL 脚本文件**（等价于控制台 `@file.sql`）：自动识别分号与 PL/SQL 独立行 `/` 终结符、支持 UTF-8 与 GBK 编码自动回退、逐条提交并报告详细执行/失败统计 |
| `list_objects` | 列出当前用户对象（TABLE, VIEW, PROCEDURE, FUNCTION, SEQUENCE），支持 LIKE 模式过滤 |
| `get_ddl` | 通过 `DBMS_METADATA.GET_DDL` 提取对象的完整 CREATE DDL |
| `explain_plan` | 执行 `EXPLAIN PLAN FOR` 并通过 `DBMS_XPLAN.DISPLAY` 输出格式化执行计划（BASIC/TYPICAL/ALL） |

---

## 配置与持久化

连接配置默认存储在二进制同级目录的混淆文件中：`<二进制所在目录>/.connections`。
- 采用魔数 `ORAMCP2` + 16 字节随机盐 + SHA-256 密钥流 XOR 混淆（`chmod 600` 仅当前 OS 用户可读），避免密码直接明文可见。
- **多进程并发安全**：写入由 `.connections.lock` 文件锁（flock）保护，锁内重读磁盘最新数据，保证多个并发客户端会话不覆盖更新。
- 密码也可不在文件中存储：由环境变量 `ORA_MCP_PASSWORD_<连接名大写>`（或兼容的 `SQLCL_MCP_PASSWORD_<连接名大写>`）提供。

---

## 客户端接入示例（stdio）

在任何支持 MCP 协议的客户端中添加：

```json
{
  "mcpServers": {
    "ora-mcp": {
      "command": "/path/to/ora-mcp",
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}
```

> **使用技巧**：无需手动编辑配置文件！在对话中直接告诉 AI：“帮我连上 `scott/tiger@dbhost.example.com:1521/ORCLPDB1`”，AI 会调用 `add_connection` 自动完成注册、测活与持久化。

---

## 构建与运行

```sh
# 调试构建
cargo build

# 优化发布构建
cargo build --release

# 静态代码检查（严格强制禁用 stdout print 宏，保护 JSON-RPC 协议通道）
cargo clippy
```

**macOS ARM64 部署注意**：如果复制二进制到 `/usr/local/bin` 等目录，受 macOS AMFI 签名机制影响需要重新签名：
```sh
cp target/release/ora-mcp /usr/local/bin/ && codesign --force --sign - /usr/local/bin/ora-mcp
```

---

## 日志

采用 `tracing` 双通道输出：
- **stderr**：终端调试与客户端实时捕获；
- **滚动文件**：自动在 `<二进制所在目录>/mcp.log.YYYY-MM-DD` 按天非阻塞滚动落盘，每行附带进程 `[PID]`，方便多进程会话排查；
- 日志级别由 `RUST_LOG` 环境变量控制（默认 `info`）。

---

## 致谢（Credits）

- 本项目的底层网络通信与密码加解密握手实现，参考并启发自优秀的开源项目 **[go-ora](https://github.com/sijms/go-ora)**（MIT License），向原作者 Sijms 致敬！
- 协议层基于官方 **[rmcp](https://crates.io/crates/rmcp)** SDK。

---

## 免责声明（Disclaimer）

- 本项目为一个独立开发的纯 Rust 开源项目，**非 Oracle Corporation 官方产品**，亦与 Oracle 官方没有任何隶属、认可或商业合作关系。
- Oracle 及相关产品标识均为其各自商标持有人的注册商标。
- 本项目按 MIT 或 Apache-2.0 协议开源，仅供学习、测试与工程集成使用。
