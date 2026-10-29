# ora_async

纯 Rust 原生异步 Oracle 客户端驱动（基于 Tokio），零 C/C++ 动态库依赖（无需 Oracle Instant Client / OCI / ODPI-C）。

> **实现与协议说明**：
> 协议通信流程与加解密握手参考自开源项目 **[sijms/go-ora](https://github.com/sijms/go-ora)**（MIT License），并在 Rust 异步所有权模型下进行了深度重构与健壮性修补：
> 1. **TTC 消息 19（服务端流控）误并入 case 11 解析**（`src/conn/routines/exec.rs` / `fetch.rs`）：`case 19` 是零载荷流控信号——客户端须**回写单字节 19 并继续读响应流**。原先合并解析在真机长 SQL / 含中文语句下会导致 TTC 流错位。已严格按规范修复流控回写。
> 2. **case 11 列数组合公式**（`exec.rs`）：列数计算为 `i2 低段 + i4 高段 × 0x100`，支持大于 255 列的宽结果集。
> 3. **命令级输入残留清理 / 防毒**（`conn/mod.rs` 等）：每条命令发起前执行 `send_request` 清空输入残留，避免解码异常后残留字节毒化后续会话。
> 4. **case 6（行块头）的列存在位图**（`row_common.rs::read_row_header` 等）：更新 `bit_vector` 状态，服务端省略 NULL 单元格时能够正确对齐列偏移（解决大批量 NULL 可空列错位问题）。


对标 `mysql_async` 的成熟架构设计，全面基于 **Tokio + `tokio_util::codec::Framed` + 异步 `Routine` 状态机** 实现 Oracle 专有的 **TNS（传输网络层）** 与 **TTC（双任务通用数据层）** 协议。

---

## 一、核心特性

1. **纯 Rust 实现（Pure Rust）**：
   - 零链接期与运行期 C 依赖（摆脱 `DPI-1047` 错误）。
   - 跨平台原生静态编译（macOS aarch64/x86_64, Windows, Linux musl）。
2. **现代 Oracle 身份认证**：
   - 支持 Oracle 12c+ (12.1/12.2/18c/19c/21c/23ai) 的 **PBKDF2-HMAC-SHA512** SpeedyKey 密钥拉伸 + **AES-256-CBC** 动态会话加密。
   - 向后兼容 11g（SHA-1 + AES-192）及 10g（O5Logon DES-CBC / MD5）。
3. **分层帧协议（TNS / TTC）**：
   - `TnsCodec` 帧管理，自动处理握手前后的 16-bit / 32-bit 大包 SDU 头切换（支持 64KB+ SDU）。
   - 自动处理多分片 DATA 包切片与拼接。
4. **强类型数据系统**：
   - 内部支持 Oracle 基数 100 浮点格式（`NUMBER`）向 `rust_decimal::Decimal`、`i64`、`f64` 转换。
   - 支持 `VARCHAR2`、`CHAR`、`NVARCHAR2`、`DATE`（7 字节）、`TIMESTAMP`（11 字节）、`TIMESTAMP WITH TIME ZONE`（13 字节）、`RAW`。
5. **分级清晰的日志系统**：
   - `trace`: 底层 TNS 原始报文十六进制分片、逐字节移动与 CLR Chunk 拆解。
   - `debug`: TNS 数据包头、TTC 协议交互字（Msg 1, 2, 3, 16, 7, 4）、协商能力位图、SCN 与 Session ID。
   - `info`: 连接建立、TNS Accept、用户认证成功（打印实例名/用户名/会话号）、连接池创建与归还。
   - `warn`: 收到 ORA 警告（Msg 15）、TNS 标记中断包、重定向回退、时区/字符集兜底。
   - `error`: 监听器拒连（ORA-12514 等）、密码校验失败（ORA-01017）、网络读写异常与协议格式违背。
6. **对标 `mysql_async` 异步设施**：
   - 包含异步连接池 `Pool` 与 `PooledConn`。
   - 支持 `Transaction` 事务生命周期（commit / rollback）。
   - 支持 `break_connection`（发送 TNS Marker 包异步取消长查询）。

---

## 二、架构设计与模块划分

```
oracle_async/
├── Cargo.toml
├── src/
│   ├── lib.rs                  // 顶层导出
│   ├── error.rs                // Error 与 OracleError (ORA-xxxxx)
│   ├── opts.rs                 // 连接参数构建器与 EZConnect URL 解析
│   ├── crypto/                 // 纯 Rust 加密算法库
│   │   ├── speedy_key.rs       // PBKDF2-HMAC-SHA512 SpeedyKey
│   │   ├── aes_cbc.rs          // AES-128/192/256-CBC (zero-IV / PKCS7)
│   │   └── o5logon.rs          // 10g/11g DES/MD5 兼容算法
│   ├── proto/                  // Oracle 线路数据结构
│   │   ├── tns_types.rs        // TNSType 枚举与标识
│   │   ├── caps.rs             // CompileCaps 与 RuntimeCaps 位图
│   │   ├── oracle_number.rs    // 基数 100 浮点高精度互转
│   │   └── oracle_date.rs      // 7/11/13 字节日期时区互转
│   ├── io/                     // 底层 I/O 与 Codec
│   │   ├── packet.rs           // TnsPacket 枚举与 Connect/Accept/Refuse 解析
│   │   ├── codec.rs            // TnsCodec: tokio_util::codec::Decoder / Encoder
│   │   ├── ttc_reader.rs       // TTC 二进制读取 (变长压缩整数/CLR/DLC/KeyVal)
│   │   └── ttc_writer.rs       // TTC 二进制构建与序列化
│   ├── conn/                   // 连接与协议 Routine 状态机
│   │   ├── mod.rs              // Conn 结构体与会话生命周期
│   │   ├── transaction.rs      // Transaction (commit/rollback)
│   │   ├── pool/               // 异步连接池 (Pool/PooledConn)
│   │   └── routines/           // 独立交互 Routine 状态机
│   │       ├── handshake.rs    // TNS Connect -> Accept
│   │       ├── ttc_nego.rs     // TTC MsgCode 1 协议协商
│   │       ├── data_type_nego.rs // TTC MsgCode 2 数据类型协商
│   │       ├── auth.rs         // TTCOAUTH 动态密钥认证
│   │       ├── exec.rs         // TTCOEXEC 执行与结果集描述
│   │       ├── fetch.rs        // 分批游标行抓取
│   │       └── ping.rs         // 心跳探活
│   └── queryable/              // 高级接口
│       ├── values.rs           // OracleValue 与 FromValue
│       ├── row.rs              // ColumnMeta 与 Row
│       ├── query_result.rs     // 惰性迭代结果集 QueryResult
│       └── mod.rs              // Queryable trait
└── tests/
    ├── crypto_tests.rs         // 密码学算法回归测试
    ├── proto_tests.rs          // 核心类型与 Number/Date 编解码测试
    └── codec_and_packet_tests.rs // TNS Codec 帧切分与封包测试
```

---

## 三、快速上手示例

### 1. 建立连接与执行查询

```rust
use ora_async::{Conn, Opts, Queryable, Row};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 支持标准 URL 格式或 OptsBuilder
    let opts = Opts::from_url("oracle://scott:tiger@localhost:1521/XEPDB1")?;
    let mut conn = Conn::connect(opts).await?;

    println!("Connected to Oracle: {}", conn.server_version());

    // 流式查询
    let mut result = conn.query("SELECT banner FROM v$version").await?;
    while let Some(row) = result.next_row().await? {
        let banner: String = row.get(0)?;
        println!("Banner: {banner}");
    }

    Ok(())
}
```

### 2. 使用连接池（Pool）

```rust
use ora_async::{Pool, Opts, Queryable};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = Opts::from_url("oracle://scott:tiger@localhost:1521/XEPDB1")?;
    let pool = Pool::with_max_conns(opts, 10);

    // 从池中租借连接
    let mut conn = pool.get_conn().await?;
    let affected = conn.exec("UPDATE employees SET salary = salary + 100 WHERE department_id = 10").await?;
    println!("Updated rows: {affected}");

    // 离开作用域自动归还连接池
    Ok(())
}
```
