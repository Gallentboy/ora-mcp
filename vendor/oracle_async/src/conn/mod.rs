pub mod routines;
pub mod pool;
pub mod transaction;

use std::collections::HashMap;
use bytes::{Buf as _, BytesMut};
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, trace, warn};
use tokio::net::TcpStream;
use crate::error::{Error, Result};
use crate::io::{
    packet::{build_marker_packet, parse_refuse_error, AcceptData, PacketType, RawPacket},
    TnsCodec, TnsFramed, TtcReader, TtcWriter,
};
use crate::opts::Opts;
use routines::{
    advanced_nego::AdvancedNegoRoutine,
    auth::AuthRoutine,
    data_type_nego::DataTypeNegoRoutine,
    db_version::GetDbVersionRoutine,
    handshake::HandshakeRoutine,
    ping::PingRoutine,
    ttc_nego::TtcNegoRoutine,
    Routine,
};
pub use transaction::Transaction;

pub struct Conn {
    pub(crate) stream: TnsFramed,
    /// Box 化：Opts（含 host/user/password/client_info 等字符串）占 248B，
    /// 是 Conn 体积的主要来源——box 后 Conn 缩到 ~450B，使 DbEngine enum
    /// 可像 MySQL 臂一样直接持有 Conn（无需在 enum 变体上套 Box）
    pub(crate) opts: Box<Opts>,
    pub(crate) accept_data: Option<AcceptData>,
    pub(crate) server_version: u8,
    pub(crate) server_version_str: String,
    pub(crate) server_charset: u16,
    pub(crate) server_ncharset: u16,
    pub(crate) server_flags: u8,
    pub(crate) server_compile_caps: Vec<u8>,
    pub(crate) server_runtime_caps: Vec<u8>,
    /// 服务器 caps[15]&1：Summary/EndOfCall 追加 EndOfCallStatus 字段
    pub(crate) has_eos_capability: bool,
    /// 服务器 caps[16]&1：Summary/EndOfCall 追加 EndToEndECIDSequence 字段
    pub(crate) has_fsap_capability: bool,
    pub(crate) ttc_version: u8,
    pub(crate) db_timezone: Option<String>,
    pub(crate) session_properties: HashMap<String, String>,
    pub(crate) session_id: u32,
    pub(crate) serial_num: u32,
    /// 真实数据库版本（0x3B 查询）：banner 尾巴不是数字，版本分支以此为准
    pub(crate) db_version_text: String,
    pub(crate) db_version_major: u32,
    /// 0x3B 回包的完整 banner（OCI 同源）——展示层用它保持与原生 OCI 一致
    pub(crate) db_version_info: String,
    /// NLS 会话参数（连接末尾加载；失败为 None，不阻断连接）。
    /// Box 化：NlsData 是 13 个 String（~312B），内联会把 Conn 撑回 760B
    /// （体积守卫 conn_stays_compact 会拦下）
    pub(crate) nls: Option<Box<routines::nls::NlsData>>,
    pub(crate) in_buffer: BytesMut,
    /// 在途请求的已发包缓冲：TNS 协议规定服务端可随时回 RESEND（类型 11）
    /// 要求客户端重传当前消息的全部包——监听器把连接转交给专用进程后这是
    /// 常规动作（握手期尤其常见）。每次成功读到响应（非 RESEND/MARKER）
    /// 即清空：重传语义只覆盖“当前在途请求”，与 go-ora 的 sendPcks 同源但
    /// 按请求边界收窄，避免长会话下无限增长。
    pub(crate) in_flight: Vec<RawPacket>,
}

impl Conn {
    /// Connect to Oracle database using the provided options and complete all handshake stages.
    pub async fn connect(opts: Opts) -> Result<Self> {
        info!(
            "Connecting to Oracle server at {}:{} (service: {:?}, sid: {:?})",
            opts.host, opts.port, opts.service_name, opts.sid
        );

        let mut conn = Self::connect_raw(&opts, false).await?;

        // Stage 1: TNS Handshake (Connect -> Accept / Refuse / Redirect)
        debug!("Beginning TNS connection handshake");
        HandshakeRoutine::new().call(&mut conn).await?;

        // Stage 1.5: Advanced Network Negotiation（ANO，0xDEADBEEF 协议）。
        // 触发条件与 go-ora 一致：Accept 回显 ACFL0&1 且非 4、ACFL1 非 8。
        // 我们在 Connect 包里请求了 ANO（ACFL0=1/ACFL1=1），服务端等着该交换，
        // 跳过会因状态机错位被直接断连。
        let (acfl0, acfl1) = conn
            .accept_data
            .as_ref()
            .map(|a| (a.acfl0, a.acfl1))
            .unwrap_or((0, 0));
        if acfl0 & 1 != 0 && acfl0 & 4 == 0 && acfl1 & 8 == 0 {
            debug!("Beginning Advanced Network Negotiation (ANO)");
            AdvancedNegoRoutine::new().call(&mut conn).await?;
        }

        // Stage 2: TTC Protocol Negotiation (TCPNego)
        debug!("Beginning TTC protocol negotiation");
        TtcNegoRoutine::new().call(&mut conn).await?;

        // Stage 3: Data Type Negotiation
        debug!("Beginning data type negotiation");
        DataTypeNegoRoutine::new().call(&mut conn).await?;

        // Stage 4: Authentication (PBKDF2-HMAC-SHA512 + AES-256-CBC)
        debug!("Beginning user authentication for user: {}", conn.opts.username);
        AuthRoutine::new().call(&mut conn).await?;

        // Stage 5: 真实数据库版本（0x3B）：ALL_USERS 等版本分支依赖它；
        // 失败不阻断连接（降级为 major=0，调用方自行兜底）
        if let Err(e) = GetDbVersionRoutine::new().call(&mut conn).await {
            warn!("DB version query failed (non-fatal): {e}");
        }

        // Stage 6: NLS 会话参数（go-ora 同口径：失败不阻断）。
        // 注：出参路径在 11g 真机上尚未跑通（见 AGENTS.md 已知边界），
        // 失败时静默跳过，不影响连接与后续查询。
        let _ = routines::nls::LoadNlsRoutine::new().call(&mut conn).await;

        info!(
            "Connected successfully to Oracle database. Version: {}, Session ID: {}, Serial: {}",
            conn.server_version_str, conn.session_id, conn.serial_num
        );

        Ok(conn)
    }

    pub(crate) async fn connect_raw(opts: &Opts, _is_redirect: bool) -> Result<Self> {
        let addr = format!("{}:{}", opts.host, opts.port);
        trace!("Establishing TCP stream to {}", addr);

        let tcp = tokio::time::timeout(opts.connect_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(Error::Io)?;

        let codec = TnsCodec::new(opts.sdu);
        let stream = TnsFramed::new(tcp, codec);

        Ok(Self {
            stream,
            opts: Box::new(opts.clone()),
            accept_data: None,
            server_version: 0,
            server_version_str: String::new(),
            server_charset: 0,
            server_ncharset: 0,
            server_flags: 0,
            server_compile_caps: Vec::new(),
            server_runtime_caps: Vec::new(),
            has_eos_capability: false,
            has_fsap_capability: false,
            ttc_version: 6,
            db_timezone: None,
            session_properties: HashMap::new(),
            session_id: 0,
            serial_num: 0,
            db_version_text: String::new(),
            db_version_major: 0,
            db_version_info: String::new(),
            nls: None,
            in_buffer: BytesMut::with_capacity(8192),
            in_flight: Vec::new(),
        })
    }

    /// 上限：服务端连续要求重传的轮次跟脚（恶意/异常流不至于死循环）。
    const MAX_RESEND_ROUNDS: u32 = 16;

    /// Read raw TNS packet from the wire. RESEND（服务端要求重传在途包）与
    /// MARKER（带外信号）在此处内联消化：重传在途序列后继续读，绝不把
    /// 这两类包遇给上层——上层只该看到真正的响应/控制包。
    pub async fn read_packet(&mut self) -> Result<RawPacket> {
        let mut resend_rounds = 0u32;
        loop {
            let pkt = match self.stream.next().await {
                Some(Ok(p)) => p,
                Some(Err(e)) => {
                    error!("Socket read error: {e}");
                    return Err(e);
                }
                None => {
                    error!("Unexpected EOF on Oracle TNS stream");
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "connection closed by server",
                    )));
                }
            };

            match pkt.packet_type {
                PacketType::Resend => {
                    resend_rounds += 1;
                    if resend_rounds > Self::MAX_RESEND_ROUNDS {
                        error!(
                            "Server keeps requesting RESEND (> {} rounds); aborting",
                            Self::MAX_RESEND_ROUNDS
                        );
                        return Err(Error::Protocol(format!(
                            "server requested RESEND more than {} times",
                            Self::MAX_RESEND_ROUNDS
                        )));
                    }
                    warn!(
                        "TNS RESEND received; retransmitting {} in-flight packet(s) (round {})",
                        self.in_flight.len(),
                        resend_rounds
                    );
                    // 重传不经 write_packet——不重复记录进 in_flight
                    for p in &self.in_flight {
                        trace!("TNS retransmit: type={:?}, len={}", p.packet_type, p.payload.len());
                        self.stream.send(p.clone()).await?;
                    }
                    continue;
                }
                PacketType::Marker => {
                    // MARKER 是带外控制信号，服务端期待应答（go-ora processMarker）：
                    // 回一个 marker_type_reset(2)、flag=0x20 的 Marker，再读掉服务端
                    // 的后续确认包，然后继续等真正的响应。markerType 在载荷第 3 字节
                    // （[1, 0, markerType]）。
                    let marker_type = pkt.payload.get(2).copied().unwrap_or(0);
                    warn!(
                        "TNS Marker received (type={marker_type}); replying with reset marker"
                    );
                    let reply = RawPacket {
                        packet_type: PacketType::Marker,
                        flag: 0x20,
                        payload: BytesMut::from(&[1u8, 0, 2][..]),
                    };
                    self.stream.send(reply).await?;
                    // 读掉复位应答后的一个包（go-ora processMarker 同款）
                    match self.stream.next().await {
                        Some(Ok(_)) => {}
                        Some(Err(e)) => return Err(e),
                        None => {
                            return Err(Error::Io(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "connection closed by server after marker reply",
                            )))
                        }
                    }
                    continue;
                }
                _ => {}
            }

            // 服务端已开始回应当前在途请求：请求-响应周期完成，重传缓冲清空
            self.in_flight.clear();
            trace!("Raw packet received: type={:?}", pkt.packet_type);
            return Ok(pkt);
        }
    }

    /// Write raw TNS packet to the wire. Records the packet into the in-flight
    /// buffer so a subsequent server RESEND can retransmit the whole sequence.
    pub async fn write_packet(&mut self, packet: RawPacket) -> Result<()> {
        trace!("Sending raw TNS packet: type={:?}", packet.packet_type);
        self.in_flight.push(packet.clone());
        self.stream.send(packet).await
    }

    /// Write DATA packet payload to Oracle server, automatically slicing into SDU chunks if needed.
    pub async fn write_data(&mut self, payload: &[u8]) -> Result<()> {
        let sdu = self.stream.codec().sdu as usize;
        let segment_len = sdu.saturating_sub(64).max(512);

        if payload.len() <= segment_len {
            let pkt = RawPacket {
                packet_type: PacketType::Data,
                flag: 0,
                payload: BytesMut::from(payload),
            };
            self.write_packet(pkt).await?;
        } else {
            let mut offset = 0;
            while offset < payload.len() {
                let end = (offset + segment_len).min(payload.len());
                let chunk = &payload[offset..end];
                let pkt = RawPacket {
                    packet_type: PacketType::Data,
                    flag: 0,
                    payload: BytesMut::from(chunk),
                };
                self.write_packet(pkt).await?;
                offset += segment_len;
            }
        }
        Ok(())
    }

    /// Flush and send accumulated writer buffer as DATA packet(s).
    pub async fn send_writer(&mut self, writer: TtcWriter) -> Result<()> {
        let bytes = writer.freeze();
        self.write_data(&bytes).await
    }

    /// 发起新请求（v2 每命令 ResetBuffer 的读侧对位）：先清空输入残留再发送。
    /// 命令级防毒——上一语句解码失败/提前退出留在缓冲里的字节不再毒化本
    /// 会话的后续交互（真机症状：一次解码错误后所有查询持续报
    /// invalid int size）。响应中途的流控回写（case 19 的 echo）不经此方法
    pub async fn send_request(&mut self, writer: TtcWriter) -> Result<()> {
        self.reset_read_buffer();
        self.send_writer(writer).await
    }

    /// 清空输入缓冲残留（v2 resetRead 同型；丢弃量留 trace 便于诊断）
    pub fn reset_read_buffer(&mut self) {
        if !self.in_buffer.is_empty() {
            trace!("discard {} residual input bytes", self.in_buffer.len());
        }
        self.in_buffer.clear();
    }

    /// Read until at least `needed` bytes are in `self.in_buffer`, filling from incoming DATA packets.
    /// RESEND / MARKER 已在 read_packet 内消化（重传/跳过），此处只会看到
    /// DATA / REFUSE / 其它控制包。
    pub async fn ensure_in_buffer(&mut self, needed: usize) -> Result<()> {
        while self.in_buffer.len() < needed {
            let pkt = self.read_packet().await?;
            match pkt.packet_type {
                PacketType::Data => {
                    self.in_buffer.extend_from_slice(&pkt.payload);
                }
                PacketType::Refuse => {
                    return Err(parse_refuse_error(&pkt));
                }
                other => {
                    return Err(Error::Protocol(format!(
                        "unexpected packet type {other:?} while waiting for DATA"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Read next single byte from accumulated input buffer.
    pub async fn get_byte(&mut self) -> Result<u8> {
        self.ensure_in_buffer(1).await?;
        let mut reader = TtcReader::new(&mut self.in_buffer);
        reader.get_byte()
    }

    /// 动态读取压缩 BE 整数：peek 首字节定实际长度再按需补包——预读上限
    /// 会在「Summary 正好落在包尾」时等一个永不到来的下一包（真机踩坑）。
    pub async fn read_ci(&mut self, size: usize) -> Result<i64> {
        self.ensure_in_buffer(1).await?;
        let wire = (self.in_buffer[0] as usize) & 0x7F;
        self.ensure_in_buffer(1 + wire.min(8)).await?;
        let mut r = TtcReader::new(&mut self.in_buffer);
        r.get_int64(size, true, true)
    }

    /// 动态读取 CLR 变长字节流（含 0xFE 分块形态），逐段 peek 按需补包。
    pub async fn read_clr(&mut self) -> Result<Option<Vec<u8>>> {
        self.ensure_in_buffer(1).await?;
        let first = self.in_buffer[0];
        if first == 0 || first == 0xFF || first == 0xFD {
            self.in_buffer.advance(1);
            return Ok(None);
        }
        if first != 0xFE {
            self.ensure_in_buffer(1 + first as usize).await?;
            let mut r = TtcReader::new(&mut self.in_buffer);
            return r.get_clr();
        }
        // 分块形态：0xFE + (块长 + 块数据)* + 0
        self.in_buffer.advance(1);
        let mut out = Vec::new();
        loop {
            self.ensure_in_buffer(1).await?;
            let chunk_len = self.in_buffer[0] as usize;
            if chunk_len == 0 {
                self.in_buffer.advance(1);
                break;
            }
            self.ensure_in_buffer(1 + chunk_len).await?;
            self.in_buffer.advance(1);
            let chunk = self.in_buffer.split_to(chunk_len);
            out.extend_from_slice(&chunk);
        }
        Ok(Some(out))
    }

    /// 动态读取 DLC（长度前缀 int(4,comp) + CLR），按需补包。
    pub async fn read_dlc(&mut self) -> Result<Option<Vec<u8>>> {
        let length = self.read_ci(4).await? as usize;
        if length > 0 {
            if let Some(mut bytes) = self.read_clr().await? {
                if bytes.len() > length {
                    bytes.truncate(length);
                }
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    /// Ping server with ping routine.
    pub async fn ping(&mut self) -> Result<()> {
        PingRoutine::new().call(self).await
    }

    /// Begin a new transaction on this connection.
    pub async fn start_transaction(&mut self) -> Result<Transaction<'_>> {
        Transaction::new(self).await
    }

    /// 协议级提交（go-ora Tx.Commit：simpleObject operationID 0x0E）
    ///
    /// 与 SQL 文本 `COMMIT` 的差别：不占语句解析/游标资源，服务端直接
    /// 提交当前事务并回 Summary；go-ora 在提交后把 autoCommit 置真。
    pub async fn commit(&mut self) -> Result<()> {
        self.simple_object(0x0E).await
    }

    /// 协议级回滚（go-ora Tx.Rollback：simpleObject operationID 0x0F）
    pub async fn rollback(&mut self) -> Result<()> {
        self.simple_object(0x0F).await
    }

    /// simpleObject 执行（go-ora simpleObject.exec：`[3, opID, 0]` + 读 4/9）
    async fn simple_object(&mut self, operation_id: u8) -> Result<()> {
        let mut w = TtcWriter::new();
        w.put_bytes(&[3, operation_id, 0]);
        self.send_request(w).await?;
        loop {
            let msg = self.get_byte().await?;
            if msg == 4 {
                let s = routines::summary::read_summary(self).await?;
                if s.ret_code != 0 {
                    let msg_str = String::from_utf8_lossy(&s.error_message.unwrap_or_default())
                        .to_string();
                    return Err(Error::Server(crate::error::OracleError {
                        code: s.ret_code,
                        message: msg_str,
                    }));
                }
                break;
            }
            if msg == 9 {
                routines::summary::read_end_of_call(self).await?;
                break;
            }
        }
        trace!("simpleObject 0x{operation_id:02X} done");
        Ok(())
    }

    /// Send a TNS Marker packet (type 12, marker 0) to abort the current running operation.
    pub async fn break_connection(&mut self) -> Result<()> {
        warn!("Sending TNS Break Marker packet to Oracle server");
        let pkt = build_marker_packet(0, 0);
        self.write_packet(pkt).await
    }

    /// 关闭服务端游标（go-ora defaultStmt.Close）：同一 DATA 包内
    /// `[0x11,0x69,0,1,1,1] + cursorID(comp4)` + `[3,0x93,0]`（simpleObject
    /// exec）。游标取尽（1403）后不关即发下一条语句，服务器会以 Marker
    /// 中断 + ORA-01002 拒绝（真机实测）。
    pub async fn close_cursor(&mut self, cursor_id: u16) -> Result<()> {
        if cursor_id == 0 {
            return Ok(());
        }
        let mut w = TtcWriter::new();
        w.put_bytes(&[0x11, 0x69, 0, 1, 1, 1]);
        w.put_uint(cursor_id as u64, 4, true, true);
        w.put_bytes(&[3, 0x93, 0]);
        self.send_request(w).await?;
        // 读掉响应（4/9 皆可终止——关游标的回包可能只有 EndOfCall 9 而无 4，
        // 真机实测：只在 4 上终止会永久等待）
        loop {
            let msg = self.get_byte().await?;
            if msg == 4 {
                routines::summary::read_summary(self).await?;
                break;
            }
            if msg == 9 {
                routines::summary::read_end_of_call(self).await?;
                break;
            }
        }
        trace!("cursor {cursor_id} closed");
        Ok(())
    }

    pub fn server_version(&self) -> &str {
        &self.server_version_str
    }

    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    /// 真实数据库版本号文本（如 "11.2.0.4.0"；未取得为空）
    pub fn db_version(&self) -> &str {
        &self.db_version_text
    }

    /// 完整版本 banner（OCI 同源，如 "Oracle Database 11g … Release 11.2.0.4.0 …"）
    pub fn db_version_banner(&self) -> &str {
        &self.db_version_info
    }

    /// NLS 会话参数（连接时加载；未加载成功为 None）
    pub fn nls(&self) -> Option<&routines::nls::NlsData> {
        self.nls.as_deref()
    }

    /// 数据库主版本（未取得为 0）
    pub fn db_version_major(&self) -> u32 {
        self.db_version_major
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// 伪服务器侧：按 TNS 16 位头读一个完整包（握手期包头恒为 u16 长度）
    async fn read_frame(sock: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut head = [0u8; 8];
        sock.read_exact(&mut head).await.unwrap();
        let len = u16::from_be_bytes([head[0], head[1]]) as usize;
        let mut full = head.to_vec();
        full.resize(len, 0);
        sock.read_exact(&mut full[8..]).await.unwrap();
        full
    }

    /// RESEND 重传回归（真机握手首批即触发的协议路径）：伪服务器先回
    /// RESEND，客户端必须重传逐字节相同的连接序列；随后回 ACCEPT，
    /// 握手应成功并解析出协商参数。
    #[tokio::test]
    async fn handshake_survives_server_resend() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let first = read_frame(&mut sock).await;
            assert!(first.len() > 70, "connect packet should carry the 70-byte header + connect data");

            // 回 RESEND（8 字节头：len=8, checksum=0, type=11, flag=0, checksum=0）
            sock.write_all(&[0u8, 8, 0, 0, 11, 0, 0, 0]).await.unwrap();

            // 读重传包：必须与首发逐字节一致（同一在途序列的完整重放）
            let resent = read_frame(&mut sock).await;
            assert_eq!(first, resent, "retransmitted connect packet must be byte-identical");

            // 回 ACCEPT：40 字节帧（8 头 + 32 载荷），version=319、SDU/TDU=8192
            let mut accept = vec![0u8; 8 + 32];
            accept[0] = 0;
            accept[1] = 40; // length
            accept[4] = 2; // type = ACCEPT
            accept[8] = 0x01;
            accept[9] = 0x3F; // version 319
            accept[22] = 1; // ACFL0（载荷偏移 14）
            accept[23] = 1; // ACFL1
            accept[32..36].copy_from_slice(&8192u32.to_be_bytes()); // 32 位 SDU
            accept[36..40].copy_from_slice(&8192u32.to_be_bytes()); // 32 位 TDU
            sock.write_all(&accept).await.unwrap();
        });

        let opts = Opts::builder()
            .host("127.0.0.1")
            .port(addr.port())
            .service_name("XEPDB1")
            .username("scott")
            .password("tiger")
            .build();

        let mut conn = Conn::connect_raw(&opts, false).await.unwrap();
        HandshakeRoutine::new().call(&mut conn).await.unwrap();

        let accept = conn.accept_data.as_ref().expect("accept data parsed");
        assert_eq!(accept.version, 319);
        assert_eq!(accept.sdu, 8192);
        assert_eq!(accept.tdu, 8192);
        assert_eq!(accept.acfl0, 1);
        // 重传缓冲在成功读到响应后清空
        assert!(conn.in_flight.is_empty());

        server.await.unwrap();
    }

    /// 伪服务器侧 ANO 子包：len u16 BE + type u16 BE + payload
    fn ano_sub(ty: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = (payload.len() as u16).to_be_bytes().to_vec();
        v.extend_from_slice(&ty.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// ANO 全流程回归：Connect → RESEND 重传 → Accept（ACFL0/1 置位）→
    /// ANO 请求（校验 magic/版本/服务数/结构）→ ANO 响应（四服务全未激活）
    /// → 协商成功放行明文链路。
    #[tokio::test]
    async fn handshake_then_ano_negotiation_succeeds() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();

            // ── Connect（16 位头）→ RESEND → 重传 ──
            let mut head = [0u8; 8];
            sock.read_exact(&mut head).await.unwrap();
            let mut first = head.to_vec();
            first.resize(u16::from_be_bytes([head[0], head[1]]) as usize, 0);
            sock.read_exact(&mut first[8..]).await.unwrap();
            sock.write_all(&[0u8, 8, 0, 0, 11, 0, 0, 0]).await.unwrap(); // RESEND
            let mut head = [0u8; 8];
            sock.read_exact(&mut head).await.unwrap();
            let mut resent = head.to_vec();
            resent.resize(u16::from_be_bytes([head[0], head[1]]) as usize, 0);
            sock.read_exact(&mut resent[8..]).await.unwrap();
            assert_eq!(first, resent);

            // ── Accept：ACFL0=1 / ACFL1=1（触发 ANO），version 319 ──
            let mut accept = vec![0u8; 8 + 32];
            accept[1] = 40;
            accept[4] = 2;
            accept[8] = 0x01;
            accept[9] = 0x3F;
            accept[22] = 1; // ACFL0
            accept[23] = 1; // ACFL1
            accept[32..36].copy_from_slice(&8192u32.to_be_bytes());
            accept[36..40].copy_from_slice(&8192u32.to_be_bytes());
            sock.write_all(&accept).await.unwrap();

            // ── 读 ANO 请求（DATA 包，32 位头）──
            let mut lenb = [0u8; 4];
            sock.read_exact(&mut lenb).await.unwrap();
            let mut frame = lenb.to_vec();
            frame.resize(u32::from_be_bytes(lenb) as usize, 0);
            sock.read_exact(&mut frame[4..]).await.unwrap();
            assert_eq!(frame[4], 6, "DATA packet");
            let ano = &frame[10..]; // 去掉 8 头 + 2 dataFlag
            assert_eq!(&ano[0..4], &0xDEAD_BEEFu32.to_be_bytes());
            assert_eq!(&ano[6..10], &0x0B20_0200u32.to_be_bytes());
            assert_eq!(&ano[10..12], &4u16.to_be_bytes()); // servCount = 4
            assert_eq!(ano[12], 0);
            // supervisor cid 签名字节（结构正确性的锚点）
            let cid: Vec<u8> = vec![0, 0, 16, 28, 102, 236, 40, 234];
            assert!(
                ano.windows(cid.len()).any(|w| w == cid),
                "ANO request should embed the supervisor cid"
            );

            // ── 回 ANO 响应：四服务全未激活（algo 0 = 明文）──
            let ver = ano_sub(5, &0x0B20_0200u32.to_be_bytes());
            let mut sup = Vec::new();
            sup.extend_from_slice(&4u16.to_be_bytes());
            sup.extend_from_slice(&3u16.to_be_bytes());
            sup.extend_from_slice(&0u32.to_be_bytes());
            sup.extend_from_slice(&ver);
            sup.extend_from_slice(&ano_sub(6, &31u16.to_be_bytes()));
            let mut arr = 0xDEAD_BEEFu32.to_be_bytes().to_vec();
            arr.extend_from_slice(&3u16.to_be_bytes());
            arr.extend_from_slice(&4u32.to_be_bytes());
            for v in [4u16, 1, 2, 3] {
                arr.extend_from_slice(&v.to_be_bytes());
            }
            sup.extend_from_slice(&ano_sub(1, &arr));

            let mut auth = Vec::new();
            auth.extend_from_slice(&1u16.to_be_bytes());
            auth.extend_from_slice(&3u16.to_be_bytes());
            auth.extend_from_slice(&0u32.to_be_bytes());
            auth.extend_from_slice(&ver);
            auth.extend_from_slice(&ano_sub(6, &0xFBFFu16.to_be_bytes()));

            let mut enc = Vec::new();
            enc.extend_from_slice(&2u16.to_be_bytes());
            enc.extend_from_slice(&2u16.to_be_bytes());
            enc.extend_from_slice(&0u32.to_be_bytes());
            enc.extend_from_slice(&ver);
            enc.extend_from_slice(&ano_sub(2, &[0]));

            let mut integ = Vec::new();
            integ.extend_from_slice(&3u16.to_be_bytes());
            integ.extend_from_slice(&2u16.to_be_bytes());
            integ.extend_from_slice(&0u32.to_be_bytes());
            integ.extend_from_slice(&ver);
            integ.extend_from_slice(&ano_sub(2, &[0]));

            let mut resp = 0xDEAD_BEEFu32.to_be_bytes().to_vec();
            let body_len = 13 + sup.len() + auth.len() + enc.len() + integ.len();
            resp.extend_from_slice(&(body_len as u16).to_be_bytes());
            resp.extend_from_slice(&0x0B20_0200u32.to_be_bytes());
            resp.extend_from_slice(&4u16.to_be_bytes());
            resp.push(0);
            resp.extend_from_slice(&sup);
            resp.extend_from_slice(&auth);
            resp.extend_from_slice(&enc);
            resp.extend_from_slice(&integ);

            let mut data = Vec::new();
            data.extend_from_slice(&((resp.len() + 10) as u32).to_be_bytes());
            data.push(6); // DATA
            data.push(0);
            data.extend_from_slice(&[0, 0]); // checksum
            data.extend_from_slice(&[0, 0]); // dataFlag
            data.extend_from_slice(&resp);
            sock.write_all(&data).await.unwrap();
        });

        let opts = Opts::builder()
            .host("127.0.0.1")
            .port(addr.port())
            .service_name("XEPDB1")
            .username("scott")
            .password("tiger")
            .build();

        let mut conn = Conn::connect_raw(&opts, false).await.unwrap();
        HandshakeRoutine::new().call(&mut conn).await.unwrap();

        // Accept 的 ACFL0/1 置位 → ANO 必须执行且成功（明文放行）
        routines::advanced_nego::AdvancedNegoRoutine::new()
            .call(&mut conn)
            .await
            .unwrap();

        server.await.unwrap();
    }
}

#[cfg(test)]
mod size_probe {
    use super::*;
    /// Conn 体积守卫：Opts 等大字段采用 Box 隔离，确保 Conn 结构体整体
    /// 栈内存占用控制在 512 字节以内，避免大枚举变体内存膨胀。
    #[test]
    fn conn_stays_compact() {
        let size = std::mem::size_of::<Conn>();
        assert!(size <= 512, "Conn 体积 {size}B 超过 512B 预算");
    }
}
