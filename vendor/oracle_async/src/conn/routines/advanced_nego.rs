//! Advanced Network Negotiation（ANO，0xDEADBEEF 协议）：TNS Accept 之后、
//! TTC 协议之前的可选安全协商层。客户端在 Connect 包里通过 ACFL0/ACFL1
//! 请求 ANO（本驱动固定请求 1/1），服务端 Accept 回显后**必须**完成该交换
//! 才能进入 TTC 协商——跳过会因协议状态机错位被服务端直接断连。
//!
//! 语义（对照 go-ora advanced_nego 包逐字节移植）：
//! - 客户端上报四个服务：supervisor(4) / auth(1) / encrypt(2) / integrity(3)；
//! - auth 不选任何服务（用户名密码认证不走 ANO 通道）、加密与完整性
//!   level=0（accepted：接受但不要求），服务端通常全部回"未激活"（algo 0）；
//! - integrity 服务在 subPacketNum==8 时携带 Diffie-Hellman 参数（g/p/服务端
//!   公钥/IV），需回发客户端公钥完成密钥协商——即使最终 algo=0 不启用加密；
//! - 本驱动：algo=0（明文）直接放行；服务端若强制选择了加密/完整性算法
//!   （REQUIRED 配置），报清晰错误（原生网络加密暂未实现）。

use async_trait::async_trait;
use log::{debug, info, trace, warn};
use num_bigint::BigUint;
use rand::RngCore;

use crate::conn::Conn;
use crate::error::{Error, Result};
use crate::io::{TtcReader, TtcWriter};
use super::Routine;

const ANO_VERSION: u32 = 0x0B20_0200;
const ANO_MAGIC: u64 = 0xDEAD_BEEF;

#[derive(Default)]
pub struct AdvancedNegoRoutine;

impl AdvancedNegoRoutine {
    pub fn new() -> Self {
        Self
    }
}

// ── 写侧：子包帧（length u16 BE + type u16 BE + 载荷），对照 comm.go ──────

#[inline]
fn ph(w: &mut TtcWriter, len: u16, ty: u16) {
    w.put_uint(len as u64, 2, true, false);
    w.put_uint(ty as u64, 2, true, false);
}

#[inline]
fn w_version(w: &mut TtcWriter) {
    ph(w, 4, 5);
    w.put_uint(ANO_VERSION as u64, 4, true, false);
}

#[inline]
fn w_bytes(w: &mut TtcWriter, b: &[u8]) {
    ph(w, b.len() as u16, 1);
    w.put_bytes(b);
}

#[inline]
fn w_ub1(w: &mut TtcWriter, v: u8) {
    ph(w, 1, 2);
    w.put_byte(v);
}

#[inline]
fn w_ub2(w: &mut TtcWriter, v: u16) {
    ph(w, 2, 3);
    w.put_uint(v as u64, 2, true, false);
}

#[inline]
fn w_status(w: &mut TtcWriter, v: u16) {
    ph(w, 2, 6);
    w.put_uint(v as u64, 2, true, false);
}

/// 服务段头：serviceType u16 + subPacketNum u16 + 0 u32（default_service.writeHeader）
#[inline]
fn service_header(w: &mut TtcWriter, service_type: u16, sub_packets: u16) {
    w.put_uint(service_type as u64, 2, true, false);
    w.put_uint(sub_packets as u64, 2, true, false);
    w.put_uint(0, 4, true, false);
}

fn write_client_request(w: &mut TtcWriter) {
    // 服务数据长度口径照抄 go-ora（用于总长度字段；与实际字节一致）
    const ENC_IDS: [u8; 9] = [0, 1, 8, 10, 6, 3, 15, 16, 17];
    const INT_IDS: [u8; 6] = [0, 1, 3, 4, 5, 6];
    const SUP_CID: [u8; 8] = [0, 0, 16, 28, 102, 236, 40, 234];
    const SUP_SERV: [u16; 4] = [4, 1, 2, 3];

    let sup_len = 12 + SUP_CID.len() + 4 + 10 + SUP_SERV.len() * 2; // 42
    let auth_len = 20;
    let enc_len = 17 + ENC_IDS.len(); // 26
    let int_len = 12 + INT_IDS.len(); // 18
    let total = 13 + (8 + sup_len) + (8 + auth_len) + (8 + enc_len) + (8 + int_len);

    // ANO 头：magic u32 + length u16 + version u32 + servCount u16 + errFlags u8
    w.put_uint(ANO_MAGIC, 4, true, false);
    w.put_uint(total as u64, 2, true, false);
    w.put_uint(ANO_VERSION as u64, 4, true, false);
    w.put_uint(4, 2, true, false);
    w.put_byte(0);

    // supervisor（服务 4）：version + cid + ub2 数组
    service_header(w, 4, 3);
    w_version(w);
    w_bytes(w, &SUP_CID);
    ph(w, (10 + SUP_SERV.len() * 2) as u16, 1);
    w.put_uint(ANO_MAGIC, 4, true, false);
    w.put_uint(3, 2, true, false);
    w.put_uint(SUP_SERV.len() as u64, 4, true, false);
    for v in SUP_SERV {
        w.put_uint(v as u64, 2, true, false);
    }

    // auth（服务 1）：version + 0xE0E1 + status 0xFCFF，不选任何认证服务
    service_header(w, 1, 3);
    w_version(w);
    w_ub2(w, 0xE0E1);
    w_status(w, 0xFCFF);

    // encrypt（服务 2）：version + 候选算法 id 列表 + 首选标记 1
    service_header(w, 2, 3);
    w_version(w);
    w_bytes(w, &ENC_IDS);
    w_ub1(w, 1);

    // integrity（服务 3）：version + 候选哈希 id 列表
    service_header(w, 3, 2);
    w_version(w);
    w_bytes(w, &INT_IDS);
}

// ── 读侧：经 in_buffer 的原语读取 ─────────────────────────────────────────

async fn rd_int(conn: &mut Conn, size: usize) -> Result<i64> {
    conn.ensure_in_buffer(size).await?;
    let mut r = TtcReader::new(&mut conn.in_buffer);
    r.get_int64(size, false, true)
}

/// 子包头校验（comm.go validatePacketHeader 的逐分支移植）
fn validate_packet_header(length: usize, ty: u16) -> Result<()> {
    let ok = match ty {
        0 | 1 => true,
        2 => length <= 1,
        3 | 6 => length <= 2,
        4 | 5 => length <= 4,
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(Error::Protocol("advanced negotiation: invalid sub-packet header".into()))
    }
}

/// 读一个子包头并断言类型；返回载荷长度
async fn rd_packet_header(conn: &mut Conn, expected: u16) -> Result<usize> {
    let len = rd_int(conn, 2).await? as usize;
    let ty = rd_int(conn, 2).await? as u16;
    if ty != expected {
        return Err(Error::Protocol(format!(
            "advanced negotiation: sub-packet type {ty} != expected {expected}"
        )));
    }
    validate_packet_header(len, ty)?;
    Ok(len)
}

async fn rd_bytes(conn: &mut Conn) -> Result<Vec<u8>> {
    let len = rd_packet_header(conn, 1).await?;
    conn.ensure_in_buffer(len).await?;
    let mut r = TtcReader::new(&mut conn.in_buffer);
    r.get_bytes(len)
}

async fn rd_ub1(conn: &mut Conn) -> Result<u8> {
    rd_packet_header(conn, 2).await?;
    conn.ensure_in_buffer(1).await?;
    let mut r = TtcReader::new(&mut conn.in_buffer);
    r.get_byte()
}

async fn rd_ub2(conn: &mut Conn) -> Result<u16> {
    rd_packet_header(conn, 3).await?;
    conn.ensure_in_buffer(2).await?;
    let mut r = TtcReader::new(&mut conn.in_buffer);
    Ok(r.get_int64(2, false, true)? as u16)
}

async fn rd_status(conn: &mut Conn) -> Result<u16> {
    rd_packet_header(conn, 6).await?;
    conn.ensure_in_buffer(2).await?;
    let mut r = TtcReader::new(&mut conn.in_buffer);
    Ok(r.get_int64(2, false, true)? as u16)
}

async fn rd_version(conn: &mut Conn) -> Result<u32> {
    rd_packet_header(conn, 5).await?;
    conn.ensure_in_buffer(4).await?;
    let mut r = TtcReader::new(&mut conn.in_buffer);
    Ok(r.get_int64(4, false, true)? as u32)
}

/// auth 服务响应：0xFBFF = 未激活（放行）；0xFAFF 且 sub>2 = 服务端选中了
/// ANO 认证服务（Kerberos/NTS）——本驱动不支持，明确报错
async fn read_auth_service(conn: &mut Conn, sub_packets: usize) -> Result<()> {
    rd_version(conn).await?;
    let status = rd_status(conn).await?;
    if status == 0xFAFF && sub_packets > 2 {
        return Err(Error::Protocol(
            "server selected an ANO authentication service (Kerberos/NTS), \
             which oracle_async does not support yet"
                .into(),
        ));
    }
    if status != 0xFBFF {
        return Err(Error::Protocol("advanced negotiation: bad auth service status".into()));
    }
    debug!("ANO auth service: inactive (plain password auth)");
    Ok(())
}

/// supervisor 服务响应：version + status 31 + ub2 数组
async fn read_supervisor_service(conn: &mut Conn) -> Result<()> {
    rd_version(conn).await?;
    let status = rd_status(conn).await?;
    if status != 31 {
        return Err(Error::Protocol("advanced negotiation: bad supervisor status".into()));
    }
    // readUB2Array：子包(1) + DEADBEEF u32 + 3 u16 + count u32 + count × u16
    let _len = rd_packet_header(conn, 1).await?;
    let magic = rd_int(conn, 4).await?;
    let ver = rd_int(conn, 2).await?;
    let count = rd_int(conn, 4).await? as usize;
    if magic as u64 != ANO_MAGIC || ver != 3 {
        return Err(Error::Protocol("advanced negotiation: bad supervisor array".into()));
    }
    for _ in 0..count {
        rd_int(conn, 2).await?;
    }
    Ok(())
}

/// integrity 服务响应。sub_packets==8 时携带 DH 参数，返回待回发的客户端公钥
async fn read_integrity_service(
    conn: &mut Conn,
    sub_packets: usize,
) -> Result<(u8, Option<Vec<u8>>)> {
    rd_version(conn).await?;
    let algo = rd_ub1(conn).await?;
    if sub_packets != 8 {
        return Ok((algo, None));
    }

    let dh_gen_len = rd_ub2(conn).await? as usize;
    let dh_prim_len = rd_ub2(conn).await? as usize;
    let gen = rd_bytes(conn).await?;
    let prime = rd_bytes(conn).await?;
    let server_pub = rd_bytes(conn).await?;
    let iv = rd_bytes(conn).await?;
    if dh_gen_len == 0 || dh_prim_len == 0 {
        return Err(Error::Protocol("advanced negotiation: bad DH parameters".into()));
    }
    let byte_len = dh_gen_len.div_ceil(8);
    if server_pub.len() != byte_len || prime.len() != byte_len {
        return Err(Error::Protocol("advanced negotiation: DH out of sync".into()));
    }

    // DH：pub = g^priv mod p；shared = serverPub^priv mod p
    let mut priv_key = vec![0u8; byte_len];
    rand::thread_rng().fill_bytes(&mut priv_key);
    let g = BigUint::from_bytes_be(&gen);
    let p = BigUint::from_bytes_be(&prime);
    let x = BigUint::from_bytes_be(&priv_key);
    let s_pub = BigUint::from_bytes_be(&server_pub);
    let client_pub = g.modpow(&x, &p).to_bytes_be();
    let _shared = s_pub.modpow(&x, &p);
    trace!(
        "ANO DH done: byte_len={byte_len}, iv_len={}, shared computed",
        iv.len()
    );

    let mut padded = vec![0u8; byte_len];
    let offset = byte_len.saturating_sub(client_pub.len());
    padded[offset..].copy_from_slice(&client_pub);
    Ok((algo, Some(padded)))
}

#[async_trait]
impl Routine<()> for AdvancedNegoRoutine {
    async fn call(&mut self, conn: &mut Conn) -> Result<()> {
        let mut w = TtcWriter::with_capacity(256);
        write_client_request(&mut w);
        debug!("Sending ANO request (4 services: supervisor/auth/encrypt/integrity)");
        conn.send_writer(w).await?;

        // 响应头：magic u32 + length u16 + version u32 + servCount u16 + errFlags u8
        let magic = rd_int(conn, 4).await?;
        if magic as u64 != ANO_MAGIC {
            return Err(Error::Protocol("advanced negotiation: bad response magic".into()));
        }
        let _length = rd_int(conn, 2).await?;
        let _version = rd_int(conn, 4).await?;
        let serv_count = rd_int(conn, 2).await? as usize;
        let _err_flags = rd_int(conn, 1).await?;
        debug!("ANO response: {serv_count} service(s)");

        let mut encrypt_algo: u8 = 0;
        let mut integrity_algo: u8 = 0;
        let mut client_pub_key: Option<Vec<u8>> = None;

        for _ in 0..serv_count {
            // 服务段头：type u16 + subPacketNum u16 + errCode u32
            conn.ensure_in_buffer(8).await?;
            let (svc_type, sub_packets, err_code) = {
                let mut r = TtcReader::new(&mut conn.in_buffer);
                (
                    r.get_int64(2, false, true)? as u16,
                    r.get_int64(2, false, true)? as usize,
                    r.get_int64(4, false, true)? as u32,
                )
            };
            if err_code != 0 {
                return Err(Error::Protocol(format!(
                    "advanced negotiation: service {svc_type} failed with ora-{err_code}"
                )));
            }
            match svc_type {
                1 => read_auth_service(conn, sub_packets).await?,
                2 => {
                    rd_version(conn).await?;
                    encrypt_algo = rd_ub1(conn).await?;
                }
                3 => {
                    let (algo, pubkey) = read_integrity_service(conn, sub_packets).await?;
                    integrity_algo = algo;
                    client_pub_key = pubkey;
                }
                4 => read_supervisor_service(conn).await?,
                other => {
                    warn!("ANO: ignoring unknown service type {other}");
                }
            }
        }

        // DH 公钥回发（integrity sub_packets==8 时）
        if let Some(pubkey) = client_pub_key {
            let mut w = TtcWriter::with_capacity(64);
            let total = 13 + 8 + 4 + pubkey.len();
            w.put_uint(ANO_MAGIC, 4, true, false);
            w.put_uint(total as u64, 2, true, false);
            w.put_uint(ANO_VERSION as u64, 4, true, false);
            w.put_uint(1, 2, true, false);
            w.put_byte(0);
            service_header(&mut w, 3, 1);
            w_bytes(&mut w, &pubkey);
            debug!("Sending ANO client public key ({} bytes)", pubkey.len());
            conn.send_writer(w).await?;
        }

        if encrypt_algo != 0 {
            return Err(Error::Protocol(format!(
                "server REQUIRES native network encryption (ANO encrypt algo id={encrypt_algo}); \
                 set SQLNET.ENCRYPTION_SERVER to accepted/ignored on the server, \
                 or wait for oracle_async crypto support"
            )));
        }
        if integrity_algo != 0 {
            return Err(Error::Protocol(format!(
                "server REQUIRES native data integrity (ANO hash algo id={integrity_algo}); \
                 set SQLNET.CRYPTO_CHECKSUMS_SERVER to accepted/ignored on the server, \
                 or wait for oracle_async crypto support"
            )));
        }
        info!("ANO complete: plain link (no encryption/integrity algorithm selected)");
        Ok(())
    }
}
