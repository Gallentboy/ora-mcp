use async_trait::async_trait;
use log::{debug, error, info, trace};
use sha2::{Digest, Sha512};
use sha1::Sha1;
use md5::Md5;
use crate::conn::Conn;
use crate::crypto::{
    decrypt_session_key, encrypt_password, encrypt_session_key, generate_speedy_key,
    get_key_from_user_password,
};
use crate::error::{Error, OracleError, Result};
use crate::io::{TtcReader, TtcWriter};
use super::Routine;

#[derive(Default)]
pub struct AuthRoutine;

impl AuthRoutine {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Routine<()> for AuthRoutine {
    async fn call(&mut self, conn: &mut Conn) -> Result<()> {
        let username = conn.opts.username.clone();
        let password = conn.opts.password.clone();

        // 1. Send initial TTCOAUTH packet (0x76)
        let mut writer = TtcWriter::new();
        writer.put_bytes(&[3, 0x76, 0, 1]);
        writer.put_uint(username.len() as u64, 4, true, true);
        // LogonMode = NoNewPass (0x1，注意 0x2 是 WithNewPass 改密标志！)
        writer.put_uint(0x1, 4, true, true);
        writer.put_bytes(&[1, 1, 5, 1, 1]);
        writer.put_clr(username.as_bytes());

        writer.put_key_val_string("AUTH_TERMINAL", &conn.opts.client_info.host_name, 0);
        writer.put_key_val_string("AUTH_PROGRAM_NM", &conn.opts.client_info.program_name, 0);
        writer.put_key_val_string("AUTH_MACHINE", &conn.opts.client_info.host_name, 0);
        writer.put_key_val_string("AUTH_PID", &format!("{}", conn.opts.client_info.pid), 0);
        writer.put_key_val_string("AUTH_SID", &conn.opts.client_info.os_user_name, 0);

        debug!("Sending TTCOAUTH initial challenge request (MsgCode 3, Op 0x76)");
        conn.send_writer(writer).await?;

        // 2. Read server authentication parameters (MsgCode 8 until MsgCode 4)
        let mut server_sess_key = String::new();
        let mut salt_hex = String::new();
        let mut verifier_type = 18453i32; // Default 12c+
        let mut pbkdf2_chk_salt = String::new();
        let mut pbkdf2_vgen_count = 4096usize;
        let mut pbkdf2_sder_count = 3usize;

        loop {
            let msg = conn.get_byte().await?;
            trace!("Auth challenge response MsgCode: {}", msg);
            match msg {
                8 => {
                    conn.ensure_in_buffer(8).await?;
                    let mut reader = TtcReader::new(&mut conn.in_buffer);
                    let dict_len = reader.get_int(4, true, true)? as usize;
                    for _ in 0..dict_len {
                        conn.ensure_in_buffer(16).await?;
                        let mut r = TtcReader::new(&mut conn.in_buffer);
                        let (key, val, num) = r.get_key_val()?;
                        match key.as_str() {
                            "AUTH_SESSKEY" => server_sess_key = val,
                            "AUTH_VFR_DATA" => {
                                salt_hex = val;
                                verifier_type = num;
                            }
                            "AUTH_PBKDF2_CSK_SALT" => pbkdf2_chk_salt = val,
                            "AUTH_PBKDF2_VGEN_COUNT" => {
                                if let Ok(n) = val.parse::<usize>() {
                                    pbkdf2_vgen_count = n.clamp(4096, 100_000_000);
                                }
                            }
                            "AUTH_PBKDF2_SDER_COUNT" => {
                                if let Ok(n) = val.parse::<usize>() {
                                    pbkdf2_sder_count = n.clamp(3, 100_000_000);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                4 => {
                    // Summary object
                    let s = super::summary::read_summary(conn).await?;
                    let ret_code = s.ret_code;
                    if ret_code != 0 {
                        let err_msg = s.error_message.unwrap_or_default();
                        let err_str = String::from_utf8_lossy(&err_msg).to_string();
                        error!("Authentication challenge failed with ORA-{:05}: {}", ret_code, err_str);
                        return Err(Error::Server(OracleError {
                            code: ret_code,
                            message: err_str,
                        }));
                    }
                    break;
                }
                9 => {
                    // EndOfCall：同样终止（go-ora 循环 4/9 皆停）
                    super::summary::read_end_of_call(conn).await?;
                    break;
                }
                other => {
                    trace!("Skipping intermediate auth message code: {other}");
                }
            }
        }

        debug!(
            "Auth challenge parsed: verifier_type={}, vgen_count={}, sder_count={}",
            verifier_type, pbkdf2_vgen_count, pbkdf2_sder_count
        );
        trace!(
            "Auth challenge detail: sesskey_len={}, salt_len={}",
            server_sess_key.len(),
            salt_hex.len()
        );
        if let Some(c4) = conn.server_compile_caps.get(4) {
            trace!(
                "caps[4]={c4:#04x}: &2={} &32={} (11g padding={} custom_hash={})",
                c4 & 2,
                c4 & 32,
                c4 & 2 == 0,
                c4 & 32 != 0
            );
        }

        // 3. Compute client session key and encrypt password
        let (e_client_sess_key, e_password, e_speedy_key) = match verifier_type {
            18453 => {
                // 12c+ PBKDF2-HMAC-SHA512 + AES-256-CBC
                let salt = hex::decode(&salt_hex)
                    .map_err(|e| Error::Auth(format!("invalid salt hex: {e}")))?;
                let mut msg = salt.clone();
                msg.extend_from_slice(b"AUTH_PBKDF2_SPEEDY_KEY");

                let speedy_key = generate_speedy_key(&msg, password.as_bytes(), pbkdf2_vgen_count);
                let mut hasher = Sha512::new();
                hasher.update(speedy_key);
                hasher.update(&salt);
                let key_hash = hasher.finalize();
                let key = &key_hash[..32];

                let server_session_key = decrypt_session_key(false, key, &server_sess_key)?;

                let mut client_session_key = vec![0u8; server_session_key.len()];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut client_session_key);

                let e_client = encrypt_session_key(false, key, &client_session_key)?;

                let mut key_buffer = hex::encode_upper(&client_session_key);
                key_buffer.push_str(&hex::encode_upper(&server_session_key));

                let df2key = hex::decode(&pbkdf2_chk_salt)
                    .map_err(|e| Error::Auth(format!("invalid pbkdf2 salt: {e}")))?;
                let final_key = generate_speedy_key(&df2key, key_buffer.as_bytes(), pbkdf2_sder_count);
                let final_key32 = &final_key[..32];

                let e_pass = encrypt_password(password.as_bytes(), final_key32, false)?;
                let e_speed = encrypt_password(&speedy_key, final_key32, false)?;

                (e_client, e_pass, Some(e_speed))
            }
            6949 => {
                // 11g SHA-1 + AES-192。padding 开关由服务器编译能力位决定：
                // caps[4]&2 == 0 → 填充（go-ora 同款判定，本字段影响会话密钥
                // 的加解密形态——AUTH_PASSWORD 恒按填充形态加密）
                let padding = conn
                    .server_compile_caps
                    .get(4)
                    .map(|c| c & 2 == 0)
                    .unwrap_or(true);
                let salt = hex::decode(&salt_hex)
                    .map_err(|e| Error::Auth(format!("invalid salt hex: {e}")))?;
                let mut hasher = Sha1::new();
                hasher.update(password.as_bytes());
                hasher.update(&salt);
                let mut key = hasher.finalize().to_vec();
                key.extend_from_slice(&[0, 0, 0, 0]);

                let server_session_key = decrypt_session_key(padding, &key, &server_sess_key)?;
                if server_session_key.len() < 40 {
                    return Err(Error::Auth(format!(
                        "server session key too short for 11g verifier: {} bytes",
                        server_session_key.len()
                    )));
                }

                let mut client_session_key = vec![0u8; server_session_key.len()];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut client_session_key);

                let e_client = encrypt_session_key(padding, &key, &client_session_key)?;

                // 密码加密密钥：caps[4]&32（customHash）走 SpeedyKey 派生，
                // 否则走 MD5 双段异或（go-ora generatePasswordEncKey 两分支）
                let caps4 = conn.server_compile_caps.get(4).copied().unwrap_or(0);
                let final_key: Vec<u8> = if caps4 & 32 != 0 {
                    let mut buf = client_session_key[..24].to_vec();
                    buf.extend_from_slice(&server_session_key[..24]);
                    let key_buffer = hex::encode_upper(&buf);
                    let df2key = hex::decode(&pbkdf2_chk_salt).unwrap_or_default();
                    let sk = generate_speedy_key(&df2key, key_buffer.as_bytes(), pbkdf2_sder_count);
                    trace!("11g customHash (speedy) password key derivation");
                    sk[..24].to_vec()
                } else {
                    let mut xor_buf = [0u8; 24];
                    for i in 0..24 {
                        xor_buf[i] = client_session_key[i + 16] ^ server_session_key[i + 16];
                    }

                    let mut md5_1 = Md5::new();
                    md5_1.update(&xor_buf[..16]);
                    let p1 = md5_1.finalize();

                    let mut md5_2 = Md5::new();
                    md5_2.update(&xor_buf[16..]);
                    let p2 = md5_2.finalize();

                    let mut k = p1.to_vec();
                    k.extend_from_slice(&p2);
                    k.truncate(24);
                    k
                };

                let e_pass = encrypt_password(password.as_bytes(), &final_key, true)?;
                (e_client, e_pass, None)
            }
            2361 => {
                // 10g O5Logon
                let key = get_key_from_user_password(&username, &password)?;
                let server_session_key = decrypt_session_key(false, &key, &server_sess_key)?;
                if server_session_key.len() < 32 {
                    return Err(Error::Auth(format!(
                        "server session key too short for 10g verifier: {} bytes",
                        server_session_key.len()
                    )));
                }

                let mut client_session_key = vec![0u8; server_session_key.len()];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut client_session_key);

                let e_client = encrypt_session_key(false, &key, &client_session_key)?;

                let mut xor_buf = vec![0u8; 16];
                for i in 0..16 {
                    xor_buf[i] = client_session_key[i + 16] ^ server_session_key[i + 16];
                }

                let mut md5 = Md5::new();
                md5.update(&xor_buf);
                let final_key = md5.finalize();

                let e_pass = encrypt_password(password.as_bytes(), &final_key, true)?;
                (e_client, e_pass, None)
            }
            other => return Err(Error::Auth(format!("unsupported verifier type: {other}"))),
        };

        // 4. Send second TTCOAUTH packet (0x73) with encrypted credentials
        let mut writer = TtcWriter::new();
        // [3, 0x73, 0, 1]：末位 1 = 用户存在标志字节（go-ora PutBytes(1)），
        // 缺失会令整个包错位、服务器无法解析（以 Marker 复位僵持到超时）
        writer.put_bytes(&[3, 0x73, 0, 1]);
        writer.put_int(username.len() as i64, 4, true, true);
        // LogonMode = UserAndPass(0x100) | NoNewPass(0x1) = 0x101；
        // 0x2 是 WithNewPass（改密标志），误置会让服务器把密码当改密流程拒掉
        // （真机 ORA-01017，与 go-ora trace 的 02 01 01 字节对齐确认）
        writer.put_uint(0x101, 4, true, true);
        writer.put_byte(1);

        let mut key_count = 14; // 13 固定键 + AUTH_ALTER_SESSION（go-ora index=14）
        if e_speedy_key.is_some() {
            key_count += 1;
        }
        writer.put_uint(key_count, 4, true, true);
        writer.put_bytes(&[1, 1]);
        writer.put_clr(username.as_bytes());

        // Write authentication key-values
        writer.put_key_val_string("AUTH_SESSKEY", &e_client_sess_key, 1);
        writer.put_key_val_string("AUTH_PASSWORD", &e_password, 0);
        if let Some(ref speed) = e_speedy_key {
            writer.put_key_val_string("AUTH_PBKDF2_SPEEDY_KEY", speed, 0);
        }

        writer.put_key_val_string("AUTH_TERMINAL", &conn.opts.client_info.host_name, 0);
        writer.put_key_val_string("AUTH_PROGRAM_NM", &conn.opts.client_info.program_name, 0);
        writer.put_key_val_string("AUTH_MACHINE", &conn.opts.client_info.host_name, 0);
        writer.put_key_val_string("AUTH_PID", &format!("{}", conn.opts.client_info.pid), 0);
        writer.put_key_val_string("AUTH_SID", &conn.opts.client_info.os_user_name, 0);
        writer.put_key_val_string("AUTH_CONNECT_STRING", &conn.opts.connection_data(), 0);
        writer.put_key_val_string("SESSION_CLIENT_CHARSET", &format!("{}", conn.server_charset), 0);
        writer.put_key_val_string("SESSION_CLIENT_LIB_TYPE", "0", 0);
        writer.put_key_val_string("SESSION_CLIENT_DRIVER_NAME", &conn.opts.client_info.driver_name, 0);
        writer.put_key_val_string("SESSION_CLIENT_VERSION", "2.0.0.0", 0);
        writer.put_key_val_string("SESSION_CLIENT_LOBATTR", "1", 0);
        // go-ora 默认口径：AMERICAN/AMERICA + 本地时区，尾部带 NUL（flag=1）
        let tz_offset = chrono::Local::now().offset().local_minus_utc();
        let tz_h = tz_offset / 3600;
        let tz_m = ((tz_offset / 60) % 60).abs();
        let alter_session = format!(
            "ALTER SESSION SET NLS_LANGUAGE='AMERICAN' NLS_TERRITORY='AMERICA'  TIME_ZONE='{tz_h:+03}:{tz_m:02}'\0"
        );
        writer.put_key_val_string("AUTH_ALTER_SESSION", &alter_session, 1);

        debug!("Sending TTCOAUTH credentials response (MsgCode 3, Op 0x73)");
        trace!("TTCOAUTH 0x73 payload hex: {}", hex::encode_upper(&writer.buf));
        conn.send_writer(writer).await?;

        // 5. Read final authentication acknowledgement
        loop {
            let msg = conn.get_byte().await?;
            trace!("Auth response MsgCode: {}", msg);
            match msg {
                8 => {
                    conn.ensure_in_buffer(8).await?;
                    let mut reader = TtcReader::new(&mut conn.in_buffer);
                    let dict_len = reader.get_int(2, true, true)? as usize;
                    for _ in 0..dict_len {
                        conn.ensure_in_buffer(16).await?;
                        let mut r = TtcReader::new(&mut conn.in_buffer);
                        let (key, val, _) = r.get_key_val()?;
                        if key == "AUTH_SESSION_ID" {
                            conn.session_id = val.parse::<u32>().unwrap_or(0);
                        } else if key == "AUTH_SERIAL_NUM" {
                            conn.serial_num = val.parse::<u32>().unwrap_or(0);
                        }
                        conn.session_properties.insert(key, val);
                    }
                }
                4 => {
                    // Summary
                    let s = super::summary::read_summary(conn).await?;
                    let ret_code = s.ret_code;
                    if ret_code != 0 {
                        let err_str = String::from_utf8_lossy(&s.error_message.unwrap_or_default()).to_string();
                        error!("Authentication rejected by server with ORA-{:05}: {}", ret_code, err_str);
                        return Err(Error::Server(OracleError {
                            code: ret_code,
                            message: err_str,
                        }));
                    }
                    info!(
                        "Authentication succeeded for user '{}'. Session ID: {}, Serial: {}",
                        username, conn.session_id, conn.serial_num
                    );
                    break;
                }
                9 => {
                    // EndOfCall：同样终止（go-ora 循环 4/9 皆停）
                    super::summary::read_end_of_call(conn).await?;
                    break;
                }
                other => {
                    trace!("Skipping auth response message code: {other}");
                }
            }
        }

        Ok(())
    }
}
