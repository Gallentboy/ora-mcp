use async_trait::async_trait;
use log::{debug, trace};
use crate::conn::Conn;
use crate::error::{Error, Result};
use crate::io::{TtcReader, TtcWriter};
use super::Routine;

#[derive(Default)]
pub struct TtcNegoRoutine;

impl TtcNegoRoutine {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Routine<()> for TtcNegoRoutine {
    async fn call(&mut self, conn: &mut Conn) -> Result<()> {
        let mut writer = TtcWriter::new();
        // Msg code 1 (TTC negotiation), Client protocol version (6, 0)
        writer.put_bytes(&[1, 6, 0]);
        writer.put_bytes(b"OracleClientRust\0");

        debug!("Sending TTC Protocol Negotiation request (MsgCode 1)");
        conn.send_writer(writer).await?;

        // Read TTC response from server
        let msg_code = conn.get_byte().await?;
        if msg_code != 1 {
            return Err(Error::Protocol(format!(
                "expected TTC message code 1, got {msg_code}"
            )));
        }

        // Ensure we have enough header data
        conn.ensure_in_buffer(64).await?;
        let mut reader = TtcReader::new(&mut conn.in_buffer);

        let server_version = reader.get_byte()?;
        conn.server_version = server_version;

        // Skip 1 byte separator
        let _ = reader.get_byte()?;
        let server_version_str = reader.get_null_term_string(50)?;
        conn.server_version_str = server_version_str;

        let server_charset = reader.get_int(2, false, false)? as u16;
        conn.server_charset = server_charset;

        conn.server_flags = reader.get_byte()?;
        let charset_elem = reader.get_int(2, false, false)? as usize;
        if charset_elem > 0 {
            let _ = reader.get_bytes(charset_elem * 5)?;
        }

        let len1 = reader.get_int(2, false, true)? as usize;
        let num_array = reader.get_bytes(len1)?;
        if num_array.len() >= 10 {
            let num3 = 6 + (num_array[5] as usize) + (num_array[6] as usize);
            if num_array.len() >= num3 + 5 {
                conn.server_ncharset = u16::from_be_bytes([num_array[num3 + 3], num_array[num3 + 4]]);
            }
        }

        let len2 = reader.get_byte()? as usize;
        let compile_caps = reader.get_bytes(len2)?;
        conn.server_compile_caps = compile_caps;

        let len3 = reader.get_byte()? as usize;
        let runtime_caps = reader.get_bytes(len3)?;
        conn.server_runtime_caps = runtime_caps;

        // 能力位（go-ora newTCPNego 尾段）：EOS= caps[15]&1、FSAP= caps[16]&1，
        // 决定 Summary（Msg 4）与 EndOfCall（Msg 9）的伸缩字段
        if conn.server_compile_caps.len() > 15 && conn.server_compile_caps[15] & 1 != 0 {
            conn.has_eos_capability = true;
        }
        if conn.server_compile_caps.len() > 16 && conn.server_compile_caps[16] & 1 != 0 {
            conn.has_fsap_capability = true;
        }

        debug!(
            "TTC Negotiation Complete: Server='{}', Charset={}, NCharset={}, CompileCapsLen={}, RuntimeCapsLen={}",
            conn.server_version_str, conn.server_charset, conn.server_ncharset,
            conn.server_compile_caps.len(), conn.server_runtime_caps.len()
        );

        trace!(
            "Server CompileCaps: {:?}, RuntimeCaps: {:?}",
            conn.server_compile_caps, conn.server_runtime_caps
        );

        Ok(())
    }
}
