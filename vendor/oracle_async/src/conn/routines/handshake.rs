use async_trait::async_trait;
use log::{debug, error, info, warn};
use crate::conn::Conn;
use crate::error::{Error, Result};
use crate::io::{
    packet::{build_connect_packet, parse_accept_packet, parse_refuse_error, PacketType},
};
use super::Routine;

#[derive(Default)]
pub struct HandshakeRoutine;

impl HandshakeRoutine {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Routine<()> for HandshakeRoutine {
    async fn call(&mut self, conn: &mut Conn) -> Result<()> {
        let (connect_pkt, extra_data) = build_connect_packet(&conn.opts, false);
        debug!("Sending TNS Connect packet");
        conn.write_packet(connect_pkt).await?;

        if let Some(extra) = extra_data {
            debug!("Sending connect data overflow in DATA packet (len: {})", extra.len());
            conn.write_data(&extra).await?;
        }

        let resp = conn.read_packet().await?;
        match resp.packet_type {
            PacketType::Accept => {
                let accept = parse_accept_packet(&resp)?;
                info!(
                    "TNS Accept received: version={}, SDU={}, TDU={}, options={:#x}",
                    accept.version, accept.sdu, accept.tdu, accept.options
                );

                // Update codec with negotiated values
                let codec = conn.stream.codec_mut();
                codec.tns_version = accept.version;
                codec.sdu = accept.sdu;
                codec.handshake_complete = true;

                conn.accept_data = Some(accept);
                Ok(())
            }
            PacketType::Redirect => {
                let data = String::from_utf8_lossy(&resp.payload).to_string();
                warn!("TNS Redirect received: {data}");
                // In production RAC / DataGuard environments, the client updates the target address and reconnects
                Err(Error::Redirect {
                    addr: data.clone(),
                    reconnect_data: String::new(),
                })
            }
            PacketType::Refuse => {
                let err = parse_refuse_error(&resp);
                error!("TNS Connection refused by listener: {err}");
                Err(err)
            }
            other => {
                error!("Unexpected TNS packet during handshake: {other:?}");
                Err(Error::Protocol(format!(
                    "unexpected packet {other:?} during TNS handshake"
                )))
            }
        }
    }
}
