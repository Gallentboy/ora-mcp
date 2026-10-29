use async_trait::async_trait;
use log::{debug, trace};
use crate::conn::Conn;
use crate::error::{Error, OracleError, Result};
use crate::io::{TtcWriter};
use super::Routine;

#[derive(Default)]
pub struct PingRoutine;

impl PingRoutine {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Routine<()> for PingRoutine {
    async fn call(&mut self, conn: &mut Conn) -> Result<()> {
        debug!("Pinging Oracle server (MsgCode 3, Op 0x93)");
        let mut writer = TtcWriter::new();
        writer.put_bytes(&[3, 0x93, 0]);
        conn.send_request(writer).await?;

        loop {
            let msg = conn.get_byte().await?;
            trace!("Ping response MsgCode: {}", msg);
            if msg == 4 {
                let s = super::summary::read_summary(conn).await?;
                if s.ret_code != 0 {
                    let err_str =
                        String::from_utf8_lossy(&s.error_message.unwrap_or_default()).to_string();
                    return Err(Error::Server(OracleError {
                        code: s.ret_code,
                        message: err_str,
                    }));
                }
                debug!("Ping acknowledged successfully by Oracle server");
                break;
            }
            if msg == 9 {
                // EndOfCall：同样是调用结束信号（go-ora 循环 4/9 皆终止）
                super::summary::read_end_of_call(conn).await?;
                debug!("Ping acknowledged (EndOfCall) by Oracle server");
                break;
            }
        }
        Ok(())
    }
}
