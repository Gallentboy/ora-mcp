use bytes::{BufMut, BytesMut};
use log::trace;
use tokio_util::codec::{Decoder, Encoder};
use crate::error::{Error, Result};
use super::packet::{PacketType, RawPacket};

pub struct TnsCodec {
    pub handshake_complete: bool,
    pub tns_version: u16,
    pub sdu: u32,
}

impl TnsCodec {
    pub fn new(sdu: u32) -> Self {
        Self {
            handshake_complete: false,
            tns_version: 315,
            sdu,
        }
    }
}

impl Decoder for TnsCodec {
    type Item = RawPacket;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if src.len() < 8 {
            return Ok(None);
        }

        // TNS packet header length decoding:
        // Before handshake completion, standard 2-byte big-endian.
        // After handshake completion, if negotiated version >= 315 (12c+), 4-byte big-endian.
        let (packet_len, packet_type_byte, flag) = if self.handshake_complete && self.tns_version >= 315 {
            let len = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;
            (len, src[4], src[5])
        } else {
            let len = u16::from_be_bytes([src[0], src[1]]) as usize;
            (len, src[4], src[5])
        };

        if packet_len < 8 {
            return Err(Error::Protocol(format!(
                "invalid TNS packet length: {packet_len} < 8"
            )));
        }

        if src.len() < packet_len {
            trace!(
                "TNS frame partial: have {} bytes, need {} bytes",
                src.len(),
                packet_len
            );
            src.reserve(packet_len - src.len());
            return Ok(None);
        }

        let packet_bytes = src.split_to(packet_len);
        let ptype = PacketType::try_from(packet_type_byte)?;

        trace!(
            "TNS Recv: type={:?}({}), flag={:#04x}, len={}",
            ptype, packet_type_byte, flag, packet_len
        );

        let header_len = if ptype == PacketType::Data { 10 } else { 8 };
        let payload = if packet_len > header_len {
            BytesMut::from(&packet_bytes[header_len..])
        } else {
            BytesMut::new()
        };

        // 逐包解码日志：DEBUG 下太吵（每个 TNS 包一条），降到 TRACE
        trace!(
            "TNS Packet Decoded: type={:?}, flag={}, payload_len={}",
            ptype, flag, payload.len()
        );

        Ok(Some(RawPacket {
            packet_type: ptype,
            flag,
            payload,
        }))
    }
}

impl Encoder<RawPacket> for TnsCodec {
    type Error = Error;

    fn encode(&mut self, item: RawPacket, dst: &mut BytesMut) -> Result<()> {
        let is_data = item.packet_type == PacketType::Data;
        let header_len = if is_data { 10 } else { 8 };
        let total_len = header_len + item.payload.len();

        dst.reserve(total_len);

        if self.handshake_complete && self.tns_version >= 315 {
            dst.put_u32(total_len as u32);
        } else {
            dst.put_u16(total_len as u16);
            dst.put_u16(0); // Packet Checksum = 0
        }

        dst.put_u8(item.packet_type as u8);
        dst.put_u8(item.flag);
        dst.put_u16(0); // Header Checksum = 0

        if is_data {
            dst.put_u16(0); // dataFlag = 0
        }

        dst.extend_from_slice(&item.payload);

        trace!(
            "TNS Send: type={:?}, flag={:#04x}, total_len={}",
            item.packet_type, item.flag, total_len
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_encode_decode_roundtrip() {
        let mut codec = TnsCodec::new(8192);
        let mut buf = BytesMut::new();

        let pkt = RawPacket {
            packet_type: PacketType::Data,
            flag: 0,
            payload: BytesMut::from(&b"hello oracle"[..]),
        };

        codec.encode(pkt, &mut buf).unwrap();
        assert_eq!(buf.len(), 10 + 12);

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.packet_type, PacketType::Data);
        assert_eq!(&decoded.payload[..], b"hello oracle");
    }
}
