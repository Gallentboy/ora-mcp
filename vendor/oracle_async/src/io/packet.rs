use bytes::{BufMut, BytesMut};
use crate::error::{Error, Result};
use crate::opts::Opts;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Connect = 1,
    Accept = 2,
    Ack = 3,
    Refuse = 4,
    Redirect = 5,
    Data = 6,
    Null = 7,
    Abort = 9,
    Resend = 11,
    Marker = 12,
    Attn = 13,
    Ctrl = 14,
}

impl TryFrom<u8> for PacketType {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        match v {
            1 => Ok(PacketType::Connect),
            2 => Ok(PacketType::Accept),
            3 => Ok(PacketType::Ack),
            4 => Ok(PacketType::Refuse),
            5 => Ok(PacketType::Redirect),
            6 => Ok(PacketType::Data),
            7 => Ok(PacketType::Null),
            9 => Ok(PacketType::Abort),
            11 => Ok(PacketType::Resend),
            12 => Ok(PacketType::Marker),
            13 => Ok(PacketType::Attn),
            14 => Ok(PacketType::Ctrl),
            other => Err(Error::Protocol(format!("unknown TNS packet type: {other}"))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RawPacket {
    pub packet_type: PacketType,
    pub flag: u8,
    pub payload: BytesMut,
}

#[derive(Debug, Clone)]
pub struct AcceptData {
    pub version: u16,
    pub options: u16,
    pub sdu: u32,
    pub tdu: u32,
    pub acfl0: u8,
    pub acfl1: u8,
    pub sid: Option<Vec<u8>>,
}

pub fn build_connect_packet(opts: &Opts, is_redirect: bool) -> (RawPacket, Option<BytesMut>) {
    let connect_data = opts.connection_data();
    let conn_bytes = connect_data.as_bytes();
    let embedded = conn_bytes.len() <= 230;

    let total_len = if embedded { 70 + conn_bytes.len() } else { 70 };
    let mut payload = BytesMut::with_capacity(total_len);

    // TNS Connect payload starts at offset 8 (after 8-byte TNS header)
    // Offset 8..10: Version
    payload.put_u16(0x013F); // 319 (12c+)
    // Offset 10..12: LoVersion
    payload.put_u16(0x0135); // 309
    // Offset 12..14: Options
    payload.put_u16(0x0000);

    // Offset 14..16: SDU (u16 clamp)
    let sdu_u16 = if opts.sdu > 0xFFFF { 0xFFFF } else { opts.sdu as u16 };
    payload.put_u16(sdu_u16);
    // Offset 16..18: TDU (u16 clamp)
    payload.put_u16(sdu_u16);

    // Offset 18..20: Hardware flags: 79, 152
    payload.put_u8(79);
    payload.put_u8(152);

    // Offset 20..22: Reserved
    payload.put_u16(0);
    // Offset 22..24: OurOne
    payload.put_u16(1);
    // Offset 24..26: ConnectData length
    payload.put_u16(conn_bytes.len() as u16);
    // Offset 26..28: ConnectData offset (70)
    payload.put_u16(70);

    // Offset 28..32: Max / SDU extension zeros
    payload.put_u32(0);

    // Offset 32..34: ACFL0, ACFL1
    payload.put_u8(1);
    payload.put_u8(1);

    // Offset 34..58: Zeros (padding up to 58)
    payload.put_bytes(0, 24);

    // Offset 58..62: SDU u32
    payload.put_u32(opts.sdu);
    // Offset 62..66: TDU u32
    payload.put_u32(opts.sdu);
    // Offset 66..70: Zeros
    payload.put_u32(0);

    if embedded {
        payload.put_slice(conn_bytes);
        (
            RawPacket {
                packet_type: PacketType::Connect,
                flag: if is_redirect { 4 } else { 0 },
                payload,
            },
            None,
        )
    } else {
        (
            RawPacket {
                packet_type: PacketType::Connect,
                flag: if is_redirect { 4 } else { 0 },
                payload,
            },
            Some(BytesMut::from(conn_bytes)),
        )
    }
}

pub fn parse_accept_packet(packet: &RawPacket) -> Result<AcceptData> {
    let p = &packet.payload;
    if p.len() < 24 {
        return Err(Error::Protocol("ACCEPT packet payload too short".into()));
    }

    let version = u16::from_be_bytes([p[0], p[1]]);
    let options = u16::from_be_bytes([p[2], p[3]]);
    let mut sdu = u16::from_be_bytes([p[4], p[5]]) as u32;
    let mut tdu = u16::from_be_bytes([p[6], p[7]]) as u32;
    let acfl0 = p[14];
    let acfl1 = p[15];

    if version >= 315 && p.len() >= 32 {
        sdu = u32::from_be_bytes([p[24], p[25], p[26], p[27]]);
        tdu = u32::from_be_bytes([p[28], p[29], p[30], p[31]]);
    }

    let sid = if (packet.flag & 1) != 0 && p.len() >= 16 {
        Some(p[p.len() - 16..].to_vec())
    } else {
        None
    };

    Ok(AcceptData {
        version,
        options,
        sdu,
        tdu,
        acfl0,
        acfl1,
        sid,
    })
}

pub fn parse_refuse_error(packet: &RawPacket) -> Error {
    let text = String::from_utf8_lossy(&packet.payload);
    let code = if let Some(pos) = text.find("(ERR=") {
        let after = &text[pos + 5..];
        if let Some(end) = after.find(')') {
            after[..end].parse::<i32>().unwrap_or(0)
        } else {
            0
        }
    } else {
        0
    };
    Error::Refused(format!("ORA-{:05}: {}", code, text.trim()))
}

pub fn build_marker_packet(marker_type: u8, marker_data: u8) -> RawPacket {
    let mut payload = BytesMut::with_capacity(2);
    payload.put_u8(marker_type);
    payload.put_u8(marker_data);
    RawPacket {
        packet_type: PacketType::Marker,
        flag: 0,
        payload,
    }
}

