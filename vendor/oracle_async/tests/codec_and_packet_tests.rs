use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};
use ora_async::io::{
    packet::{build_connect_packet, build_marker_packet, parse_accept_packet, parse_refuse_error, PacketType, RawPacket},
    TnsCodec, TtcReader, TtcWriter,
};
use ora_async::opts::Opts;

#[test]
fn test_tns_codec_16bit_header() {
    let mut codec = TnsCodec::new(8192);
    codec.handshake_complete = false;

    let payload = BytesMut::from(&b"SELECT 1 FROM DUAL"[..]);
    let packet = RawPacket {
        packet_type: PacketType::Data,
        flag: 0,
        payload,
    };

    let mut buf = BytesMut::new();
    codec.encode(packet, &mut buf).unwrap();

    // Data header is 10 bytes + 18 bytes payload = 28 bytes total
    assert_eq!(buf.len(), 28);
    // 16-bit header length
    assert_eq!(&buf[0..2], &[0, 28]);
    assert_eq!(buf[4], PacketType::Data as u8);

    let decoded = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.packet_type, PacketType::Data);
    assert_eq!(&decoded.payload[..], b"SELECT 1 FROM DUAL");
}

#[test]
fn test_tns_codec_32bit_header() {
    let mut codec = TnsCodec::new(8192);
    codec.handshake_complete = true;
    codec.tns_version = 315;

    let payload = BytesMut::from(&b"TEST PAYLOAD 32BIT"[..]);
    let packet = RawPacket {
        packet_type: PacketType::Data,
        flag: 0,
        payload,
    };

    let mut buf = BytesMut::new();
    codec.encode(packet, &mut buf).unwrap();

    // Data header is 10 bytes + 18 bytes payload = 28 bytes total
    assert_eq!(buf.len(), 28);
    // 32-bit header length
    assert_eq!(&buf[0..4], &[0, 0, 0, 28]);
    assert_eq!(buf[4], PacketType::Data as u8);

    let decoded = codec.decode(&mut buf).unwrap().unwrap();
    assert_eq!(decoded.packet_type, PacketType::Data);
    assert_eq!(&decoded.payload[..], b"TEST PAYLOAD 32BIT");
}

#[test]
fn test_connect_packet_generation() {
    let opts = Opts::builder()
        .host("oracle.internal")
        .port(1521)
        .service_name("XEPDB1")
        .username("system")
        .build();

    let (pkt, extra) = build_connect_packet(&opts, false);
    assert_eq!(pkt.packet_type, PacketType::Connect);
    assert_eq!(pkt.flag, 0);

    // Standard connect packet payload length >= 70
    assert!(pkt.payload.len() >= 70);

    // If connect data <= 230 bytes, extra is None (embedded)
    assert!(extra.is_none());
}

#[test]
fn test_refuse_error_parsing() {
    let refuse_payload = BytesMut::from(
        &b"(DESCRIPTION=(TMP=)(VSNNUM=318767104)(ERR=12514)(ERROR_STACK=(DESC=(CODE=12514)(EMERG=...))))"[..],
    );
    let pkt = RawPacket {
        packet_type: PacketType::Refuse,
        flag: 0,
        payload: refuse_payload,
    };
    let err = parse_refuse_error(&pkt);
    let err_str = err.to_string();
    assert!(err_str.contains("ORA-12514"));
}

#[test]
fn test_marker_packet() {
    let marker = build_marker_packet(0, 0);
    assert_eq!(marker.packet_type, PacketType::Marker);
    assert_eq!(&marker.payload[..], &[0, 0]);
}

#[test]
fn test_ttc_writer_and_reader_keyval() {
    let mut writer = TtcWriter::new();
    writer.put_key_val_string("AUTH_TERMINAL", "myhost", 1);
    let mut bytes = writer.freeze();

    let mut reader = TtcReader::new(&mut bytes);
    let (k, v, num) = reader.get_key_val().unwrap();
    assert_eq!(k, "AUTH_TERMINAL");
    assert_eq!(v, "myhost");
    assert_eq!(num, 1);
}

#[test]
fn test_parse_accept_packet() {
    let mut payload = BytesMut::with_capacity(32);
    // version = 319 (0x013F)
    payload.extend_from_slice(&0x013Fu16.to_be_bytes());
    // options = 0x0000
    payload.extend_from_slice(&0u16.to_be_bytes());
    // sdu = 8192
    payload.extend_from_slice(&8192u16.to_be_bytes());
    // tdu = 8192
    payload.extend_from_slice(&8192u16.to_be_bytes());
    // histone, buffer_len, offset (6 bytes)
    payload.extend_from_slice(&[0u8; 6]);
    // acfl0 = 1, acfl1 = 1
    payload.extend_from_slice(&[1, 1]);
    // padding up to 24 bytes
    payload.extend_from_slice(&[0u8; 8]);
    // 32-bit sdu / tdu
    payload.extend_from_slice(&8192u32.to_be_bytes());
    payload.extend_from_slice(&8192u32.to_be_bytes());

    let pkt = RawPacket {
        packet_type: PacketType::Accept,
        flag: 0,
        payload,
    };

    let accept = parse_accept_packet(&pkt).unwrap();
    assert_eq!(accept.version, 319);
    assert_eq!(accept.sdu, 8192);
    assert_eq!(accept.tdu, 8192);
    assert_eq!(accept.acfl0, 1);
    assert_eq!(accept.acfl1, 1);
}

