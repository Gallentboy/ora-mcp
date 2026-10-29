//! Oracle 字符集编解码（go-ora converters/string_conversion 语义的
//! encoding_rs 等价实现）。真机踩坑：服务器字符集 852 = ZHS16GBK（双字节，
//! 中文注释/数据全走它），此前 from_utf8_lossy 直接乱码。
//!
//! 常用字符集 ID（go-ora NewStringConverter 分派口径）：
//! - 870/871/872/873：UTF-8 直通（AL32UTF8 族）
//! - 2000：UTF-16BE、2002：UTF-16LE（国家字符集 AL16UTF16）
//! - 852 (0x354)：ZHS16GBK（CharWidth 2）
//! - 1：US7ASCII；其余单字节集按 Windows 单字节最优努力
//!
//! GBK 与 GB18030 的选用（真机探针实测）：解码用 **GB18030**（GBK 的国标
//! 超集，对合法 GBK 数据解码完全一致，且对 GBK 未定义边界字节更健壮）；
//! 编码方向两者都不能直接用——GBK.encode 遇不可表示字符会注入 HTML 数字
//! 引用（`a&#128512;b`，WHATWG 行为），GB18030.encode 会输出服务器
//! （ZHS16GBK）不认识的 4 字节序列——改逐字符 GBK 编码、不可表示替换 '?'
//!（go-ora eReplace 口径）。

use encoding_rs::{GBK, GB18030, UTF_16BE, UTF_16LE};

/// 字节流按 Oracle 字符集 ID 解码为 Rust String（损失性，绝不失败）
pub fn decode(bytes: &[u8], charset_id: u32) -> String {
    match charset_id {
        870..=873 => String::from_utf8_lossy(bytes).into_owned(),
        2000 => {
            let (cow, _, _) = UTF_16BE.decode(bytes);
            cow.into_owned()
        }
        2002 => {
            let (cow, _, _) = UTF_16LE.decode(bytes);
            cow.into_owned()
        }
        852 => {
            // 解码用超集 GB18030：合法 GBK 数据结果与 GBK 解码器完全一致，
            // 边界字节更健壮
            let (cow, _, _) = GB18030.decode(bytes);
            cow.into_owned()
        }
        // US7ASCII 与未知单字节集：ASCII 透通 + 非法字节替换
        _ => bytes.iter().map(|&b| {
            if b.is_ascii() { b as char } else { '\u{FFFD}' }
        }).collect(),
    }
}

/// Rust String 按 Oracle 字符集 ID 编码为字节流（ASCII 恒无损；
/// GBK 编码失败字符替换为 '?'，与 go-ora eReplace 口径一致）
pub fn encode(text: &str, charset_id: u32) -> Vec<u8> {
    match charset_id {
        870..=873 => text.as_bytes().to_vec(),
        2000 => {
            let (cow, _, _) = UTF_16BE.encode(text);
            cow.into_owned()
        }
        2002 => {
            let (cow, _, _) = UTF_16LE.encode(text);
            cow.into_owned()
        }
        852 => {
            // 逐字符 GBK 编码：不可表示字符替换 '?'（eReplace 口径）。
            // 不能整串 GBK.encode（会注入 HTML 数字引用），也不能
            // GB18030.encode（4 字节序列服务器不认识）
            use encoding_rs::EncoderResult;
            let mut encoder = GBK.new_encoder();
            let mut out = Vec::with_capacity(text.len());
            let mut ch_buf = [0u8; 4];
            let mut dst = [0u8; 4];
            for ch in text.chars() {
                if ch.is_ascii() {
                    out.push(ch as u8);
                    continue;
                }
                let s = ch.encode_utf8(&mut ch_buf);
                let (res, _, written) =
                    encoder.encode_from_utf8_without_replacement(s, &mut dst, true);
                match res {
                    EncoderResult::InputEmpty => out.extend_from_slice(&dst[..written]),
                    _ => out.push(b'?'),
                }
            }
            out
        }
        _ => text.chars().map(|c| if c.is_ascii() { c as u8 } else { b'?' }).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gbk_roundtrip_chinese() {
        let s = "中文注释测试：取号机加锁";
        let enc = encode(s, 852);
        assert_ne!(enc, s.as_bytes(), "GBK 编码应非 UTF-8");
        let dec = decode(&enc, 852);
        assert_eq!(dec, s);
    }

    #[test]
    fn utf8_charset_passthrough() {
        let s = "hello 中文";
        assert_eq!(decode(&encode(s, 871), 871), s);
    }

    #[test]
    fn ascii_always_safe() {
        assert_eq!(decode(b"SELECT 1", 852), "SELECT 1");
        assert_eq!(encode("ABC", 852), b"ABC");
    }

    #[test]
    fn gbk_unencodable_replaced_with_question() {
        // emoji 不在 GBK：替换 '?'（不注入 HTML 数字引用、不出 4 字节序列）
        assert_eq!(encode("a\u{1F600}b", 852), b"a?b");
    }

    #[test]
    fn gbk_superset_decode_edge_bytes() {
        // 解码用 GB18030 超集：GBK 未定义边界字节不整串报废
        let mixed = [0xD6, 0xD0, 0xCE, 0xC4]; // “中文” GBK
        assert_eq!(decode(&mixed, 852), "中文");
        // 生僻汉字（GBK 收录）往返
        let s = "堃喆淼犇";
        assert_eq!(decode(&encode(s, 852), 852), s);
    }
}
