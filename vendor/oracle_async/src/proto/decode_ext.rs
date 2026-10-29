//! 扩展类型解码——go-ora converters 的逐字节复刻。
//!
//! 覆盖 INTERVAL YEAR TO MONTH / DAY TO SECOND、BOOLEAN、VECTOR、UROWID
//! 以及 binary float/double。这些类型在工作台里以字符串/二进制展示，
//! 但必须**按协议正确解码**（否则字节错位或显示乱码）。

use rust_decimal::Decimal;
use std::str::FromStr;

/// INTERVAL YEAR TO MONTH（go-ora ConvertIntervalYM_DTY）
///
/// 前 4 字节 = 年数 + 0x80000000，第 5 字节 = 月数 + 60。
#[inline]
pub fn decode_interval_ym(val: &[u8]) -> Option<String> {
    if val.len() < 5 {
        return None;
    }
    let uyears = u32::from_be_bytes([val[0], val[1], val[2], val[3]]) as i64;
    let years = uyears - 0x8000_0000i64;
    if years >= 0 && val[4] >= 60 {
        Some(format!("+{:02}-{:02}", years, val[4] - 60))
    } else {
        Some(format!("-{:02}-{:02}", -years, 60i32 - val[4] as i32))
    }
}

/// INTERVAL DAY TO SECOND（go-ora ConvertIntervalDS_DTY）
///
/// 前 4 字节 = 天数 + 0x80000000；第 4..7 字节 = 时/分/秒 各 +60；
/// 后 4 字节 = 纳秒 + 0x80000000（输出时换算为微秒，与 go-ora 同）。
#[inline]
pub fn decode_interval_ds(val: &[u8]) -> Option<String> {
    if val.len() < 11 {
        return None;
    }
    let udays = u32::from_be_bytes([val[0], val[1], val[2], val[3]]) as i64;
    let uns = u32::from_be_bytes([val[7], val[8], val[9], val[10]]) as i64;
    let mut days = udays - 0x8000_0000i64;
    let mut ns = (uns - 0x8000_0000i64) / 1000;

    if days >= 0 && ns >= 0 && val[4] >= 60 && val[5] >= 60 && val[6] >= 60 {
        Some(format!(
            "+{:02} {:02}:{:02}:{:02}.{:06}",
            days,
            val[4] - 60,
            val[5] - 60,
            val[6] - 60,
            ns
        ))
    } else {
        days = -days;
        ns = -ns;
        Some(format!(
            "-{:02} {:02}:{:02}:{:02}.{:06}",
            days,
            60i32 - val[4] as i32,
            60i32 - val[5] as i32,
            60i32 - val[6] as i32,
            ns
        ))
    }
}

/// BOOLEAN（go-ora converters.DecodeBool：{1,1} = true）
#[inline]
pub fn decode_boolean(val: &[u8]) -> Option<bool> {
    if val.len() == 2 {
        Some(val == [1, 1])
    } else if val.len() == 1 {
        Some(val[0] != 0)
    } else {
        None
    }
}

/// BINARY_FLOAT（go-ora ConvertBinaryFloat：首字节最高位为符号约定，
/// 负数按位取反）
#[inline]
pub fn decode_binary_float(val: &[u8]) -> Option<f32> {
    if val.len() < 4 {
        return None;
    }
    let mut b = [val[0], val[1], val[2], val[3]];
    if b[0] & 128 != 0 {
        b[0] &= 127;
    } else {
        for x in &mut b {
            *x = !*x;
        }
    }
    Some(f32::from_bits(u32::from_be_bytes(b)))
}

/// BINARY_DOUBLE（go-ora ConvertBinaryDouble）
#[inline]
pub fn decode_binary_double(val: &[u8]) -> Option<f64> {
    if val.len() < 8 {
        return None;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&val[..8]);
    if b[0] & 128 != 0 {
        b[0] &= 127;
    } else {
        for x in &mut b {
            *x = !*x;
        }
    }
    Some(f64::from_bits(u64::from_be_bytes(b)))
}

/// VECTOR（go-ora vector.go decode）：magic 219 + version 0 + flag(u16) +
/// format + count（按 flag 位定宽度）+ 可选 8 字节额外头 + 元素数组。
/// 返回形如 `[1, 2, 3]` 的展示串（float32/float64/int8 三种 format）。
pub fn decode_vector(value: &[u8]) -> Option<String> {
    if value.is_empty() {
        return Some("[]".to_string());
    }
    let mut i = 0usize;
    let read = |i: &mut usize, n: usize| -> Option<&[u8]> {
        if *i + n > value.len() {
            None
        } else {
            let s = &value[*i..*i + n];
            *i += n;
            Some(s)
        }
    };

    if read(&mut i, 1)?[0] != 219 {
        return None;
    }
    if read(&mut i, 1)?[0] != 0 {
        return None;
    }
    let flag = u16::from_be_bytes(read(&mut i, 2)?.try_into().ok()?);
    let format = read(&mut i, 1)?[0];
    let count = if flag & 1 != 0 {
        read(&mut i, 1)?[0] as usize
    } else if flag & 2 != 0 {
        u32::from_be_bytes(read(&mut i, 4)?.try_into().ok()?) as usize
    } else {
        u16::from_be_bytes(read(&mut i, 2)?.try_into().ok()?) as usize
    };
    if flag & 0x10 != 0 {
        let rem = value.len().saturating_sub(i);
        i += 8.min(rem);
    }

    let mut parts: Vec<String> = Vec::with_capacity(count);
    match format {
        2 => {
            for _ in 0..count {
                let e = decode_binary_float(read(&mut i, 4)?)?;
                parts.push(format!("{e}"));
            }
        }
        3 => {
            for _ in 0..count {
                let e = decode_binary_double(read(&mut i, 8)?)?;
                parts.push(format!("{e}"));
            }
        }
        4 => {
            for _ in 0..count {
                parts.push(format!("{}", read(&mut i, 1)?[0]));
            }
        }
        _ => return None,
    }
    Some(format!("[{}]", parts.join(", ")))
}

/// UROWID 的字节 → 十六进制展示（go-ora urowid 直接透传字节）
#[inline(always)]
pub fn decode_urowid_hex(val: &[u8]) -> String {
    hex::encode_upper(val)
}

/// NUMBER 字节 → 字符串（与 oracle_number::decode_number 同源，此处仅为
/// 扩展解码模块的自洽入口）
pub fn decode_number_str(val: &[u8]) -> Option<String> {
    crate::proto::oracle_number::decode_number(val).ok()
}

/// 十进制字符串 → Decimal（宽松：失败返回 None 而非错误）
pub fn parse_decimal(s: &str) -> Option<Decimal> {
    Decimal::from_str(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_ym_positive_and_negative() {
        // +0001-02：年 1（1 + 0x80000000），月 2（62）
        let mut v = (0x8000_0001u32).to_be_bytes().to_vec();
        v.push(62);
        assert_eq!(decode_interval_ym(&v).unwrap(), "+01-02");
        // -0001-02：年 -1（0x7FFFFFFF），月 58（60-2）
        let mut v = (0x7FFF_FFFFu32).to_be_bytes().to_vec();
        v.push(58);
        assert_eq!(decode_interval_ym(&v).unwrap(), "-01-02");
    }

    #[test]
    fn interval_ds_positive() {
        // +01 02:03:04.000005
        let mut v = (0x8000_0001u32).to_be_bytes().to_vec();
        v.extend_from_slice(&[62, 63, 64]);
        v.extend_from_slice(&(0x8000_0000u32 + 5000).to_be_bytes());
        assert_eq!(decode_interval_ds(&v).unwrap(), "+01 02:03:04.000005");
    }

    #[test]
    fn boolean_values() {
        assert_eq!(decode_boolean(&[1, 1]), Some(true));
        assert_eq!(decode_boolean(&[1, 0]), Some(false));
        assert_eq!(decode_boolean(&[1]), Some(true));
    }

    #[test]
    fn binary_float_roundtrip_signs() {
        // 正数：符号位清 0（首字节最高位标记）
        let pos = 1.5f32;
        let bits = pos.to_bits();
        let mut b = bits.to_be_bytes();
        b[0] |= 128;
        assert!((decode_binary_float(&b).unwrap() - pos).abs() < 1e-6);

        let neg = -1.5f32;
        let bits = neg.to_bits();
        let mut b = bits.to_be_bytes();
        for x in &mut b {
            *x = !*x;
        }
        assert!((decode_binary_float(&b).unwrap() - neg).abs() < 1e-6);
    }

    #[test]
    fn vector_float32() {
        let mut v = vec![219, 0];
        v.extend_from_slice(&2u16.to_be_bytes()); // flag: 2 → count 为 u32
        v.push(2); // format float32
        v.extend_from_slice(&3u32.to_be_bytes()); // count = 3
        // 元素须按 EncodeFloat32 的符号变换写（正数首字节 |0x80），
        // 直接塞 to_bits() 会被解码器当成负数取反
        for x in [1.0f32, 2.0, 3.0] {
            let mut b = x.to_bits().to_be_bytes();
            if x > 0.0 {
                b[0] |= 128;
            } else {
                for y in &mut b {
                    *y = !*y;
                }
            }
            v.extend_from_slice(&b);
        }
        assert_eq!(decode_vector(&v).unwrap(), "[1, 2, 3]");
    }
}
