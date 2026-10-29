use rust_decimal::Decimal;
use std::str::FromStr;
use crate::error::{Error, Result};

pub fn is_zero(b: &[u8]) -> bool {
    b.len() == 1 && b[0] == 128
}

pub fn is_positive(b: &[u8]) -> bool {
    !b.is_empty() && (b[0] & 128) != 0
}

/// Convert Oracle internal NUMBER bytes into a standard ASCII numeric string.
pub fn decode_number(b: &[u8]) -> Result<String> {
    if b.is_empty() {
        return Err(Error::Decode("empty Oracle number bytes".into()));
    }
    if is_zero(b) {
        return Ok("0".into());
    }
    if b == [255, 101] {
        return Ok("Infinity".into());
    }
    if b == [0] {
        return Ok("-Infinity".into());
    }

    let positive = is_positive(b);
    let mut data = Vec::with_capacity(b.len());

    if positive {
        data.push((b[0] & 0x7F).wrapping_sub(65) as i8);
        for &byte in &b[1..] {
            data.push(byte.wrapping_sub(1) as i8);
        }
    } else {
        let actual_len = if b.len() == 21 && *b.last().unwrap() != 102 {
            b.len()
        } else {
            b.len().saturating_sub(1)
        };
        data.push((((b[0] ^ 0xFF) & 0x7F).wrapping_sub(65)) as i8);
        for &byte in &b[1..actual_len] {
            data.push((101u8.wrapping_sub(byte)) as i8);
        }
    }

    let mut exponent = data[0] as i32;
    let real_data_len = data.len() - 1;
    let k = exponent - (real_data_len as i32 - 1);

    let mut result = String::with_capacity(64);
    if !positive {
        result.push('-');
    }

    if k >= 0 {
        result.push_str(&format!("{}", data[1]));
        let mut b1 = 2;
        while b1 <= real_data_len {
            result.push_str(&format!("{:02}", data[b1]));
            b1 += 1;
            exponent -= 1;
        }
        while exponent > 0 {
            result.push_str("00");
            exponent -= 1;
        }
    } else {
        let n = real_data_len as i32 + k;
        if n > 0 {
            result.push_str(&format!("{}", data[1]));
            if n == 1 {
                result.push('.');
            }
            let mut b1 = 2;
            while b1 < real_data_len {
                result.push_str(&format!("{:02}", data[b1]));
                if n == b1 as i32 {
                    result.push('.');
                }
                b1 += 1;
            }
            if b1 <= real_data_len {
                if data[b1] % 10 == 0 {
                    result.push_str(&format!("{}", data[b1] / 10));
                } else {
                    result.push_str(&format!("{:02}", data[b1]));
                }
            }
        } else {
            result.push_str("0.");
            let mut padding = n;
            while padding < 0 {
                result.push_str("00");
                padding += 1;
            }
            for val in data.iter().take(real_data_len).skip(1) {
                result.push_str(&format!("{:02}", val));
            }
            if real_data_len >= 1 {
                let last = data[real_data_len];
                if last % 10 == 0 {
                    result.push_str(&format!("{}", last / 10));
                } else {
                    result.push_str(&format!("{:02}", last));
                }
            }
        }
    }

    Ok(result)
}

/// NUMBER 字节 → i64（逐单元格调用的热点包装，内联收益明确）
#[inline]
pub fn decode_number_to_i64(b: &[u8]) -> Result<i64> {
    let s = decode_number(b)?;
    s.parse::<i64>().map_err(|e| Error::Decode(format!("failed to parse i64 from '{s}': {e}")))
}

/// NUMBER 字节 → f64（同上，逐单元格热点）
#[inline]
pub fn decode_number_to_f64(b: &[u8]) -> Result<f64> {
    let s = decode_number(b)?;
    s.parse::<f64>().map_err(|e| Error::Decode(format!("failed to parse f64 from '{s}': {e}")))
}

/// NUMBER 字节 → Decimal（同上，逐单元格热点）
#[inline]
pub fn decode_number_to_decimal(b: &[u8]) -> Result<Decimal> {
    let s = decode_number(b)?;
    Decimal::from_str(&s).map_err(|e| Error::Decode(format!("failed to parse Decimal from '{s}': {e}")))
}

/// Oracle NUMBER 编码核心——go-ora `(*Number).encode` 逐字节复刻。
///
/// mantissa 是十进制数字串（无符号无小数点），exp 是十进制指数（科学计数
/// 法口径：值 = 0.<mantissa> × 10^(exp+1)），negative 为符号。
/// 算法：去尾零 → 指数为偶数时左补一个 '0' 使长度成偶数 → 每两位合成一个
/// base-100 位（负数取 100-b 补数）→ 首字节写指数（正 = exp/2+1|0x80、
/// 负 = ^(exp/2+1+64)）→ 负数且位数 <21 时尾部补 0x66 终止标记。
fn encode_mantissa(mantissa: &str, mut exp: i32, negative: bool) -> Vec<u8> {
    let mut m: Vec<u8> = mantissa.bytes().collect();
    // 去尾零
    while m.len() > 1 && *m.last().unwrap() == b'0' {
        m.pop();
    }
    if m.is_empty() || m.iter().all(|&b| b == b'0') {
        return vec![0x80];
    }
    if exp % 2 == 0 {
        m.insert(0, b'0');
    }
    let mantissa_len = m.len();
    let mut size = 1 + mantissa_len.div_ceil(2);
    if negative && mantissa_len < 21 {
        size += 1;
    }
    let mut data = vec![0u8; size];

    let mut i = 0;
    while i < mantissa_len {
        let mut b = 10 * (m[i] - b'0');
        if i < mantissa_len - 1 {
            b += m[i + 1] - b'0';
        }
        if negative {
            b = 100 - b;
        }
        data[1 + i / 2] = b + 1;
        i += 2;
    }

    if negative && mantissa_len < 21 {
        let last = data.len() - 1;
        data[last] = 0x66;
    }

    if exp < 0 {
        exp -= 1;
    }
    exp = (exp / 2) + 1;
    data[0] = if negative {
        (exp + 64) as u8 ^ 0x7f
    } else {
        (exp + 64) as u8 | 0x80
    };
    data
}

/// i64 → Oracle NUMBER 字节（go-ora NewNumberFromInt64 → encode）
pub fn encode_i64_to_number(val: i64) -> Vec<u8> {
    if val == 0 {
        return vec![0x80];
    }
    let s = val.unsigned_abs().to_string();
    let exp = s.len() as i32 - 1;
    encode_mantissa(&s, exp, val < 0)
}

/// u64 → Oracle NUMBER 字节（go-ora NewNumberFromUint64）
pub fn encode_u64_to_number(val: u64) -> Vec<u8> {
    if val == 0 {
        return vec![0x80];
    }
    let s = val.to_string();
    let exp = s.len() as i32 - 1;
    encode_mantissa(&s, exp, false)
}

/// 十进制字符串 → Oracle NUMBER（go-ora NewNumberFromString：支持小数与
/// 科学计数法 e/E）
pub fn encode_decimal_str_to_number(val: &str) -> Result<Vec<u8>> {
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return Err(Error::Decode("empty number string".into()));
    }
    let negative = trimmed.starts_with('-');
    let mut mantissa = if negative || trimmed.starts_with('+') {
        trimmed[1..].to_string()
    } else {
        trimmed.to_string()
    };

    let mut exp: i32 = 0;
    // 科学计数法
    if let Some(i) = mantissa.find(['e', 'E']) {
        let exp_str = mantissa[i + 1..].to_string();
        exp = exp_str
            .parse::<i32>()
            .map_err(|e| Error::Decode(format!("invalid exponent '{exp_str}': {e}")))?;
        mantissa.truncate(i);
    }
    let mut is_float = false;
    if let Some(i) = mantissa.find('.') {
        mantissa.remove(i);
        exp += i as i32 - 1;
        is_float = true;
    }
    if !is_float {
        exp += mantissa.len() as i32 - 1;
    }
    if mantissa.is_empty() || !mantissa.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Decode(format!("invalid number string: {val}")));
    }
    Ok(encode_mantissa(&mantissa, exp, negative))
}

/// f64 → Oracle NUMBER（go-ora NewNumberFromFloat：先格式化 'e' 形态）
pub fn encode_f64_to_number(val: f64) -> Result<Vec<u8>> {
    if val == 0.0 {
        return Ok(vec![0x80]);
    }
    if val.is_nan() {
        return Err(Error::Decode("NaN cannot be encoded as Oracle NUMBER".into()));
    }
    if val.is_infinite() {
        return Ok(if val > 0.0 { vec![255, 101] } else { vec![0] });
    }
    // Rust 的 {:e} 与 Go 的 'e' 格式同为「d.dddde±N」形态
    let formatted = format!("{val:e}");
    encode_decimal_str_to_number(&formatted)
}

/// Decimal → Oracle NUMBER（走字符串，保持精度）
pub fn encode_decimal_to_number(val: &Decimal) -> Result<Vec<u8>> {
    encode_decimal_str_to_number(&val.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero() {
        assert_eq!(decode_number(&[128]).unwrap(), "0");
        assert_eq!(encode_i64_to_number(0), vec![128]);
    }

    #[test]
    fn test_positive_integers() {
        let b = encode_i64_to_number(1);
        assert_eq!(decode_number(&b).unwrap(), "1");

        let b = encode_i64_to_number(100);
        assert_eq!(decode_number(&b).unwrap(), "100");

        let b = encode_i64_to_number(123456);
        assert_eq!(decode_number(&b).unwrap(), "123456");
    }

    #[test]
    fn test_negative_integers() {
        let b = encode_i64_to_number(-1);
        assert_eq!(decode_number(&b).unwrap(), "-1");

        let b = encode_i64_to_number(-100);
        assert_eq!(decode_number(&b).unwrap(), "-100");

        let b = encode_i64_to_number(-123456);
        assert_eq!(decode_number(&b).unwrap(), "-123456");
    }
}

#[cfg(test)]
mod encode_tests {
    use super::*;

    /// 编码→解码往返（go-ora encode 算法的正确性锚点）
    #[test]
    fn roundtrip_integers() {
        for v in [0i64, 1, -1, 9, -9, 42, -42, 100, -100, 101, 9999,
                  123456789, -123456789, i64::MAX, i64::MIN + 1] {
            let enc = encode_i64_to_number(v);
            let dec = decode_number_to_i64(&enc).unwrap();
            assert_eq!(dec, v, "roundtrip failed for {v} (bytes {enc:02x?})");
        }
    }

    #[test]
    fn roundtrip_u64() {
        for v in [0u64, 1, 255, 65535, u32::MAX as u64, u64::MAX] {
            let enc = encode_u64_to_number(v);
            let dec = decode_number_to_decimal(&enc).unwrap();
            assert_eq!(dec, Decimal::from(v), "roundtrip failed for {v}");
        }
    }

    /// 小数/科学计数法（go-ora NewNumberFromString 同口径）
    #[test]
    fn roundtrip_decimals() {
        for (s, expect) in [
            ("1.5", "1.5"),
            ("-1.5", "-1.5"),
            ("0.01", "0.01"),
            ("-0.01", "-0.01"),
            ("123.456", "123.456"),
            ("-123.456", "-123.456"),
            ("1e10", "10000000000"),
            ("1.23e-5", "0.0000123"),
            ("3.14159265358979", "3.14159265358979"),
        ] {
            let enc = encode_decimal_str_to_number(s).unwrap();
            let dec = decode_number(&enc).unwrap();
            // 数值等价比较（尾零/格式差异不算错）
            let a: Decimal = dec.parse().unwrap();
            let b: Decimal = expect.parse().unwrap();
            assert_eq!(a, b, "roundtrip failed for {s}: got {dec}");
        }
    }

    #[test]
    fn roundtrip_f64() {
        // 3.14159 是测试用的任意小数（非 PI 常量语义），clippy 会误报
        #[allow(clippy::approx_constant)]
        let values = [0.0f64, 1.0, -1.0, 0.5, -0.5, 3.14159, 1e20, -1e-20, 1234.5678];
        for v in values {
            let enc = encode_f64_to_number(v).unwrap();
            let dec = decode_number_to_f64(&enc).unwrap();
            assert!((dec - v).abs() < v.abs().max(1.0) * 1e-12, "f64 {v} -> {dec}");
        }
    }

    /// 已知向量：go-ora 对 1 与 -1 的编码（与旧实现一致，锁住字节级兼容）
    #[test]
    fn known_vectors() {
        assert_eq!(encode_i64_to_number(1), vec![193, 2]);
        assert_eq!(encode_i64_to_number(-1), vec![62, 100, 102]);
        assert_eq!(encode_i64_to_number(0), vec![128]);
    }
}
