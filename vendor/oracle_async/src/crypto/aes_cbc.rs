use aes::{Aes128, Aes192, Aes256};
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use aes::cipher::block_padding::NoPadding;
use crate::error::{Error, Result};

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes192CbcEnc = cbc::Encryptor<Aes192>;
type Aes192CbcDec = cbc::Decryptor<Aes192>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

const IV: [u8; 16] = [0u8; 16];

pub fn pkcs5_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut out = Vec::with_capacity(data.len() + pad_len);
    out.extend_from_slice(data);
    out.resize(data.len() + pad_len, pad_len as u8);
    out
}

pub fn pkcs5_unpad(data: &[u8], block_size: usize) -> Result<&[u8]> {
    if data.is_empty() || data.len() % block_size != 0 {
        return Err(Error::Decode("invalid encrypted block length".into()));
    }
    let pad_len = *data.last().unwrap() as usize;
    if pad_len == 0 || pad_len > block_size || pad_len > data.len() {
        return Ok(data);
    }
    for &b in &data[data.len() - pad_len..] {
        if b as usize != pad_len {
            return Ok(data);
        }
    }
    Ok(&data[..data.len() - pad_len])
}

/// 裸 CBC 解密（整块，无去填充语义）
fn raw_decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(Error::Decode("ciphertext length must be a non-empty multiple of 16".into()));
    }
    match key.len() {
        16 => {
            let k: &[u8; 16] = key.try_into().map_err(|_| Error::Decode("invalid key length".into()))?;
            Aes128CbcDec::new(k.into(), (&IV).into())
                .decrypt_padded_vec::<NoPadding>(ciphertext)
                .map_err(|e| Error::Decode(format!("AES-128 decrypt error: {e}")))
        }
        24 => {
            let k: &[u8; 24] = key.try_into().map_err(|_| Error::Decode("invalid key length".into()))?;
            Aes192CbcDec::new(k.into(), (&IV).into())
                .decrypt_padded_vec::<NoPadding>(ciphertext)
                .map_err(|e| Error::Decode(format!("AES-192 decrypt error: {e}")))
        }
        32 => {
            let k: &[u8; 32] = key.try_into().map_err(|_| Error::Decode("invalid key length".into()))?;
            Aes256CbcDec::new(k.into(), (&IV).into())
                .decrypt_padded_vec::<NoPadding>(ciphertext)
                .map_err(|e| Error::Decode(format!("AES-256 decrypt error: {e}")))
        }
        other => Err(Error::Decode(format!("invalid AES key length: {other}"))),
    }
}

/// Decrypt AES-CBC ciphertext with an all-zero 16-byte IV.
///
/// padding 语义对照 go-ora decryptSessionKey：先裸解密整块，padding=true 时
/// **容忍式**裁剪——尾部恰好构成合法 PKCS7 才裁，否则原样返回（绝不报错；
/// Oracle 的会话密钥并非总是 PKCS7 填充，取决于服务器 caps[4]&2）。
pub fn decrypt_cbc(key: &[u8], ciphertext: &[u8], padding: bool) -> Result<Vec<u8>> {
    let mut out = raw_decrypt(key, ciphertext)?;
    if padding {
        let num = *out.last().unwrap() as usize;
        if num > 0 && num < 16 && num <= out.len()
            && out[out.len() - num..].iter().all(|&b| b as usize == num)
        {
            let keep = out.len() - num;
            out.truncate(keep);
        }
    }
    Ok(out)
}

/// 裸 CBC 加密（整块明文）
fn raw_encrypt(key: &[u8], padded: &[u8]) -> Result<Vec<u8>> {
    if padded.is_empty() || padded.len() % 16 != 0 {
        return Err(Error::Decode("padded plaintext must be a non-empty multiple of 16".into()));
    }
    match key.len() {
        16 => {
            let k: &[u8; 16] = key.try_into().map_err(|_| Error::Decode("invalid key length".into()))?;
            Ok(Aes128CbcEnc::new(k.into(), (&IV).into()).encrypt_padded_vec::<NoPadding>(padded))
        }
        24 => {
            let k: &[u8; 24] = key.try_into().map_err(|_| Error::Decode("invalid key length".into()))?;
            Ok(Aes192CbcEnc::new(k.into(), (&IV).into()).encrypt_padded_vec::<NoPadding>(padded))
        }
        32 => {
            let k: &[u8; 32] = key.try_into().map_err(|_| Error::Decode("invalid key length".into()))?;
            Ok(Aes256CbcEnc::new(k.into(), (&IV).into()).encrypt_padded_vec::<NoPadding>(padded))
        }
        other => Err(Error::Decode(format!("invalid AES key length: {other}"))),
    }
}

/// Encrypt AES-CBC plaintext with an all-zero 16-byte IV.
///
/// padding 语义对照 go-ora encryptSessionKey：恒先做 PKCS5 填充并整块加密；
/// padding=true 返回完整密文，padding=false 把密文**截回明文原长**（会话
/// 密钥恒为 32/48 字节块对齐，截断即丢掉纯填充块）。
pub fn encrypt_cbc(key: &[u8], plaintext: &[u8], padding: bool) -> Result<Vec<u8>> {
    let padded = pkcs5_pad(plaintext, 16);
    let mut ct = raw_encrypt(key, &padded)?;
    if !padding {
        ct.truncate(plaintext.len());
    }
    Ok(ct)
}

/// Decrypt server session key given in hexadecimal string.
pub fn decrypt_session_key(padding: bool, key: &[u8], hex_session_key: &str) -> Result<Vec<u8>> {
    let ciphertext = hex::decode(hex_session_key)
        .map_err(|e| Error::Decode(format!("invalid hex server session key: {e}")))?;
    decrypt_cbc(key, &ciphertext, padding)
}

/// Encrypt client session key and return uppercase hex string.
pub fn encrypt_session_key(padding: bool, key: &[u8], session_key: &[u8]) -> Result<String> {
    let encrypted = encrypt_cbc(key, session_key, padding)?;
    Ok(hex::encode_upper(encrypted))
}

/// Encrypt password with random 16-byte prefix.
pub fn encrypt_password(password: &[u8], key: &[u8], padding: bool) -> Result<String> {
    let mut buf = Vec::with_capacity(16 + password.len());
    let mut prefix = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut prefix);
    buf.extend_from_slice(&prefix);
    buf.extend_from_slice(password);
    encrypt_session_key(padding, key, &buf)
}
