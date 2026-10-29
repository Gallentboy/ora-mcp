use ora_async::crypto::{
    decrypt_session_key, encrypt_password, encrypt_session_key, generate_speedy_key,
    get_key_from_user_password, pkcs5_pad, pkcs5_unpad,
};

#[test]
fn test_speedy_key_reproducible() {
    let message = b"1234567890abcdefAUTH_PBKDF2_SPEEDY_KEY";
    let password = b"OracleSecretPassword2026";
    let k1 = generate_speedy_key(message, password, 4096);
    let k2 = generate_speedy_key(message, password, 4096);
    assert_eq!(k1, k2);
    assert_ne!(k1, [0u8; 64]);
}

#[test]
fn test_aes_cbc_roundtrip_all_key_sizes() {
    // AES-128 (16 bytes)
    let key16 = [0x42u8; 16];
    let data = b"Hello Oracle TNS protocol with 16 bytes!";
    let enc16 = encrypt_session_key(true, &key16, data).unwrap();
    let dec16 = decrypt_session_key(true, &key16, &enc16).unwrap();
    assert_eq!(&dec16[..], data);

    // AES-192 (24 bytes)
    let key24 = [0x55u8; 24];
    let enc24 = encrypt_session_key(true, &key24, data).unwrap();
    let dec24 = decrypt_session_key(true, &key24, &enc24).unwrap();
    assert_eq!(&dec24[..], data);

    // AES-256 (32 bytes)
    let key32 = [0x77u8; 32];
    let enc32 = encrypt_session_key(true, &key32, data).unwrap();
    let dec32 = decrypt_session_key(true, &key32, &enc32).unwrap();
    assert_eq!(&dec32[..], data);
}

#[test]
fn test_password_encryption() {
    // AUTH_PASSWORD 恒按填充形态加密（go-ora 6949/2361 分支），完整往返
    let key32 = [0x11u8; 32];
    let password = b"tiger";
    let enc_pass = encrypt_password(password, &key32, true).unwrap();
    assert_ne!(enc_pass, "");

    let dec = decrypt_session_key(true, &key32, &enc_pass).unwrap();
    // Decrypted bytes have 16-byte random prefix + password
    assert!(dec.len() >= 16 + password.len());
    assert_eq!(&dec[16..16 + password.len()], password);
}

#[test]
fn test_session_key_unpadded_truncation_semantics() {
    // !padding：PKCS5 填充加密后密文截回原长（go-ora encryptSessionKey）。
    // 真实 AUTH_SESSKEY 恒 32/48 字节块对齐，截断即丢掉纯填充块。
    let key = [0x42u8; 16];
    let sk = [7u8; 32];
    let hexstr = encrypt_session_key(false, &key, &sk).unwrap();
    let ct = hex::decode(&hexstr).unwrap();
    assert_eq!(ct.len(), 32, "ciphertext truncated back to plaintext length");

    let dec = decrypt_session_key(false, &key, &hexstr).unwrap();
    assert_eq!(dec, sk.to_vec());
}

#[test]
fn test_decrypt_tolerant_padding_never_errors() {
    // go-ora decryptSessionKey 容忍语义：解密结果尾部不构成合法 PKCS7 时
    // 不报错、不裁剪（服务器密钥并非总是 PKCS7 填充）
    let key = [0x42u8; 16];
    let pt = vec![0x55u8; 48]; // 48 字节块对齐，尾字节 0x55 ≠ 合法填充
    let hexstr = encrypt_session_key(false, &key, &pt).unwrap();
    let dec = decrypt_session_key(true, &key, &hexstr).unwrap();
    assert_eq!(dec.len(), 48, "invalid padding tail must not trim nor error");
    assert_eq!(dec, pt);
}

#[test]
fn test_o5logon_des_key_generation() {
    let k = get_key_from_user_password("scott", "tiger").unwrap();
    assert_eq!(k.len(), 16);
    assert_eq!(&k[8..], &[0u8; 8]);
    assert_ne!(&k[..8], &[0u8; 8]);
}

#[test]
fn test_pkcs5_padding() {
    let data = b"12345";
    let padded = pkcs5_pad(data, 16);
    assert_eq!(padded.len(), 16);
    assert_eq!(padded[15], 11);

    let unpadded = pkcs5_unpad(&padded, 16).unwrap();
    assert_eq!(unpadded, data);
}
