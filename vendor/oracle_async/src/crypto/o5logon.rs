use des::Des;
use des::cipher::{BlockEncrypt, KeyInit};
use crate::error::Result;

/// Oracle 10g O5Logon key derivation from uppercase username and password using DES.
pub fn get_key_from_user_password(username: &str, password: &str) -> Result<[u8; 16]> {
    let u = username.to_uppercase();
    let p = password.to_uppercase();

    let mut buffer = Vec::with_capacity((u.len() + p.len()) * 2 + 8);
    for b in u.bytes() {
        buffer.push(0);
        buffer.push(b);
    }
    for b in p.bytes() {
        buffer.push(0);
        buffer.push(b);
    }
    while buffer.len() % 8 != 0 {
        buffer.push(0);
    }

    let initial_key: [u8; 8] = [1, 35, 69, 103, 137, 171, 205, 239];

    let des_enc = |input: &[u8], key: &[u8; 8]| -> [u8; 8] {
        let cipher = Des::new(key.into());
        let mut ret = [0u8; 8];
        for chunk in input.chunks_exact(8) {
            for y in 0..8 {
                ret[y] ^= chunk[y];
            }
            let mut block = des::cipher::generic_array::GenericArray::clone_from_slice(&ret);
            cipher.encrypt_block(&mut block);
            ret.copy_from_slice(&block);
        }
        ret
    };

    let key1 = des_enc(&buffer, &initial_key);
    let key2 = des_enc(&buffer, &key1);

    let mut final_key = [0u8; 16];
    final_key[..8].copy_from_slice(&key2);
    // last 8 bytes are 0
    Ok(final_key)
}
