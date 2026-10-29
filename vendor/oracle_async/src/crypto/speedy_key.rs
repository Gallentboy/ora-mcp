use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

/// Oracle 12c+ PBKDF2 SpeedyKey algorithm (custom PBKDF2 variant).
///
/// In round 1, computes HMAC-SHA512(key=password, msg=message || [0, 0, 0, 1]).
/// For subsequent rounds (2..=turns), computes HMAC-SHA512(key=password, msg=prev_hash)
/// and XORs into the accumulator.
pub fn generate_speedy_key(message: &[u8], key: &[u8], turns: usize) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC supports any key length");
    mac.update(message);
    mac.update(&[0, 0, 0, 1]);
    let first_hash = mac.finalize().into_bytes();

    let mut result = [0u8; 64];
    result.copy_from_slice(&first_hash[..]);

    let mut temp_hash = result;

    for _ in 2..=turns {
        let mut mac = HmacSha512::new_from_slice(key).expect("HMAC supports any key length");
        mac.update(&temp_hash);
        let current = mac.finalize().into_bytes();
        temp_hash.copy_from_slice(&current[..]);

        for i in 0..64 {
            result[i] ^= temp_hash[i];
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_speedy_key_deterministic() {
        let salt = b"0123456789abcdef";
        let mut msg = salt.to_vec();
        msg.extend_from_slice(b"AUTH_PBKDF2_SPEEDY_KEY");
        let pass = b"tiger";
        let k1 = generate_speedy_key(&msg, pass, 3);
        let k2 = generate_speedy_key(&msg, pass, 3);
        assert_eq!(k1, k2);
        assert_ne!(k1, [0u8; 64]);
    }
}
