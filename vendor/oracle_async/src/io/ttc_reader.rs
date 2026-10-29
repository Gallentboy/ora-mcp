use bytes::{Buf, BytesMut};
use crate::error::{Error, Result};

pub struct TtcReader<'a> {
    pub buf: &'a mut BytesMut,
    pub use_big_clr_chunks: bool,
}

impl<'a> TtcReader<'a> {
    pub fn new(buf: &'a mut BytesMut) -> Self {
        Self {
            buf,
            use_big_clr_chunks: false,
        }
    }

    pub fn remaining(&self) -> usize {
        self.buf.remaining()
    }

    pub fn get_byte(&mut self) -> Result<u8> {
        if self.buf.remaining() < 1 {
            return Err(Error::Decode("unexpected EOF reading byte".into()));
        }
        Ok(self.buf.get_u8())
    }

    pub fn get_bytes(&mut self, length: usize) -> Result<Vec<u8>> {
        if self.buf.remaining() < length {
            return Err(Error::Decode(format!(
                "unexpected EOF: need {length} bytes, have {}",
                self.buf.remaining()
            )));
        }
        let mut out = vec![0u8; length];
        self.buf.copy_to_slice(&mut out);
        Ok(out)
    }

    pub fn get_int64(&mut self, size: usize, compress: bool, big_endian: bool) -> Result<i64> {
        let mut actual_size = size;
        let mut neg_flag = false;
        let mut is_big_endian = big_endian;

        if compress {
            let b = self.get_byte()? as usize;
            if b & 0x80 != 0 {
                neg_flag = true;
                actual_size = b & 0x7F;
            } else {
                actual_size = b;
            }
            is_big_endian = true;
        }

        if actual_size == 0 {
            return Ok(0);
        }
        if actual_size > 8 {
            return Err(Error::Decode(format!("invalid int size: {actual_size}")));
        }

        let rb = self.get_bytes(actual_size)?;
        let mut temp = [0u8; 8];

        let mut ret = if is_big_endian {
            temp[8 - actual_size..].copy_from_slice(&rb);
            i64::from_be_bytes(temp)
        } else {
            temp[..actual_size].copy_from_slice(&rb);
            i64::from_le_bytes(temp)
        };

        if neg_flag {
            ret = -ret;
        }
        Ok(ret)
    }

    pub fn get_int(&mut self, size: usize, compress: bool, big_endian: bool) -> Result<i32> {
        let val = self.get_int64(size, compress, big_endian)?;
        Ok(val as i32)
    }

    pub fn get_null_term_string(&mut self, max_len: usize) -> Result<String> {
        let mut bytes = Vec::new();
        while self.buf.has_remaining() && bytes.len() < max_len {
            let b = self.buf.get_u8();
            if b == 0 {
                break;
            }
            bytes.push(b);
        }
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    pub fn get_clr(&mut self) -> Result<Option<Vec<u8>>> {
        let nb = self.get_byte()?;
        if nb == 0 || nb == 0xFF || nb == 0xFD {
            return Ok(None);
        }

        let mut chunk_size = nb as usize;
        let mut temp = Vec::new();

        if chunk_size == 0xFE {
            loop {
                chunk_size = if self.use_big_clr_chunks {
                    self.get_int(4, true, true)? as usize
                } else {
                    self.get_byte()? as usize
                };
                if chunk_size == 0 {
                    break;
                }
                let chunk = self.get_bytes(chunk_size)?;
                temp.extend_from_slice(&chunk);
            }
        } else {
            let chunk = self.get_bytes(chunk_size)?;
            temp.extend_from_slice(&chunk);
        }

        Ok(Some(temp))
    }

    pub fn get_dlc(&mut self) -> Result<Option<Vec<u8>>> {
        let length = self.get_int(4, true, true)? as usize;
        if length > 0 {
            if let Some(mut bytes) = self.get_clr()? {
                if bytes.len() > length {
                    bytes.truncate(length);
                }
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    pub fn get_key_val(&mut self) -> Result<(String, String, i32)> {
        let key_bytes = self.get_dlc()?.unwrap_or_default();
        let val_bytes = self.get_dlc()?.unwrap_or_default();
        let num = self.get_int(4, true, true)?;
        Ok((
            String::from_utf8_lossy(&key_bytes).to_string(),
            String::from_utf8_lossy(&val_bytes).to_string(),
            num,
        ))
    }
}
