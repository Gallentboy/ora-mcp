use bytes::{BufMut, BytesMut};

pub struct TtcWriter {
    pub buf: BytesMut,
    pub clr_chunk_size: usize,
    pub use_big_clr_chunks: bool,
}

impl Default for TtcWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl TtcWriter {
    pub fn new() -> Self {
        Self {
            buf: BytesMut::with_capacity(1024),
            clr_chunk_size: 64,
            use_big_clr_chunks: false,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: BytesMut::with_capacity(capacity),
            clr_chunk_size: 64,
            use_big_clr_chunks: false,
        }
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn put_byte(&mut self, b: u8) {
        self.buf.put_u8(b);
    }

    pub fn put_bytes(&mut self, data: &[u8]) {
        self.buf.put_slice(data);
    }

    pub fn put_uint(&mut self, num: u64, size: u8, big_endian: bool, compress: bool) {
        if size == 1 {
            self.buf.put_u8(num as u8);
            return;
        }

        if compress {
            let be_bytes = num.to_be_bytes();
            let mut start = 0;
            while start < 8 && be_bytes[start] == 0 {
                start += 1;
            }
            let valid = &be_bytes[start..];
            let actual_size = (size as usize).min(valid.len());

            if actual_size == 0 {
                self.buf.put_u8(0);
            } else {
                self.buf.put_u8(actual_size as u8);
                self.buf.put_slice(&valid[..actual_size]);
            }
        } else {
            match size {
                2 => {
                    if big_endian {
                        self.buf.put_u16(num as u16);
                    } else {
                        self.buf.put_u16_le(num as u16);
                    }
                }
                4 => {
                    if big_endian {
                        self.buf.put_u32(num as u32);
                    } else {
                        self.buf.put_u32_le(num as u32);
                    }
                }
                8 => {
                    if big_endian {
                        self.buf.put_u64(num);
                    } else {
                        self.buf.put_u64_le(num);
                    }
                }
                _ => self.buf.put_u8(num as u8),
            }
        }
    }

    pub fn put_int(&mut self, num: i64, size: u8, big_endian: bool, compress: bool) {
        if compress {
            let be_bytes = (num as u64).to_be_bytes();
            let mut start = 0;
            while start < 8 && be_bytes[start] == 0 {
                start += 1;
            }
            let valid = &be_bytes[start..];
            let actual_size = (size as usize).min(valid.len());

            if actual_size == 0 {
                self.buf.put_u8(0);
            } else {
                self.buf.put_u8(actual_size as u8);
                self.buf.put_slice(&valid[..actual_size]);
            }
        } else {
            self.put_uint(num as u64, size, big_endian, false);
        }
    }

    pub fn put_clr(&mut self, data: &[u8]) {
        let len = data.len();
        if len > 0xFC {
            self.buf.put_u8(0xFE);
            let mut start = 0;
            while start < len {
                let end = (start + self.clr_chunk_size).min(len);
                let chunk = &data[start..end];
                if self.use_big_clr_chunks {
                    self.put_int(chunk.len() as i64, 4, true, true);
                } else {
                    self.buf.put_u8(chunk.len() as u8);
                }
                self.buf.put_slice(chunk);
                start += self.clr_chunk_size;
            }
            self.buf.put_u8(0);
        } else if len == 0 {
            self.buf.put_u8(0);
        } else {
            self.buf.put_u8(len as u8);
            self.buf.put_slice(data);
        }
    }

    pub fn put_key_val(&mut self, key: &[u8], val: &[u8], num: u8) {
        if key.is_empty() {
            self.buf.put_u8(0);
        } else {
            self.put_uint(key.len() as u64, 4, true, true);
            self.put_clr(key);
        }

        if val.is_empty() {
            self.buf.put_u8(0);
        } else {
            self.put_uint(val.len() as u64, 4, true, true);
            self.put_clr(val);
        }

        self.put_int(num as i64, 4, true, true);
    }

    pub fn put_key_val_string(&mut self, key: &str, val: &str, num: u8) {
        self.put_key_val(key.as_bytes(), val.as_bytes(), num);
    }

    pub fn freeze(self) -> BytesMut {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::ttc_reader::TtcReader;

    #[test]
    fn test_clr_roundtrip() {
        let mut writer = TtcWriter::new();
        writer.put_clr(b"test string clr");
        let mut bytes = writer.freeze();

        let mut reader = TtcReader::new(&mut bytes);
        let decoded = reader.get_clr().unwrap().unwrap();
        assert_eq!(&decoded[..], b"test string clr");
    }

    #[test]
    fn test_compressed_int_roundtrip() {
        let mut writer = TtcWriter::new();
        writer.put_int(1234567, 4, true, true);
        let mut bytes = writer.freeze();

        let mut reader = TtcReader::new(&mut bytes);
        let val = reader.get_int(4, true, true).unwrap();
        assert_eq!(val, 1234567);
    }
}
