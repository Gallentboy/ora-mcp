use std::fmt;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OracleError {
    pub code: i32,
    pub message: String,
}

impl fmt::Display for OracleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ORA-{:05}: {}", self.code, self.message)
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TNS Protocol error: {0}")]
    Protocol(String),

    #[error("Oracle Server error: {0}")]
    Server(OracleError),

    #[error("Connection refused by listener: {0}")]
    Refused(String),

    #[error("Connection redirect received: {addr}")]
    Redirect { addr: String, reconnect_data: String },

    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("Type decode error: {0}")]
    Decode(String),

    #[error("Unsupported TNS data type: {0}")]
    UnsupportedType(u8),

    #[error("Conversion error: {0}")]
    FromValue(String),

    #[error("Connection pool exhausted or closed")]
    PoolClosed,

    #[error("Operation timed out")]
    Timeout,
}

pub type Result<T> = std::result::Result<T, Error>;
