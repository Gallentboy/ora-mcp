pub mod handshake;
pub mod advanced_nego;
pub mod ttc_nego;
pub mod data_type_nego;
pub mod auth;
pub mod summary;
pub mod db_version;
pub mod row_common;
pub mod bind;
pub mod nls;
pub mod lob;
pub mod udt;
pub mod ping;
pub mod exec;
pub mod fetch;

use async_trait::async_trait;
use crate::conn::Conn;
use crate::error::Result;

#[async_trait]
pub trait Routine<T> {
    async fn call(&mut self, conn: &mut Conn) -> Result<T>;
}
