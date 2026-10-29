use std::ops::{Deref, DerefMut};
use async_trait::async_trait;
use log::debug;
use crate::conn::Conn;
use crate::error::Result;
use crate::queryable::{QueryResult, Queryable};

pub struct Transaction<'a> {
    conn: &'a mut Conn,
    committed: bool,
}

impl<'a> Transaction<'a> {
    pub async fn new(conn: &'a mut Conn) -> Result<Self> {
        debug!("Beginning transaction");
        Ok(Self {
            conn,
            committed: false,
        })
    }

    pub async fn commit(mut self) -> Result<()> {
        debug!("Committing transaction (protocol-level 0x0E)");
        // go-ora Tx.Commit：协议级 simpleObject 0x0E，不走 SQL 文本
        self.conn.commit().await?;
        self.committed = true;
        Ok(())
    }

    pub async fn rollback(mut self) -> Result<()> {
        debug!("Rolling back transaction (protocol-level 0x0F)");
        self.conn.rollback().await?;
        self.committed = true;
        Ok(())
    }
}

impl<'a> Deref for Transaction<'a> {
    type Target = Conn;
    fn deref(&self) -> &Self::Target {
        self.conn
    }
}

impl<'a> DerefMut for Transaction<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.conn
    }
}

impl<'a> Drop for Transaction<'a> {
    fn drop(&mut self) {
        if !self.committed {
            debug!("Transaction dropped without commit; rollback expected on next reuse");
        }
    }
}

#[async_trait]
impl<'a> Queryable for Transaction<'a> {
    async fn query<'b>(&'b mut self, query: &str) -> Result<QueryResult<'b>> {
        self.conn.query(query).await
    }

    async fn exec(&mut self, query: &str) -> Result<u64> {
        self.conn.exec(query).await
    }

    async fn query_with_params<'b>(
        &'b mut self,
        query: &str,
        params: Vec<crate::conn::routines::bind::BindParam>,
    ) -> Result<QueryResult<'b>> {
        self.conn.query_with_params(query, params).await
    }

    async fn exec_with_params(
        &mut self,
        query: &str,
        params: Vec<crate::conn::routines::bind::BindParam>,
    ) -> Result<u64> {
        self.conn.exec_with_params(query, params).await
    }
}
