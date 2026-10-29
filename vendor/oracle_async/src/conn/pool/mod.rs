use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use async_trait::async_trait;
use log::{debug, info};
use tokio::sync::{Mutex, Semaphore};
use crate::conn::Conn;
use crate::error::{Error, Result};
use crate::opts::Opts;
use crate::queryable::{QueryResult, Queryable};

pub struct PoolInner {
    opts: Opts,
    idle: Mutex<Vec<Conn>>,
    semaphore: Arc<Semaphore>,
    max_conns: usize,
}

#[derive(Clone)]
pub struct Pool {
    inner: Arc<PoolInner>,
}

pub struct PooledConn {
    conn: Option<Conn>,
    pool: Arc<PoolInner>,
}

impl Pool {
    pub fn new(opts: Opts) -> Self {
        Self::with_max_conns(opts, 10)
    }

    pub fn with_max_conns(opts: Opts, max_conns: usize) -> Self {
        info!("Creating Oracle connection pool (max_conns: {max_conns})");
        let inner = PoolInner {
            opts,
            idle: Mutex::new(Vec::with_capacity(max_conns)),
            semaphore: Arc::new(Semaphore::new(max_conns)),
            max_conns,
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    pub async fn get_conn(&self) -> Result<PooledConn> {
        let permit = self
            .inner
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::PoolClosed)?;

        // Try getting an idle connection
        {
            let mut idle = self.inner.idle.lock().await;
            while let Some(mut conn) = idle.pop() {
                // Quick ping health check
                if conn.ping().await.is_ok() {
                    debug!("Reusing healthy pooled connection (Session: {})", conn.session_id);
                    // Forget permit: the permit is maintained while PooledConn is active
                    std::mem::forget(permit);
                    return Ok(PooledConn {
                        conn: Some(conn),
                        pool: self.inner.clone(),
                    });
                }
                debug!("Discarding stale pooled connection");
            }
        }

        // Establish new connection
        debug!("Creating new Oracle connection for pool");
        let conn = Conn::connect(self.inner.opts.clone()).await?;
        std::mem::forget(permit);

        Ok(PooledConn {
            conn: Some(conn),
            pool: self.inner.clone(),
        })
    }

    pub fn max_conns(&self) -> usize {
        self.inner.max_conns
    }
}

impl Deref for PooledConn {
    type Target = Conn;
    fn deref(&self) -> &Self::Target {
        self.conn.as_ref().expect("connection present")
    }
}

impl DerefMut for PooledConn {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.conn.as_mut().expect("connection present")
    }
}

impl Drop for PooledConn {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let pool = self.pool.clone();
            tokio::spawn(async move {
                let mut idle = pool.idle.lock().await;
                idle.push(conn);
                pool.semaphore.add_permits(1);
            });
        }
    }
}

#[async_trait]
impl Queryable for PooledConn {
    async fn query<'a>(&'a mut self, query: &str) -> Result<QueryResult<'a>> {
        self.deref_mut().query(query).await
    }

    async fn exec(&mut self, query: &str) -> Result<u64> {
        self.deref_mut().exec(query).await
    }

    async fn query_with_params<'a>(
        &'a mut self,
        query: &str,
        params: Vec<crate::conn::routines::bind::BindParam>,
    ) -> Result<QueryResult<'a>> {
        self.deref_mut().query_with_params(query, params).await
    }

    async fn exec_with_params(
        &mut self,
        query: &str,
        params: Vec<crate::conn::routines::bind::BindParam>,
    ) -> Result<u64> {
        self.deref_mut().exec_with_params(query, params).await
    }
}

#[async_trait]
impl Queryable for Pool {
    async fn query<'a>(&'a mut self, query: &str) -> Result<QueryResult<'a>> {
        // Pool query requires a leased connection
        let mut conn = self.get_conn().await?;
        let _res = conn.query(query).await?;
        // Return results (for pool level, collect into memory)
        Err(Error::Protocol("pool-level streaming query requires borrowing a connection with get_conn()".into()))
    }

    async fn exec(&mut self, query: &str) -> Result<u64> {
        let mut conn = self.get_conn().await?;
        conn.exec(query).await
    }

    async fn query_with_params<'a>(
        &'a mut self,
        _query: &str,
        _params: Vec<crate::conn::routines::bind::BindParam>,
    ) -> Result<QueryResult<'a>> {
        Err(Error::Protocol(
            "pool-level streaming query requires borrowing a connection with get_conn()".into(),
        ))
    }

    async fn exec_with_params(
        &mut self,
        query: &str,
        params: Vec<crate::conn::routines::bind::BindParam>,
    ) -> Result<u64> {
        let mut conn = self.get_conn().await?;
        conn.exec_with_params(query, params).await
    }
}
