use std::time::Duration;
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub program_name: String,
    pub host_name: String,
    pub os_user_name: String,
    pub driver_name: String,
    pub pid: u32,
}

impl Default for ClientInfo {
    fn default() -> Self {
        Self {
            program_name: "oracle_async".into(),
            host_name: "localhost".into(),
            os_user_name: "oracle".into(),
            driver_name: "oracle_async:0.1.0".into(),
            pid: std::process::id(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Opts {
    pub host: String,
    pub port: u16,
    pub service_name: Option<String>,
    pub sid: Option<String>,
    pub username: String,
    pub password: String,
    pub sdu: u32,
    pub connect_timeout: Duration,
    pub client_info: ClientInfo,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 1521,
            service_name: None,
            sid: None,
            username: "".into(),
            password: "".into(),
            sdu: 8192,
            connect_timeout: Duration::from_secs(15),
            client_info: ClientInfo::default(),
        }
    }
}

impl Opts {
    pub fn builder() -> OptsBuilder {
        OptsBuilder::default()
    }

    /// Parse connection string or URL like:
    /// `oracle://user:pass@host:1521/service_name`
    /// or `host:1521/service_name`
    pub fn from_url(url_str: &str) -> Result<Self> {
        let mut builder = OptsBuilder::default();
        let trimmed = url_str.trim();
        let without_scheme = if let Some(rest) = trimmed.strip_prefix("oracle://") {
            rest
        } else if let Some(rest) = trimmed.strip_prefix("tcp://") {
            rest
        } else {
            trimmed
        };

        // Split user:pass@rest
        let (auth_part, host_part) = if let Some((auth, rest)) = without_scheme.split_once('@') {
            (Some(auth), rest)
        } else {
            (None, without_scheme)
        };

        if let Some(auth) = auth_part {
            if let Some((u, p)) = auth.split_once(':') {
                builder = builder.username(u).password(p);
            } else {
                builder = builder.username(auth);
            }
        }

        // Parse host:port/service
        if let Some((hp, service)) = host_part.split_once('/') {
            let (h, p) = if let Some((h_str, p_str)) = hp.split_once(':') {
                let port = p_str.parse::<u16>().map_err(|e| Error::Protocol(format!("invalid port: {e}")))?;
                (h_str, port)
            } else {
                (hp, 1521)
            };
            builder = builder.host(h).port(p).service_name(service);
        } else if let Some((h_str, p_str)) = host_part.split_once(':') {
            let port = p_str.parse::<u16>().map_err(|e| Error::Protocol(format!("invalid port: {e}")))?;
            builder = builder.host(h_str).port(port);
        } else {
            builder = builder.host(host_part);
        }

        Ok(builder.build())
    }

    /// Generate standard TNS Connect Data payload:
    /// `(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=...)(CID=(PROGRAM=...)(HOST=...)(USER=...)))(ADDRESS=(PROTOCOL=tcp)(HOST=...)(PORT=...)))`
    pub fn connection_data(&self) -> String {
        let target = if let Some(ref svc) = self.service_name {
            format!("(SERVICE_NAME={})", svc)
        } else if let Some(ref sid) = self.sid {
            format!("(SID={})", sid)
        } else {
            "(SERVICE_NAME=ORCL)".into()
        };

        format!(
            "(DESCRIPTION=(CONNECT_DATA={}(CID=(PROGRAM={})(HOST={})(USER={})))"
            ,
            target,
            self.client_info.program_name,
            self.client_info.host_name,
            self.client_info.os_user_name,
        ) + &format!(
            "(ADDRESS=(PROTOCOL=tcp)(HOST={})(PORT={})))",
            self.host, self.port
        )
    }
}

#[derive(Default)]
pub struct OptsBuilder {
    opts: Opts,
}

impl OptsBuilder {
    pub fn host(mut self, host: impl Into<String>) -> Self {
        self.opts.host = host.into();
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        self.opts.port = port;
        self
    }

    pub fn username(mut self, user: impl Into<String>) -> Self {
        self.opts.username = user.into();
        self
    }

    pub fn password(mut self, pass: impl Into<String>) -> Self {
        self.opts.password = pass.into();
        self
    }

    pub fn service_name(mut self, svc: impl Into<String>) -> Self {
        self.opts.service_name = Some(svc.into());
        self.opts.sid = None;
        self
    }

    pub fn sid(mut self, sid: impl Into<String>) -> Self {
        self.opts.sid = Some(sid.into());
        self.opts.service_name = None;
        self
    }

    pub fn sdu(mut self, sdu: u32) -> Self {
        self.opts.sdu = sdu;
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.opts.connect_timeout = timeout;
        self
    }

    pub fn client_info(mut self, info: ClientInfo) -> Self {
        self.opts.client_info = info;
        self
    }

    pub fn build(self) -> Opts {
        self.opts
    }
}
