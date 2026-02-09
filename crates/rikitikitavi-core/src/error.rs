use std::net::IpAddr;

/// Top-level application errors.
#[derive(Debug, thiserror::Error)]
pub enum RikitikitaviError {
    #[error("scan error: {0}")]
    Scan(#[from] ScanError),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("export error: {0}")]
    Export(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Errors that can occur during scanning.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("scanner '{scanner}' failed: {message}")]
    ScannerFailed { scanner: String, message: String },

    #[error("timeout scanning {target}")]
    Timeout { target: String },

    #[error("host unreachable: {host}")]
    HostUnreachable { host: IpAddr },

    #[error("insufficient privileges for scanner '{scanner}'")]
    InsufficientPrivileges { scanner: String },

    #[error("network interface '{interface}' not found")]
    InterfaceNotFound { interface: String },

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}
