use putty_config::{Conf, Protocol};
use putty_fips::{FipsError, FipsPolicy};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("FIPS Policy Violation: {0}")]
    Fips(#[from] FipsError),
    #[error("Network I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SSH Protocol error: {0}")]
    Ssh(String),
    #[error("Authentication failed for user '{0}'")]
    AuthFailed(String),
    #[error("Protocol error: {0}")]
    Other(String),
}

#[derive(Debug, Clone)]
pub enum BackendEvent {
    Output(Vec<u8>),
    Close,
    Prompt { prompt: String, echo: bool },
}

pub trait InteractionSeat: Send {
    fn output(&mut self, data: &[u8]);
    fn notify_close(&mut self);
}

pub trait Backend: Send {
    fn connect(&mut self) -> Result<(), ProtocolError>;
    fn send(&mut self, data: &[u8]) -> Result<(), ProtocolError>;
    fn poll_events(&mut self) -> Result<Vec<BackendEvent>, ProtocolError>;
    fn resize(&mut self, width: u16, height: u16) -> Result<(), ProtocolError>;
    fn disconnect(&mut self) -> Result<(), ProtocolError>;
    fn is_connected(&self) -> bool;
}

pub struct BackendFactory;

impl BackendFactory {
    pub fn create_backend(conf: &Conf) -> Result<Box<dyn Backend>, ProtocolError> {
        // Enforce FIPS 140-3 protocol validation upfront
        if conf.fips_mode {
            FipsPolicy::validate_protocol(conf.protocol.to_str(), true)?;
        }

        match conf.protocol {
            Protocol::Ssh => {
                let backend = crate::ssh::SshBackend::new(conf.clone())?;
                Ok(Box::new(backend))
            }
            Protocol::Telnet => {
                if conf.fips_mode {
                    return Err(ProtocolError::Fips(FipsError::ProhibitedProtocol {
                        protocol: "telnet".to_string(),
                    }));
                }
                let backend = crate::telnet::TelnetBackend::new(conf.clone());
                Ok(Box::new(backend))
            }
            Protocol::Raw => {
                if conf.fips_mode {
                    return Err(ProtocolError::Fips(FipsError::ProhibitedProtocol {
                        protocol: "raw".to_string(),
                    }));
                }
                let backend = crate::raw::RawBackend::new(conf.clone());
                Ok(Box::new(backend))
            }
            _ => Err(ProtocolError::Other(format!(
                "Protocol '{}' is not supported in this build",
                conf.protocol.to_str()
            ))),
        }
    }
}
