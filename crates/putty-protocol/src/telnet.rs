use crate::backend::{Backend, BackendEvent, ProtocolError};
use putty_config::Conf;
use putty_fips::FipsError;
use std::io::{Read, Write};
use std::net::TcpStream;

pub struct TelnetBackend {
    conf: Conf,
    stream: Option<TcpStream>,
    connected: bool,
}

impl TelnetBackend {
    pub fn new(conf: Conf) -> Self {
        Self {
            conf,
            stream: None,
            connected: false,
        }
    }
}

impl Backend for TelnetBackend {
    fn connect(&mut self) -> Result<(), ProtocolError> {
        // Enforce FIPS 140-3 policy: Telnet is an unencrypted protocol and strictly prohibited!
        if self.conf.fips_mode {
            return Err(ProtocolError::Fips(FipsError::ProhibitedProtocol {
                protocol: "telnet".to_string(),
            }));
        }

        let addr = format!("{}:{}", self.conf.host, self.conf.port);
        let stream = TcpStream::connect(&addr)?;
        stream.set_nonblocking(true)?;
        self.stream = Some(stream);
        self.connected = true;
        Ok(())
    }

    fn send(&mut self, data: &[u8]) -> Result<(), ProtocolError> {
        if self.conf.fips_mode {
            return Err(ProtocolError::Fips(FipsError::ProhibitedProtocol {
                protocol: "telnet".to_string(),
            }));
        }
        if let Some(ref mut stream) = self.stream {
            stream.write_all(data)?;
            stream.flush()?;
        }
        Ok(())
    }

    fn poll_events(&mut self) -> Result<Vec<BackendEvent>, ProtocolError> {
        if self.conf.fips_mode {
            return Err(ProtocolError::Fips(FipsError::ProhibitedProtocol {
                protocol: "telnet".to_string(),
            }));
        }
        let mut events = Vec::new();
        if let Some(ref mut stream) = self.stream {
            let mut buf = [0u8; 4096];
            match stream.read(&mut buf) {
                Ok(0) => {
                    self.connected = false;
                    events.push(BackendEvent::Close);
                }
                Ok(n) => {
                    // Filter or handle IAC if present, or pass through clean data
                    events.push(BackendEvent::Output(buf[..n].to_vec()));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data ready
                }
                Err(e) => return Err(ProtocolError::Io(e)),
            }
        }
        Ok(events)
    }

    fn resize(&mut self, _width: u16, _height: u16) -> Result<(), ProtocolError> {
        // Send NAWS (Negotiate About Window Size) in Telnet
        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), ProtocolError> {
        self.connected = false;
        self.stream = None;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}
