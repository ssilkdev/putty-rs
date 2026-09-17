use putty_fips::{FipsError, FipsPolicy};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Ssh,
    Telnet,
    Rlogin,
    Raw,
    Serial,
}

impl Protocol {
    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Ssh => "ssh",
            Self::Telnet => "telnet",
            Self::Rlogin => "rlogin",
            Self::Raw => "raw",
            Self::Serial => "serial",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ssh" | "ssh2" => Some(Self::Ssh),
            "telnet" => Some(Self::Telnet),
            "rlogin" => Some(Self::Rlogin),
            "raw" => Some(Self::Raw),
            "serial" => Some(Self::Serial),
            _ => None,
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            Self::Ssh => 22,
            Self::Telnet => 23,
            Self::Rlogin => 513,
            Self::Raw => 0,
            Self::Serial => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conf {
    pub session_name: String,
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
    pub username: String,
    pub password: Option<String>,
    pub key_file: Option<String>,
    pub fips_mode: bool,
    pub cipher_priority: Vec<String>,
    pub kex_priority: Vec<String>,
    pub mac_priority: Vec<String>,
    pub terminal_type: String,
    pub rows: u16,
    pub cols: u16,
}

impl Default for Conf {
    fn default() -> Self {
        Self {
            session_name: "Default Settings".into(),
            host: String::new(),
            port: 22,
            protocol: Protocol::Ssh,
            username: String::new(),
            password: None,
            key_file: None,
            fips_mode: false,
            cipher_priority: FipsPolicy::APPROVED_CIPHERS.iter().map(|s| s.to_string()).collect(),
            kex_priority: FipsPolicy::APPROVED_KEX.iter().map(|s| s.to_string()).collect(),
            mac_priority: FipsPolicy::APPROVED_MACS.iter().map(|s| s.to_string()).collect(),
            terminal_type: "xterm-256color".into(),
            rows: 24,
            cols: 80,
        }
    }
}

impl Conf {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_fips_mode(&mut self, enabled: bool) {
        self.fips_mode = enabled;
        if enabled {
            // Filter lists to only approved algorithms
            self.cipher_priority.retain(|c| FipsPolicy::validate_cipher(c, true).is_ok());
            self.kex_priority.retain(|k| FipsPolicy::validate_kex(k, true).is_ok());
            self.mac_priority.retain(|m| FipsPolicy::validate_mac(m, true).is_ok());
        }
    }

    pub fn validate(&self) -> Result<(), FipsError> {
        if self.fips_mode {
            FipsPolicy::validate_protocol(self.protocol.to_str(), true)?;
            for c in &self.cipher_priority {
                FipsPolicy::validate_cipher(c, true)?;
            }
            for k in &self.kex_priority {
                FipsPolicy::validate_kex(k, true)?;
            }
            for m in &self.mac_priority {
                FipsPolicy::validate_mac(m, true)?;
            }
        }
        Ok(())
    }
}
