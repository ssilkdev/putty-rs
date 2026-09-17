use crate::conf::{Conf, Protocol};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Session not found: {0}")]
    NotFound(String),
}

pub trait SessionStorage {
    fn load_session(&self, name: &str) -> Result<Conf, StorageError>;
    fn save_session(&self, conf: &Conf) -> Result<(), StorageError>;
    fn list_sessions(&self) -> Result<Vec<String>, StorageError>;
    fn delete_session(&self, name: &str) -> Result<(), StorageError>;
}

pub struct FileStorage {
    directory: std::path::PathBuf,
}

impl FileStorage {
    pub fn new<P: AsRef<Path>>(dir: P) -> std::io::Result<Self> {
        let path = dir.as_ref().to_path_buf();
        fs::create_dir_all(&path)?;
        Ok(Self { directory: path })
    }
}

impl SessionStorage for FileStorage {
    fn load_session(&self, name: &str) -> Result<Conf, StorageError> {
        let file_path = self.directory.join(format!("{}.json", name));
        if !file_path.exists() {
            return Err(StorageError::NotFound(name.to_string()));
        }
        let data = fs::read_to_string(file_path)?;
        let mut conf: Conf = serde_json::from_str(&data)?;
        if let Some(ref enc) = conf.password {
            conf.password = Some(crate::crypto_vault::unprotect_password(enc));
        }
        Ok(conf)
    }

    fn save_session(&self, conf: &Conf) -> Result<(), StorageError> {
        let mut to_save = conf.clone();
        if let Some(ref plain) = to_save.password {
            to_save.password = Some(crate::crypto_vault::protect_password(plain));
        }
        let file_path = self.directory.join(format!("{}.json", to_save.session_name));
        let data = serde_json::to_string_pretty(&to_save)?;
        fs::write(file_path, data)?;
        Ok(())
    }

    fn list_sessions(&self) -> Result<Vec<String>, StorageError> {
        let mut list = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "json") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    list.push(stem.to_string());
                }
            }
        }
        Ok(list)
    }

    fn delete_session(&self, name: &str) -> Result<(), StorageError> {
        let file_path = self.directory.join(format!("{}.json", name));
        if file_path.exists() {
            fs::remove_file(file_path)?;
        }
        Ok(())
    }
}

#[cfg(windows)]
pub struct RegistryStorage;

#[cfg(windows)]
impl SessionStorage for RegistryStorage {
    fn load_session(&self, name: &str) -> Result<Conf, StorageError> {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let subkey_name = format!(r"Software\SimonTatham\PuTTY\Sessions\{}", name);
        let key = hkcu.open_subkey(&subkey_name)
            .map_err(|_| StorageError::NotFound(name.to_string()))?;

        let host: String = key.get_value("HostName").unwrap_or_default();
        let port: u32 = key.get_value("PortNumber").unwrap_or(22);
        let proto_str: String = key.get_value("Protocol").unwrap_or_else(|_| "ssh".into());
        let username: String = key.get_value("UserName").unwrap_or_default();
        let key_file: String = key.get_value("PublicKeyFile").unwrap_or_default();
        let fips_mode: u32 = key.get_value("FipsMode").unwrap_or(0);

        let enc_password: Option<String> = key.get_value("EncryptedPassword").ok()
            .or_else(|| key.get_value("Password").ok());

        let mut conf = Conf::default();
        conf.session_name = name.to_string();
        conf.host = host;
        conf.port = port as u16;
        conf.protocol = Protocol::from_str(&proto_str).unwrap_or(Protocol::Ssh);
        conf.username = username;
        conf.password = enc_password.map(|p| crate::crypto_vault::unprotect_password(&p));
        conf.key_file = if key_file.is_empty() { None } else { Some(key_file) };
        conf.set_fips_mode(fips_mode != 0);

        Ok(conf)
    }

    fn save_session(&self, conf: &Conf) -> Result<(), StorageError> {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let subkey_name = format!(r"Software\SimonTatham\PuTTY\Sessions\{}", conf.session_name);
        let (key, _) = hkcu.create_subkey(&subkey_name)
            .map_err(StorageError::Io)?;

        key.set_value("HostName", &conf.host).map_err(StorageError::Io)?;
        key.set_value("PortNumber", &(conf.port as u32)).map_err(StorageError::Io)?;
        key.set_value("Protocol", &conf.protocol.to_str()).map_err(StorageError::Io)?;
        key.set_value("UserName", &conf.username).map_err(StorageError::Io)?;
        if let Some(ref pw) = conf.password {
            let enc = crate::crypto_vault::protect_password(pw);
            key.set_value("EncryptedPassword", &enc).map_err(StorageError::Io)?;
        }
        if let Some(ref kf) = conf.key_file {
            key.set_value("PublicKeyFile", kf).map_err(StorageError::Io)?;
        }
        key.set_value("FipsMode", &(if conf.fips_mode { 1u32 } else { 0u32 })).map_err(StorageError::Io)?;

        Ok(())
    }

    fn list_sessions(&self) -> Result<Vec<String>, StorageError> {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key = match hkcu.open_subkey(r"Software\SimonTatham\PuTTY\Sessions") {
            Ok(k) => k,
            Err(_) => return Ok(Vec::new()),
        };

        let mut names = Vec::new();
        for key_name in key.enum_keys().map_while(Result::ok) {
            names.push(key_name);
        }
        Ok(names)
    }

    fn delete_session(&self, name: &str) -> Result<(), StorageError> {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        if let Ok(key) = hkcu.open_subkey_with_flags(r"Software\SimonTatham\PuTTY\Sessions", KEY_WRITE) {
            let _ = key.delete_subkey(name);
        }
        Ok(())
    }
}
