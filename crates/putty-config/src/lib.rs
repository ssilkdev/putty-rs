pub mod conf;
pub mod storage;
pub mod crypto_vault;

pub use conf::{Conf, Protocol};
pub use storage::{SessionStorage, FileStorage, StorageError};
pub use crypto_vault::{protect_password, unprotect_password};

#[cfg(windows)]
pub use storage::RegistryStorage;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conf_fips_protocol_validation() {
        let mut conf = Conf::default();
        conf.protocol = Protocol::Telnet;
        conf.set_fips_mode(false);
        assert!(conf.validate().is_ok());

        conf.set_fips_mode(true);
        assert!(conf.validate().is_err());
    }

    #[test]
    fn test_file_storage_roundtrip() {
        let temp_dir = std::env::temp_dir().join("putty_test_storage");
        let storage = FileStorage::new(&temp_dir).unwrap();

        let mut conf = Conf::default();
        conf.session_name = "test_server".into();
        conf.host = "192.168.1.100".into();
        conf.port = 2222;
        conf.set_fips_mode(true);

        storage.save_session(&conf).unwrap();
        let loaded = storage.load_session("test_server").unwrap();
        assert_eq!(loaded.host, "192.168.1.100");
        assert_eq!(loaded.port, 2222);
        assert!(loaded.fips_mode);

        let sessions = storage.list_sessions().unwrap();
        assert!(sessions.contains(&"test_server".to_string()));

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_password_encrypted_on_disk_and_recovered_in_memory() {
        let temp_dir = std::env::temp_dir().join("putty_test_encrypted_pw");
        let storage = FileStorage::new(&temp_dir).unwrap();

        let mut conf = Conf::default();
        conf.session_name = "secret_server".into();
        conf.host = "10.0.0.1".into();
        conf.password = Some("TopSecretP@ssw0rd!123".into());

        // Save session
        storage.save_session(&conf).unwrap();

        // 1. Verify that on disk the password is NOT in cleartext
        let raw_json = std::fs::read_to_string(temp_dir.join("secret_server.json")).unwrap();
        assert!(!raw_json.contains("TopSecretP@ssw0rd!123"), "Password must NOT be stored in cleartext on disk!");
        assert!(raw_json.contains("enc:"), "Password must be saved in encrypted format on disk!");

        // 2. Verify that when loaded back into memory, the program recovers the cleartext password
        let loaded = storage.load_session("secret_server").unwrap();
        assert_eq!(loaded.password.as_deref(), Some("TopSecretP@ssw0rd!123"), "Loaded password must match original!");

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
