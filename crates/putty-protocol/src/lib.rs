pub mod backend;
pub mod ssh;
pub mod telnet;
pub mod raw;

pub use backend::{Backend, BackendEvent, InteractionSeat, ProtocolError, BackendFactory};
pub use ssh::SshBackend;
pub use telnet::TelnetBackend;
pub use raw::RawBackend;

#[cfg(test)]
mod tests {
    use super::*;
    use putty_config::{Conf, Protocol};
    use putty_fips::FipsPolicy;

    #[test]
    fn test_backend_factory_fips_blocks_telnet() {
        let mut conf = Conf::default();
        conf.protocol = Protocol::Telnet;
        conf.host = "127.0.0.1".into();
        conf.port = 23;
        conf.set_fips_mode(false);

        // Allowed in non-FIPS
        assert!(BackendFactory::create_backend(&conf).is_ok());

        // Strictly forbidden in FIPS mode!
        conf.set_fips_mode(true);
        let res = BackendFactory::create_backend(&conf);
        assert!(res.is_err());
        match res {
            Err(ProtocolError::Fips(err)) => {
                assert!(matches!(err, putty_fips::FipsError::ProhibitedProtocol { .. }));
            }
            Ok(_) => panic!("Expected FIPS violation error, but got Ok"),
            Err(other) => panic!("Expected FIPS violation error, got {:?}", other),
        }
    }

    #[test]
    fn test_backend_factory_fips_blocks_raw() {
        let mut conf = Conf::default();
        conf.protocol = Protocol::Raw;
        conf.host = "127.0.0.1".into();
        conf.set_fips_mode(true);

        let res = BackendFactory::create_backend(&conf);
        assert!(res.is_err());
    }

    #[test]
    fn test_ssh_kexinit_fips_filtering() {
        let mut conf = Conf::default();
        conf.set_fips_mode(false);
        let ssh_non_fips = SshBackend::new(conf.clone()).unwrap();
        let payload_non_fips = ssh_non_fips.build_kexinit().unwrap();

        conf.set_fips_mode(true);
        let ssh_fips = SshBackend::new(conf).unwrap();
        let payload_fips = ssh_fips.build_kexinit().unwrap();

        // The FIPS KEXINIT payload is strictly filtered and shorter (excluding ChaCha20, Ed25519, Curve25519)
        assert!(payload_fips.len() < payload_non_fips.len());

        let fips_str = String::from_utf8_lossy(&payload_fips);
        assert!(!fips_str.contains("chacha20-poly1305@openssh.com"));
        assert!(!fips_str.contains("ssh-ed25519"));
        assert!(!fips_str.contains("curve25519-sha256"));
        assert!(fips_str.contains("aes256-gcm@openssh.com"));
        assert!(fips_str.contains("rsa-sha2-512"));
    }

    #[test]
    fn test_ssh_negotiation_fips_enforcement() {
        let client_ciphers = &["chacha20-poly1305@openssh.com", "aes256-ctr"];
        let server_ciphers = &["chacha20-poly1305@openssh.com", "aes256-ctr"];

        // Non-FIPS accepts first match (chacha20)
        let neg_non_fips = SshBackend::negotiate_algorithm(
            client_ciphers,
            server_ciphers,
            false,
            FipsPolicy::validate_cipher,
        ).unwrap();
        assert_eq!(neg_non_fips, "chacha20-poly1305@openssh.com");

        // FIPS strictly rejects chacha20 if offered alone
        let res_fips = SshBackend::negotiate_algorithm(
            &["chacha20-poly1305@openssh.com"],
            &["chacha20-poly1305@openssh.com"],
            true,
            FipsPolicy::validate_cipher,
        );
        assert!(res_fips.is_err());
    }
}
