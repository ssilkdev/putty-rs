pub mod error;
pub mod policy;
pub mod kat;

pub use error::FipsError;
pub use policy::FipsPolicy;
pub use kat::run_fips_self_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fips_power_on_self_tests() {
        let res = run_fips_self_tests();
        assert!(res.is_ok(), "FIPS KAT self-tests must pass: {:?}", res);
    }

    #[test]
    fn test_telnet_disallowed_in_fips_mode() {
        assert!(FipsPolicy::validate_protocol("telnet", false).is_ok());
        let err = FipsPolicy::validate_protocol("telnet", true).unwrap_err();
        assert_eq!(
            err,
            FipsError::ProhibitedProtocol {
                protocol: "telnet".to_string()
            }
        );
    }

    #[test]
    fn test_rlogin_and_raw_disallowed_in_fips_mode() {
        assert!(FipsPolicy::validate_protocol("rlogin", true).is_err());
        assert!(FipsPolicy::validate_protocol("raw", true).is_err());
        assert!(FipsPolicy::validate_protocol("ssh", true).is_ok());
        assert!(FipsPolicy::validate_protocol("ssh2", true).is_ok());
    }

    #[test]
    fn test_disallowed_ciphers_in_fips_mode() {
        assert!(FipsPolicy::validate_cipher("aes256-ctr", true).is_ok());
        assert!(FipsPolicy::validate_cipher("aes128-gcm@openssh.com", true).is_ok());

        assert!(FipsPolicy::validate_cipher("chacha20-poly1305@openssh.com", true).is_err());
        assert!(FipsPolicy::validate_cipher("3des-cbc", true).is_err());
        assert!(FipsPolicy::validate_cipher("blowfish-cbc", true).is_err());
    }

    #[test]
    fn test_disallowed_macs_in_fips_mode() {
        assert!(FipsPolicy::validate_mac("hmac-sha2-256", true).is_ok());
        assert!(FipsPolicy::validate_mac("hmac-sha2-512", true).is_ok());

        assert!(FipsPolicy::validate_mac("hmac-md5", true).is_err());
        assert!(FipsPolicy::validate_mac("hmac-sha1", true).is_err());
    }

    #[test]
    fn test_disallowed_kex_in_fips_mode() {
        assert!(FipsPolicy::validate_kex("ecdh-sha2-nistp256", true).is_ok());
        assert!(FipsPolicy::validate_kex("diffie-hellman-group14-sha256", true).is_ok());

        assert!(FipsPolicy::validate_kex("curve25519-sha256", true).is_err());
        assert!(FipsPolicy::validate_kex("diffie-hellman-group1-sha1", true).is_err());
    }

    #[test]
    fn test_disallowed_hostkeys_and_rsa_sizes() {
        assert!(FipsPolicy::validate_hostkey("rsa-sha2-256", true).is_ok());
        assert!(FipsPolicy::validate_hostkey("ecdsa-sha2-nistp256", true).is_ok());

        assert!(FipsPolicy::validate_hostkey("ssh-ed25519", true).is_err());
        assert!(FipsPolicy::validate_hostkey("ssh-rsa", true).is_err()); // SHA-1 ssh-rsa is disallowed
        assert!(FipsPolicy::validate_hostkey("ssh-dss", true).is_err());

        assert!(FipsPolicy::validate_rsa_key_bits(2048, true).is_ok());
        assert!(FipsPolicy::validate_rsa_key_bits(4096, true).is_ok());
        assert!(FipsPolicy::validate_rsa_key_bits(1024, true).is_err());
    }
}
