use crate::error::FipsError;
use std::sync::atomic::{AtomicBool, Ordering};

/// Global or contextual FIPS 140-3 mode switch
static GLOBAL_FIPS_ENABLED: AtomicBool = AtomicBool::new(false);

/// FIPS 140-3 policy rules and validation helpers
pub struct FipsPolicy;

impl FipsPolicy {
    /// Enable FIPS 140-3 mode globally
    pub fn enable_globally() {
        GLOBAL_FIPS_ENABLED.store(true, Ordering::SeqCst);
    }

    /// Disable FIPS 140-3 mode globally
    pub fn disable_globally() {
        GLOBAL_FIPS_ENABLED.store(false, Ordering::SeqCst);
    }

    /// Check whether FIPS 140-3 mode is globally enabled
    pub fn is_globally_enabled() -> bool {
        GLOBAL_FIPS_ENABLED.load(Ordering::SeqCst)
    }

    /// Allowed FIPS 140-3 symmetric ciphers for SSH transport
    pub const APPROVED_CIPHERS: &'static [&'static str] = &[
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr",
        "aes256-cbc",
        "aes192-cbc",
        "aes128-cbc",
    ];

    /// Allowed FIPS 140-3 MAC algorithms
    pub const APPROVED_MACS: &'static [&'static str] = &[
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512",
        "hmac-sha2-256",
    ];

    /// Allowed FIPS 140-3 Key Exchange algorithms
    pub const APPROVED_KEX: &'static [&'static str] = &[
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group16-sha512",
        "diffie-hellman-group18-sha512",
        "diffie-hellman-group-exchange-sha256",
    ];

    /// Allowed FIPS 140-3 Host Key / Signature algorithms
    pub const APPROVED_HOSTKEYS: &'static [&'static str] = &[
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    ];

    /// Allowed secure protocols in FIPS mode (Telnet, Rlogin, Raw TCP, SSH1 are forbidden)
    pub const APPROVED_PROTOCOLS: &'static [&'static str] = &["ssh", "ssh2"];

    /// Validate whether a protocol is permitted under FIPS mode
    pub fn validate_protocol(protocol: &str, fips_mode: bool) -> Result<(), FipsError> {
        if !fips_mode {
            return Ok(());
        }
        let lower = protocol.to_lowercase();
        if Self::APPROVED_PROTOCOLS.contains(&lower.as_str()) {
            Ok(())
        } else {
            Err(FipsError::ProhibitedProtocol {
                protocol: protocol.to_string(),
            })
        }
    }

    /// Validate a symmetric cipher algorithm name under FIPS mode
    pub fn validate_cipher(cipher: &str, fips_mode: bool) -> Result<(), FipsError> {
        if !fips_mode {
            return Ok(());
        }
        if Self::APPROVED_CIPHERS.contains(&cipher) {
            Ok(())
        } else {
            Err(FipsError::DisallowedCipher {
                cipher: cipher.to_string(),
                approved: Self::APPROVED_CIPHERS.join(", "),
            })
        }
    }

    /// Validate a MAC algorithm name under FIPS mode
    pub fn validate_mac(mac: &str, fips_mode: bool) -> Result<(), FipsError> {
        if !fips_mode {
            return Ok(());
        }
        if Self::APPROVED_MACS.contains(&mac) {
            Ok(())
        } else {
            Err(FipsError::DisallowedMac {
                mac: mac.to_string(),
                approved: Self::APPROVED_MACS.join(", "),
            })
        }
    }

    /// Validate a Key Exchange algorithm name under FIPS mode
    pub fn validate_kex(kex: &str, fips_mode: bool) -> Result<(), FipsError> {
        if !fips_mode {
            return Ok(());
        }
        if Self::APPROVED_KEX.contains(&kex) {
            Ok(())
        } else {
            Err(FipsError::DisallowedKex {
                kex: kex.to_string(),
                approved: Self::APPROVED_KEX.join(", "),
            })
        }
    }

    /// Validate a Host Key algorithm name under FIPS mode
    pub fn validate_hostkey(hostkey: &str, fips_mode: bool) -> Result<(), FipsError> {
        if !fips_mode {
            return Ok(());
        }
        if Self::APPROVED_HOSTKEYS.contains(&hostkey) {
            Ok(())
        } else {
            Err(FipsError::DisallowedHostKey {
                hostkey: hostkey.to_string(),
                approved: Self::APPROVED_HOSTKEYS.join(", "),
            })
        }
    }

    /// Validate RSA key size (FIPS 140-3 requires at least 2048-bit modulus)
    pub fn validate_rsa_key_bits(bits: usize, fips_mode: bool) -> Result<(), FipsError> {
        if !fips_mode {
            return Ok(());
        }
        if bits >= 2048 {
            Ok(())
        } else {
            Err(FipsError::InsufficientRsaKeySize { bits })
        }
    }

    /// Filter an offered algorithm list according to FIPS mode
    pub fn filter_algorithms<'a>(list: &[&'a str], approved: &[&str], fips_mode: bool) -> Vec<&'a str> {
        if !fips_mode {
            return list.to_vec();
        }
        list.iter().copied().filter(|item| approved.contains(item)).collect()
    }
}
