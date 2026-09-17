pub mod cipher;
pub mod mac;
pub mod kex;
pub mod key;
pub mod ppk;

pub use cipher::{CipherAlgorithm, SymmetricCipher, SymmetricCipherTrait, CryptoError};
pub use mac::{MacAlgorithm, MacCalculator, MacTrait};
pub use kex::{KexAlgorithm, KeyExchangeSession};
pub use key::{KeyType, PublicKeyBlob, KeyPair};
pub use ppk::{PpkKey, PpkVersion};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_fips_restrictions() {
        let key = vec![0u8; 32];
        let iv = vec![0u8; 16];

        // AES-256 CTR is allowed in both FIPS and non-FIPS
        assert!(SymmetricCipher::create("aes256-ctr", &key, &iv, false).is_ok());
        assert!(SymmetricCipher::create("aes256-ctr", &key, &iv, true).is_ok());

        // ChaCha20 is allowed in non-FIPS, but blocked in FIPS mode
        let chacha_key = vec![0u8; 64];
        assert!(SymmetricCipher::create("chacha20-poly1305@openssh.com", &chacha_key, &iv, false).is_ok());
        assert!(SymmetricCipher::create("chacha20-poly1305@openssh.com", &chacha_key, &iv, true).is_err());
    }

    #[test]
    fn test_mac_fips_restrictions() {
        let key = vec![0u8; 32];

        // HMAC-SHA2-256 allowed in both
        assert!(MacCalculator::create("hmac-sha2-256", &key, false).is_ok());
        assert!(MacCalculator::create("hmac-sha2-256", &key, true).is_ok());

        // HMAC-SHA1 and HMAC-MD5 blocked in FIPS mode
        assert!(MacCalculator::create("hmac-sha1", &key[..20], false).is_ok());
        assert!(MacCalculator::create("hmac-sha1", &key[..20], true).is_err());

        assert!(MacCalculator::create("hmac-md5", &key[..16], false).is_ok());
        assert!(MacCalculator::create("hmac-md5", &key[..16], true).is_err());
    }

    #[test]
    fn test_kex_fips_restrictions() {
        // NIST P-256 allowed in FIPS
        assert!(KeyExchangeSession::new(KexAlgorithm::EcdhNistP256, true).is_ok());

        // Curve25519 blocked in FIPS mode
        assert!(KeyExchangeSession::new(KexAlgorithm::Curve25519Sha256, false).is_ok());
        assert!(KeyExchangeSession::new(KexAlgorithm::Curve25519Sha256, true).is_err());
    }

    #[test]
    fn test_key_pair_generation_and_fips() {
        // RSA 2048 allowed in FIPS
        assert!(KeyPair::generate_rsa(2048, true).is_ok());
        // RSA 1024 blocked in FIPS
        assert!(KeyPair::generate_rsa(1024, true).is_err());

        // Ed25519 blocked in FIPS
        assert!(KeyPair::generate_ed25519(false).is_ok());
        assert!(KeyPair::generate_ed25519(true).is_err());
    }

    #[test]
    fn test_ppk_parsing_and_fips() {
        let ppk_v3_content = r#"PuTTY-User-Key-File-3: rsa-sha2-256
Encryption: none
Comment: test-fips-rsa
Public-Lines: 1
AQAB
Private-Lines: 1
AQAB
Private-MAC: 0000000000000000000000000000000000000000000000000000000000000000
"#;
        assert!(PpkKey::parse(ppk_v3_content, true).is_ok());

        let ppk_v2_content = r#"PuTTY-User-Key-File-2: rsa-sha2-256
Encryption: none
Comment: legacy-key
Public-Lines: 1
AQAB
Private-Lines: 1
AQAB
Private-MAC: 0000000000000000000000000000000000000000
"#;
        // PPK v2 is blocked in FIPS mode
        assert!(PpkKey::parse(ppk_v2_content, false).is_ok());
        assert!(PpkKey::parse(ppk_v2_content, true).is_err());
    }
}
