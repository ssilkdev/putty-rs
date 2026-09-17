use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum FipsError {
    #[error("FIPS 140-3 VIOLATION: Protocol '{protocol}' is prohibited (cleartext / unencrypted transport).")]
    ProhibitedProtocol { protocol: String },

    #[error("FIPS 140-3 VIOLATION: Cipher '{cipher}' is not an approved algorithm. Approved ciphers: {approved}")]
    DisallowedCipher { cipher: String, approved: String },

    #[error("FIPS 140-3 VIOLATION: MAC algorithm '{mac}' is not approved. Approved MACs: {approved}")]
    DisallowedMac { mac: String, approved: String },

    #[error("FIPS 140-3 VIOLATION: Key Exchange algorithm '{kex}' is not approved. Approved KEX: {approved}")]
    DisallowedKex { kex: String, approved: String },

    #[error("FIPS 140-3 VIOLATION: Host key algorithm '{hostkey}' is not approved. Approved host keys: {approved}")]
    DisallowedHostKey { hostkey: String, approved: String },

    #[error("FIPS 140-3 VIOLATION: RSA key modulus length ({bits} bits) is below the minimum required 2048 bits.")]
    InsufficientRsaKeySize { bits: usize },

    #[error("FIPS 140-3 POWER-ON SELF-TEST (POST) FAILURE: Algorithm '{algorithm}' failed Known Answer Test (KAT). Cryptographic operations are locked.")]
    KnownAnswerTestFailed { algorithm: &'static str },

    #[error("FIPS 140-3 INTEGRITY FAILURE: {0}")]
    IntegrityFailure(String),
}
