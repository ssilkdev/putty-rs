use crate::error::FipsError;
use aes::cipher::{KeyIvInit, StreamCipher};
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use hmac::Hmac;
use sha2::{Digest, Sha256, Sha512};

type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;
type HmacSha256 = Hmac<Sha256>;

/// Run all mandatory FIPS 140-3 Power-On Self Tests (POST) / Known Answer Tests (KAT)
pub fn run_fips_self_tests() -> Result<(), FipsError> {
    test_sha256_kat()?;
    test_sha512_kat()?;
    test_hmac_sha256_kat()?;
    test_aes128_ctr_kat()?;
    test_aes256_gcm_kat()?;
    Ok(())
}

fn test_sha256_kat() -> Result<(), FipsError> {
    // NIST CAVP standard test vector: "abc"
    let msg = b"abc";
    let expected = hex_literal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    let mut hasher = Sha256::new();
    hasher.update(msg);
    let result = hasher.finalize();

    if result.as_slice() != expected.as_slice() {
        return Err(FipsError::KnownAnswerTestFailed { algorithm: "SHA-256" });
    }
    Ok(())
}

fn test_sha512_kat() -> Result<(), FipsError> {
    // NIST CAVP standard test vector: "abc"
    let msg = b"abc";
    let expected = hex_literal("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    let mut hasher = Sha512::new();
    hasher.update(msg);
    let result = hasher.finalize();

    if result.as_slice() != expected.as_slice() {
        return Err(FipsError::KnownAnswerTestFailed { algorithm: "SHA-512" });
    }
    Ok(())
}

fn test_hmac_sha256_kat() -> Result<(), FipsError> {
    use hmac::digest::Mac;
    // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    let expected = hex_literal("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|_| FipsError::KnownAnswerTestFailed { algorithm: "HMAC-SHA-256" })?;
    mac.update(data);
    let result = mac.finalize().into_bytes();

    if result.as_slice() != expected.as_slice() {
        return Err(FipsError::KnownAnswerTestFailed { algorithm: "HMAC-SHA-256" });
    }
    Ok(())
}

fn test_aes128_ctr_kat() -> Result<(), FipsError> {
    // NIST SP 800-38A Test Vector
    let key = hex_literal("2b7e151628aed2a6abf7158809cf4f3c");
    let iv = hex_literal("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let plaintext = hex_literal("6bc1bee22e409f96e93d7e117393172a");
    let expected_cipher = hex_literal("874d6191b620e3261bef6864990db6ce");

    let mut cipher = Aes128Ctr::new(key.as_slice().into(), iv.as_slice().into());
    let mut buffer = plaintext.clone();
    cipher.apply_keystream(&mut buffer);

    if buffer != expected_cipher {
        return Err(FipsError::KnownAnswerTestFailed { algorithm: "AES-128-CTR" });
    }

    // Decrypt (CTR is symmetric)
    let mut decipher = Aes128Ctr::new(key.as_slice().into(), iv.as_slice().into());
    decipher.apply_keystream(&mut buffer);
    if buffer != plaintext {
        return Err(FipsError::KnownAnswerTestFailed { algorithm: "AES-128-CTR" });
    }

    Ok(())
}

fn test_aes256_gcm_kat() -> Result<(), FipsError> {
    // NIST CAVP GCM Test Vector
    let key = hex_literal("0000000000000000000000000000000000000000000000000000000000000000");
    let iv = hex_literal("000000000000000000000000");
    let plaintext = hex_literal("00000000000000000000000000000000");
    let expected_tag = hex_literal("d0d1c8a799996bf0265b98b5d48ab919");
    let expected_cipher = hex_literal("cea7403d4d606b6e074ec5d3baf39d18");

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| FipsError::KnownAnswerTestFailed { algorithm: "AES-256-GCM" })?;
    let nonce = Nonce::from_slice(&iv);

    let ciphertext_with_tag = cipher.encrypt(nonce, plaintext.as_slice())
        .map_err(|_| FipsError::KnownAnswerTestFailed { algorithm: "AES-256-GCM" })?;

    // Tag is last 16 bytes
    let split_pos = ciphertext_with_tag.len() - 16;
    let cipher_out = &ciphertext_with_tag[..split_pos];
    let tag_out = &ciphertext_with_tag[split_pos..];

    if cipher_out != expected_cipher.as_slice() || tag_out != expected_tag.as_slice() {
        return Err(FipsError::KnownAnswerTestFailed { algorithm: "AES-256-GCM" });
    }

    let decrypted = cipher.decrypt(nonce, ciphertext_with_tag.as_slice())
        .map_err(|_| FipsError::KnownAnswerTestFailed { algorithm: "AES-256-GCM" })?;

    if decrypted != plaintext {
        return Err(FipsError::KnownAnswerTestFailed { algorithm: "AES-256-GCM" });
    }

    Ok(())
}

fn hex_literal(hex_str: &str) -> Vec<u8> {
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).expect("valid hex string"))
        .collect()
}
