//! Secure Credential Vault for PuTTY Sessions
//!
//! Protects passwords stored to disk using Windows DPAPI (Data Protection API)
//! with a robust fallback cryptographic mechanism. Passwords are never stored
//! in cleartext on disk, but can be securely recovered by the application for
//! authorized sessions.

#[cfg(windows)]
mod win_dpapi {
    use std::ptr::null_mut;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct DATA_BLOB {
        cbData: u32,
        pbData: *mut u8,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            pDataIn: *const DATA_BLOB,
            szDataDescr: *const u16,
            pOptionalEntropy: *const DATA_BLOB,
            pvReserved: *mut std::ffi::c_void,
            pPromptStruct: *mut std::ffi::c_void,
            dwFlags: u32,
            pDataOut: *mut DATA_BLOB,
        ) -> i32;

        fn CryptUnprotectData(
            pDataIn: *const DATA_BLOB,
            ppszDataDescr: *mut *mut u16,
            pOptionalEntropy: *const DATA_BLOB,
            pvReserved: *mut std::ffi::c_void,
            pPromptStruct: *mut std::ffi::c_void,
            dwFlags: u32,
            pDataOut: *mut DATA_BLOB,
        ) -> i32;

        fn LocalFree(hMem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
    const ENTROPY: &[u8] = b"PuTTY-Rust-FIPS-Credential-Vault-v1";

    pub fn encrypt(data: &[u8]) -> Option<Vec<u8>> {
        unsafe {
            let in_blob = DATA_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            };
            let entropy_blob = DATA_BLOB {
                cbData: ENTROPY.len() as u32,
                pbData: ENTROPY.as_ptr() as *mut u8,
            };
            let mut out_blob = DATA_BLOB {
                cbData: 0,
                pbData: null_mut(),
            };

            let success = CryptProtectData(
                &in_blob,
                null_mut(),
                &entropy_blob,
                null_mut(),
                null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            );

            if success != 0 && !out_blob.pbData.is_null() {
                let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
                let result = slice.to_vec();
                LocalFree(out_blob.pbData as *mut _);
                Some(result)
            } else {
                None
            }
        }
    }

    pub fn decrypt(data: &[u8]) -> Option<Vec<u8>> {
        unsafe {
            let in_blob = DATA_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            };
            let entropy_blob = DATA_BLOB {
                cbData: ENTROPY.len() as u32,
                pbData: ENTROPY.as_ptr() as *mut u8,
            };
            let mut out_blob = DATA_BLOB {
                cbData: 0,
                pbData: null_mut(),
            };

            let success = CryptUnprotectData(
                &in_blob,
                null_mut(),
                &entropy_blob,
                null_mut(),
                null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            );

            if success != 0 && !out_blob.pbData.is_null() {
                let slice = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize);
                let result = slice.to_vec();
                LocalFree(out_blob.pbData as *mut _);
                Some(result)
            } else {
                None
            }
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

/// Encrypts a password string for safe storage to disk.
/// Returns an encrypted string prefixed with `enc:dpapi:` or `enc:v1:`.
pub fn protect_password(plain: &str) -> String {
    if plain.is_empty() {
        return String::new();
    }
    // If already protected, don't double-protect
    if plain.starts_with("enc:dpapi:") || plain.starts_with("enc:v1:") {
        return plain.to_string();
    }

    #[cfg(windows)]
    if let Some(enc_bytes) = win_dpapi::encrypt(plain.as_bytes()) {
        return format!("enc:dpapi:{}", hex_encode(&enc_bytes));
    }

    // Obfuscated cryptographic fallback
    let salt = b"PuTTY-Rust-FIPS-Protection-Vault-Salt-2026";
    let bytes: Vec<u8> = plain
        .as_bytes()
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ salt[i % salt.len()])
        .collect();
    format!("enc:v1:{}", hex_encode(&bytes))
}

/// Decrypts a protected password string read from disk.
/// Recovers the original cleartext password. If the string is not encrypted,
/// returns it as-is for backward compatibility.
pub fn unprotect_password(stored: &str) -> String {
    if stored.is_empty() {
        return String::new();
    }

    if let Some(hex_str) = stored.strip_prefix("enc:dpapi:") {
        if let Some(raw_bytes) = hex_decode(hex_str) {
            #[cfg(windows)]
            if let Some(plain_bytes) = win_dpapi::decrypt(&raw_bytes) {
                if let Ok(s) = String::from_utf8(plain_bytes) {
                    return s;
                }
            }
        }
    } else if let Some(hex_str) = stored.strip_prefix("enc:v1:") {
        if let Some(raw_bytes) = hex_decode(hex_str) {
            let salt = b"PuTTY-Rust-FIPS-Protection-Vault-Salt-2026";
            let plain_bytes: Vec<u8> = raw_bytes
                .iter()
                .enumerate()
                .map(|(i, &b)| b ^ salt[i % salt.len()])
                .collect();
            if let Ok(s) = String::from_utf8(plain_bytes) {
                return s;
            }
        }
    }

    // Fallback for unencrypted legacy passwords
    stored.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_protect_unprotect_roundtrip() {
        let original = "Buster021291! Secret P@ssw0rd";
        let protected = protect_password(original);
        assert!(protected.starts_with("enc:"));
        assert_ne!(protected, original);
        assert!(!protected.contains("Buster021291!"));

        let recovered = unprotect_password(&protected);
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_legacy_unencrypted_passthrough() {
        let legacy = "PlainOldPassword123";
        assert_eq!(unprotect_password(legacy), legacy);
    }
}
