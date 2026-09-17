use crate::cipher::CryptoError;

use putty_fips::{FipsError, FipsPolicy};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PpkVersion {
    V2,
    V3,
}

#[derive(Clone, Debug)]
pub struct PpkKey {
    pub version: PpkVersion,
    pub algorithm: String,
    pub encryption: String,
    pub comment: String,
    pub public_blob: Vec<u8>,
    pub private_blob: Vec<u8>,
}

impl PpkKey {
    pub fn parse(content: &str, fips_mode: bool) -> Result<Self, CryptoError> {
        let mut lines = content.lines();
        let first_line = lines.next().ok_or_else(|| {
            CryptoError::CipherError("Empty PPK file".into())
        })?;

        let (version, algorithm) = if let Some(stripped) = first_line.strip_prefix("PuTTY-User-Key-File-3: ") {
            (PpkVersion::V3, stripped.trim().to_string())
        } else if let Some(stripped) = first_line.strip_prefix("PuTTY-User-Key-File-2: ") {
            (PpkVersion::V2, stripped.trim().to_string())
        } else {
            return Err(CryptoError::CipherError("Invalid PPK header".into()));
        };

        // Enforce FIPS 140-3 checks
        if fips_mode {
            if version == PpkVersion::V2 {
                return Err(CryptoError::Fips(FipsError::IntegrityFailure(
                    "PPK v2 uses SHA-1 KDF/MAC, which is strictly prohibited under FIPS 140-3. Please upgrade to PPK v3.".into()
                )));
            }
            FipsPolicy::validate_hostkey(&algorithm, fips_mode)?;
        }

        let mut headers = HashMap::new();
        let mut public_b64 = String::new();
        let mut private_b64 = String::new();
        let mut current_section = "";

        for line in lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once(": ") {
                headers.insert(k.to_string(), v.to_string());
                if k == "Public-Lines" {
                    current_section = "public";
                    continue;
                } else if k == "Private-Lines" {
                    current_section = "private";
                    continue;
                } else if k == "Private-MAC" {
                    current_section = "mac";
                    continue;
                }
            }
            match current_section {
                "public" => public_b64.push_str(line),
                "private" => private_b64.push_str(line),
                _ => {}
            }
        }

        use base64::Engine;
        let b64_engine = base64::engine::general_purpose::STANDARD;
        let public_blob = b64_engine.decode(public_b64)
            .map_err(|e| CryptoError::CipherError(format!("Invalid public base64: {}", e)))?;
        let private_blob = b64_engine.decode(private_b64)
            .map_err(|e| CryptoError::CipherError(format!("Invalid private base64: {}", e)))?;

        let encryption = headers.get("Encryption").cloned().unwrap_or_else(|| "none".into());
        let comment = headers.get("Comment").cloned().unwrap_or_default();

        Ok(Self {
            version,
            algorithm,
            encryption,
            comment,
            public_blob,
            private_blob,
        })
    }

    pub fn to_ppk_string(&self, fips_mode: bool) -> Result<String, CryptoError> {
        if fips_mode {
            if self.version == PpkVersion::V2 {
                return Err(CryptoError::Fips(FipsError::IntegrityFailure(
                    "Cannot export PPK v2 in FIPS 140-3 mode.".into()
                )));
            }
            FipsPolicy::validate_hostkey(&self.algorithm, fips_mode)?;
        }

        use base64::Engine;
        let b64_engine = base64::engine::general_purpose::STANDARD;
        let pub_b64 = b64_engine.encode(&self.public_blob);
        let priv_b64 = b64_engine.encode(&self.private_blob);

        let pub_chunks = chunk_string(&pub_b64, 64);
        let priv_chunks = chunk_string(&priv_b64, 64);

        let mut out = String::new();
        let ver_str = match self.version {
            PpkVersion::V3 => "3",
            PpkVersion::V2 => "2",
        };
        out.push_str(&format!("PuTTY-User-Key-File-{}: {}\n", ver_str, self.algorithm));
        out.push_str(&format!("Encryption: {}\n", self.encryption));
        out.push_str(&format!("Comment: {}\n", self.comment));
        out.push_str(&format!("Public-Lines: {}\n", pub_chunks.len()));
        for c in pub_chunks {
            out.push_str(&format!("{}\n", c));
        }
        out.push_str(&format!("Private-Lines: {}\n", priv_chunks.len()));
        for c in priv_chunks {
            out.push_str(&format!("{}\n", c));
        }
        out.push_str("Private-MAC: 0000000000000000000000000000000000000000000000000000000000000000\n");
        Ok(out)
    }

    pub fn to_openssh_authorized_keys(&self) -> String {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&self.public_blob);
        let comment = if self.comment.is_empty() { "putty-key" } else { &self.comment };
        format!("{} {} {}", self.algorithm, b64, comment)
    }
}

fn chunk_string(s: &str, chunk_size: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut curr = s;
    while !curr.is_empty() {
        let (head, tail) = if curr.len() > chunk_size {
            curr.split_at(chunk_size)
        } else {
            (curr, "")
        };
        chunks.push(head.to_string());
        curr = tail;
    }
    chunks
}
