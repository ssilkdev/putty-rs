use crate::cipher::CryptoError;
use putty_fips::{FipsError, FipsPolicy};
use rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey, traits::PublicKeyParts};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    RsaSha256,
    RsaSha512,
    EcdsaSha2NistP256,
    EcdsaSha2NistP384,
    Ed25519,
    SshRsa,
}

impl KeyType {
    pub fn from_ssh_name(name: &str) -> Option<Self> {
        match name {
            "rsa-sha2-256" => Some(Self::RsaSha256),
            "rsa-sha2-512" => Some(Self::RsaSha512),
            "ecdsa-sha2-nistp256" => Some(Self::EcdsaSha2NistP256),
            "ecdsa-sha2-nistp384" => Some(Self::EcdsaSha2NistP384),
            "ssh-ed25519" => Some(Self::Ed25519),
            "ssh-rsa" => Some(Self::SshRsa),
            _ => None,
        }
    }

    pub fn to_ssh_name(&self) -> &'static str {
        match self {
            Self::RsaSha256 => "rsa-sha2-256",
            Self::RsaSha512 => "rsa-sha2-512",
            Self::EcdsaSha2NistP256 => "ecdsa-sha2-nistp256",
            Self::EcdsaSha2NistP384 => "ecdsa-sha2-nistp384",
            Self::Ed25519 => "ssh-ed25519",
            Self::SshRsa => "ssh-rsa",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PublicKeyBlob {
    pub key_type: KeyType,
    pub raw_blob: Vec<u8>,
}

pub enum KeyPair {
    Rsa {
        key_type: KeyType,
        private: RsaPrivateKey,
        public: RsaPublicKey,
        bits: usize,
    },
    EcdsaP256 {
        secret: p256::SecretKey,
        public: p256::PublicKey,
    },
    Ed25519 {
        private: [u8; 32],
        public: [u8; 32],
    },
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        match self {
            Self::Ed25519 { private, .. } => private.zeroize(),
            _ => {}
        }
    }
}

impl KeyPair {
    pub fn generate_rsa(bits: usize, fips_mode: bool) -> Result<Self, CryptoError> {
        FipsPolicy::validate_rsa_key_bits(bits, fips_mode)?;
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| CryptoError::CipherError(e.to_string()))?;
        let public = RsaPublicKey::from(&private);
        Ok(Self::Rsa {
            key_type: KeyType::RsaSha256,
            private,
            public,
            bits,
        })
    }

    pub fn generate_ecdsa_p256(fips_mode: bool) -> Result<Self, CryptoError> {
        FipsPolicy::validate_hostkey("ecdsa-sha2-nistp256", fips_mode)?;
        let secret = p256::SecretKey::random(&mut OsRng);
        let public = secret.public_key();
        Ok(Self::EcdsaP256 { secret, public })
    }

    pub fn generate_ed25519(fips_mode: bool) -> Result<Self, CryptoError> {
        if fips_mode {
            return Err(CryptoError::Fips(FipsError::DisallowedHostKey {
                hostkey: "ssh-ed25519".to_string(),
                approved: FipsPolicy::APPROVED_HOSTKEYS.join(", "),
            }));
        }
        let mut private = [0u8; 32];
        let mut public = [0u8; 32];
        use rand::RngCore;
        OsRng.fill_bytes(&mut private);
        OsRng.fill_bytes(&mut public);
        Ok(Self::Ed25519 { private, public })
    }

    pub fn key_type(&self) -> KeyType {
        match self {
            Self::Rsa { key_type, .. } => *key_type,
            Self::EcdsaP256 { .. } => KeyType::EcdsaSha2NistP256,
            Self::Ed25519 { .. } => KeyType::Ed25519,
        }
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        match self {
            Self::Rsa { public, .. } => {
                let e = public.e().to_bytes_be();
                let n = public.n().to_bytes_be();
                let mut out = Vec::new();
                write_ssh_string(&mut out, b"ssh-rsa");
                write_ssh_mpint(&mut out, &e);
                write_ssh_mpint(&mut out, &n);
                out
            }
            Self::EcdsaP256 { public, .. } => {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                let pt = public.to_encoded_point(false);
                let mut out = Vec::new();
                write_ssh_string(&mut out, b"ecdsa-sha2-nistp256");
                write_ssh_string(&mut out, b"nistp256");
                write_ssh_string(&mut out, pt.as_bytes());
                out
            }
            Self::Ed25519 { public, .. } => {
                let mut out = Vec::new();
                write_ssh_string(&mut out, b"ssh-ed25519");
                write_ssh_string(&mut out, public);
                out
            }
        }
    }

    pub fn sign(&self, data: &[u8], fips_mode: bool) -> Result<Vec<u8>, CryptoError> {
        FipsPolicy::validate_hostkey(self.key_type().to_ssh_name(), fips_mode)?;
        match self {
            Self::Rsa { private, key_type, bits, .. } => {
                FipsPolicy::validate_rsa_key_bits(*bits, fips_mode)?;
                let mut sig_out = Vec::new();
                match key_type {
                    KeyType::RsaSha512 => {
                        let mut hasher = Sha512::new();
                        hasher.update(data);
                        let digest = hasher.finalize();
                        let padding = rsa::Pkcs1v15Sign::new::<Sha512>();
                        let sig = private.sign(padding, &digest)
                            .map_err(|e| CryptoError::CipherError(e.to_string()))?;
                        write_ssh_string(&mut sig_out, b"rsa-sha2-512");
                        write_ssh_string(&mut sig_out, &sig);
                    }
                    _ => {
                        let mut hasher = Sha256::new();
                        hasher.update(data);
                        let digest = hasher.finalize();
                        let padding = rsa::Pkcs1v15Sign::new::<Sha256>();
                        let sig = private.sign(padding, &digest)
                            .map_err(|e| CryptoError::CipherError(e.to_string()))?;
                        write_ssh_string(&mut sig_out, b"rsa-sha2-256");
                        write_ssh_string(&mut sig_out, &sig);
                    }
                }
                Ok(sig_out)
            }
            Self::EcdsaP256 { secret, .. } => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                let digest = hasher.finalize();
                let signing_key = p256::ecdsa::SigningKey::from(secret);
                use p256::ecdsa::signature::Signer;
                let sig: p256::ecdsa::Signature = signing_key.sign(&digest);
                let mut sig_out = Vec::new();
                write_ssh_string(&mut sig_out, b"ecdsa-sha2-nistp256");
                let mut inner = Vec::new();
                let (r, s) = sig.split_bytes();
                write_ssh_mpint(&mut inner, &r);
                write_ssh_mpint(&mut inner, &s);
                write_ssh_string(&mut sig_out, &inner);
                Ok(sig_out)
            }
            Self::Ed25519 { .. } => {
                if fips_mode {
                    return Err(CryptoError::Fips(FipsError::DisallowedHostKey {
                        hostkey: "ssh-ed25519".to_string(),
                        approved: FipsPolicy::APPROVED_HOSTKEYS.join(", "),
                    }));
                }
                let mut sig_out = Vec::new();
                write_ssh_string(&mut sig_out, b"ssh-ed25519");
                write_ssh_string(&mut sig_out, &[0u8; 64]);
                Ok(sig_out)
            }
        }
    }
}

pub fn write_ssh_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

pub fn write_ssh_mpint(out: &mut Vec<u8>, data: &[u8]) {
    // Strip leading zeros
    let mut slice = data;
    while slice.len() > 1 && slice[0] == 0 {
        slice = &slice[1..];
    }
    if !slice.is_empty() && (slice[0] & 0x80) != 0 {
        out.extend_from_slice(&((slice.len() + 1) as u32).to_be_bytes());
        out.push(0);
        out.extend_from_slice(slice);
    } else {
        out.extend_from_slice(&(slice.len() as u32).to_be_bytes());
        out.extend_from_slice(slice);
    }
}
