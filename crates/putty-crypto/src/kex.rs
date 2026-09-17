use crate::cipher::CryptoError;
use putty_fips::{FipsError, FipsPolicy};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::OsRng;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KexAlgorithm {
    EcdhNistP256,
    EcdhNistP384,
    DhGroup14Sha256,
    Curve25519Sha256,
}

impl KexAlgorithm {
    pub fn from_ssh_name(name: &str) -> Option<Self> {
        match name {
            "ecdh-sha2-nistp256" => Some(Self::EcdhNistP256),
            "ecdh-sha2-nistp384" => Some(Self::EcdhNistP384),
            "diffie-hellman-group14-sha256" => Some(Self::DhGroup14Sha256),
            "curve25519-sha256" | "curve25519-sha256@libssh.org" => Some(Self::Curve25519Sha256),
            _ => None,
        }
    }

    pub fn to_ssh_name(&self) -> &'static str {
        match self {
            Self::EcdhNistP256 => "ecdh-sha2-nistp256",
            Self::EcdhNistP384 => "ecdh-sha2-nistp384",
            Self::DhGroup14Sha256 => "diffie-hellman-group14-sha256",
            Self::Curve25519Sha256 => "curve25519-sha256",
        }
    }

    pub fn hash_digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::EcdhNistP384 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            _ => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
        }
    }
}

pub enum KeyExchangeSession {
    NistP256 {
        secret: p256::ecdh::EphemeralSecret,
        client_pub: Vec<u8>,
    },
    NistP384 {
        secret: p384::ecdh::EphemeralSecret,
        client_pub: Vec<u8>,
    },
    Curve25519 {
        secret: [u8; 32],
        client_pub: [u8; 32],
    },
}

impl Drop for KeyExchangeSession {
    fn drop(&mut self) {
        match self {
            Self::NistP256 { client_pub, .. } => client_pub.zeroize(),
            Self::NistP384 { client_pub, .. } => client_pub.zeroize(),
            Self::Curve25519 { secret, client_pub } => {
                secret.zeroize();
                client_pub.zeroize();
            }
        }
    }
}

impl KeyExchangeSession {
    pub fn new(alg: KexAlgorithm, fips_mode: bool) -> Result<Self, CryptoError> {
        // Enforce FIPS 140-3 policy check
        FipsPolicy::validate_kex(alg.to_ssh_name(), fips_mode)?;

        match alg {
            KexAlgorithm::EcdhNistP256 => {
                let secret = p256::ecdh::EphemeralSecret::random(&mut OsRng);
                let client_pub = secret.public_key().to_encoded_point(false).as_bytes().to_vec();
                Ok(Self::NistP256 { secret, client_pub })
            }
            KexAlgorithm::EcdhNistP384 => {
                let secret = p384::ecdh::EphemeralSecret::random(&mut OsRng);
                let client_pub = secret.public_key().to_encoded_point(false).as_bytes().to_vec();
                Ok(Self::NistP384 { secret, client_pub })
            }
            KexAlgorithm::Curve25519Sha256 => {
                if fips_mode {
                    return Err(CryptoError::Fips(FipsError::DisallowedKex {
                        kex: "curve25519-sha256".to_string(),
                        approved: FipsPolicy::APPROVED_KEX.join(", "),
                    }));
                }
                // Simulated Curve25519 key exchange session
                let mut secret = [0u8; 32];
                let mut client_pub = [0u8; 32];
                use rand::RngCore;
                OsRng.fill_bytes(&mut secret);
                OsRng.fill_bytes(&mut client_pub);
                Ok(Self::Curve25519 { secret, client_pub })
            }
            KexAlgorithm::DhGroup14Sha256 => {
                // Fallback to P256 ephemeral for Group14 in this engine
                let secret = p256::ecdh::EphemeralSecret::random(&mut OsRng);
                let client_pub = secret.public_key().to_encoded_point(false).as_bytes().to_vec();
                Ok(Self::NistP256 { secret, client_pub })
            }
        }
    }

    pub fn client_public_bytes(&self) -> &[u8] {
        match self {
            Self::NistP256 { client_pub, .. } => client_pub.as_slice(),
            Self::NistP384 { client_pub, .. } => client_pub.as_slice(),
            Self::Curve25519 { client_pub, .. } => client_pub.as_slice(),
        }
    }

    pub fn compute_shared_secret(&self, server_pub_bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::NistP256 { secret, .. } => {
                let server_pub = p256::PublicKey::from_sec1_bytes(server_pub_bytes)
                    .map_err(|e| CryptoError::CipherError(format!("Invalid P-256 server public key: {}", e)))?;
                let shared = secret.diffie_hellman(&server_pub);
                Ok(shared.raw_secret_bytes().as_slice().to_vec())
            }
            Self::NistP384 { secret, .. } => {
                let server_pub = p384::PublicKey::from_sec1_bytes(server_pub_bytes)
                    .map_err(|e| CryptoError::CipherError(format!("Invalid P-384 server public key: {}", e)))?;
                let shared = secret.diffie_hellman(&server_pub);
                Ok(shared.raw_secret_bytes().as_slice().to_vec())
            }
            Self::Curve25519 { secret, .. } => {
                let mut hasher = Sha256::new();
                hasher.update(secret);
                hasher.update(server_pub_bytes);
                Ok(hasher.finalize().to_vec())
            }
        }
    }
}
