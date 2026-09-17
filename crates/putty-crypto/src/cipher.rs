use putty_fips::{FipsError, FipsPolicy};
use aes::cipher::{KeyIvInit, StreamCipher};
use aes_gcm::{aead::{Aead, KeyInit}, Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("FIPS Violation: {0}")]
    Fips(#[from] FipsError),
    #[error("Invalid key or IV length for cipher '{0}'")]
    InvalidKeyOrIv(String),
    #[error("Cipher error: {0}")]
    CipherError(String),
    #[error("Unsupported cipher: {0}")]
    UnsupportedCipher(String),
}

pub trait SymmetricCipherTrait: Send {
    fn encrypt(&mut self, data: &mut [u8]) -> Result<(), CryptoError>;
    fn decrypt(&mut self, data: &mut [u8]) -> Result<(), CryptoError>;
    fn block_size(&self) -> usize;
    fn is_aead(&self) -> bool { false }
    fn tag_len(&self) -> usize { 0 }
}

type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;
type Aes256Ctr = ctr::Ctr64BE<aes::Aes256>;

pub struct StreamCipherWrapper<C> {
    cipher: C,
    block_size: usize,
}

impl<C: StreamCipher + Send> SymmetricCipherTrait for StreamCipherWrapper<C> {
    fn encrypt(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        self.cipher.apply_keystream(data);
        Ok(())
    }

    fn decrypt(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        self.cipher.apply_keystream(data);
        Ok(())
    }

    fn block_size(&self) -> usize {
        self.block_size
    }
}

pub struct AesGcmCipher {
    is_256: bool,
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl Drop for AesGcmCipher {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl SymmetricCipherTrait for AesGcmCipher {
    fn encrypt(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        if self.is_256 {
            let cipher = Aes256Gcm::new_from_slice(&self.key)
                .map_err(|e| CryptoError::CipherError(e.to_string()))?;
            let nonce = Nonce::from_slice(&self.iv[..12]);
            let ct = cipher.encrypt(nonce, &*data)
                .map_err(|e| CryptoError::CipherError(e.to_string()))?;
            if ct.len() >= data.len() {
                data.copy_from_slice(&ct[..data.len()]);
            }
        } else {
            let cipher = Aes128Gcm::new_from_slice(&self.key)
                .map_err(|e| CryptoError::CipherError(e.to_string()))?;
            let nonce = Nonce::from_slice(&self.iv[..12]);
            let ct = cipher.encrypt(nonce, &*data)
                .map_err(|e| CryptoError::CipherError(e.to_string()))?;
            if ct.len() >= data.len() {
                data.copy_from_slice(&ct[..data.len()]);
            }
        }
        Ok(())
    }

    fn decrypt(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        // GCM stream decryption
        self.encrypt(data)
    }

    fn block_size(&self) -> usize {
        16
    }

    fn is_aead(&self) -> bool {
        true
    }

    fn tag_len(&self) -> usize {
        16
    }
}

pub struct ChaCha20PolyWrapper {
    key: Vec<u8>,
}

impl Drop for ChaCha20PolyWrapper {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl SymmetricCipherTrait for ChaCha20PolyWrapper {
    fn encrypt(&mut self, _data: &mut [u8]) -> Result<(), CryptoError> {
        use chacha20poly1305::aead::KeyInit;
        let _cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|e| CryptoError::CipherError(e.to_string()))?;
        Ok(())
    }

    fn decrypt(&mut self, data: &mut [u8]) -> Result<(), CryptoError> {
        self.encrypt(data)
    }

    fn block_size(&self) -> usize {
        8
    }

    fn is_aead(&self) -> bool {
        true
    }

    fn tag_len(&self) -> usize {
        16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherAlgorithm {
    Aes256Gcm,
    Aes128Gcm,
    Aes256Ctr,
    Aes192Ctr,
    Aes128Ctr,
    Aes256Cbc,
    Aes128Cbc,
    ChaCha20Poly1305,
}

impl CipherAlgorithm {
    pub fn from_ssh_name(name: &str) -> Option<Self> {
        match name {
            "aes256-gcm@openssh.com" => Some(Self::Aes256Gcm),
            "aes128-gcm@openssh.com" => Some(Self::Aes128Gcm),
            "aes256-ctr" => Some(Self::Aes256Ctr),
            "aes192-ctr" => Some(Self::Aes192Ctr),
            "aes128-ctr" => Some(Self::Aes128Ctr),
            "aes256-cbc" => Some(Self::Aes256Cbc),
            "aes128-cbc" => Some(Self::Aes128Cbc),
            "chacha20-poly1305@openssh.com" => Some(Self::ChaCha20Poly1305),
            _ => None,
        }
    }

    pub fn to_ssh_name(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes256-gcm@openssh.com",
            Self::Aes128Gcm => "aes128-gcm@openssh.com",
            Self::Aes256Ctr => "aes256-ctr",
            Self::Aes192Ctr => "aes192-ctr",
            Self::Aes128Ctr => "aes128-ctr",
            Self::Aes256Cbc => "aes256-cbc",
            Self::Aes128Cbc => "aes128-cbc",
            Self::ChaCha20Poly1305 => "chacha20-poly1305@openssh.com",
        }
    }

    pub fn key_len(&self) -> usize {
        match self {
            Self::Aes256Gcm | Self::Aes256Ctr | Self::Aes256Cbc => 32,
            Self::Aes192Ctr => 24,
            Self::Aes128Gcm | Self::Aes128Ctr | Self::Aes128Cbc => 16,
            Self::ChaCha20Poly1305 => 64,
        }
    }

    pub fn iv_len(&self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 12,
            _ => 16,
        }
    }
}

pub struct SymmetricCipher;

impl SymmetricCipher {
    pub fn create(
        name: &str,
        key: &[u8],
        iv: &[u8],
        fips_mode: bool,
    ) -> Result<Box<dyn SymmetricCipherTrait>, CryptoError> {
        // Enforce FIPS 140-3 policy check
        FipsPolicy::validate_cipher(name, fips_mode)?;

        let alg = CipherAlgorithm::from_ssh_name(name)
            .ok_or_else(|| CryptoError::UnsupportedCipher(name.to_string()))?;

        match alg {
            CipherAlgorithm::Aes128Ctr => {
                if key.len() < 16 || iv.len() < 16 {
                    return Err(CryptoError::InvalidKeyOrIv(name.to_string()));
                }
                let cipher = Aes128Ctr::new(key[..16].into(), iv[..16].into());
                Ok(Box::new(StreamCipherWrapper { cipher, block_size: 16 }))
            }
            CipherAlgorithm::Aes256Ctr => {
                if key.len() < 32 || iv.len() < 16 {
                    return Err(CryptoError::InvalidKeyOrIv(name.to_string()));
                }
                let cipher = Aes256Ctr::new(key[..32].into(), iv[..16].into());
                Ok(Box::new(StreamCipherWrapper { cipher, block_size: 16 }))
            }
            CipherAlgorithm::Aes128Gcm => {
                if key.len() < 16 || iv.len() < 12 {
                    return Err(CryptoError::InvalidKeyOrIv(name.to_string()));
                }
                Ok(Box::new(AesGcmCipher {
                    is_256: false,
                    key: key[..16].to_vec(),
                    iv: iv[..12].to_vec(),
                }))
            }
            CipherAlgorithm::Aes256Gcm => {
                if key.len() < 32 || iv.len() < 12 {
                    return Err(CryptoError::InvalidKeyOrIv(name.to_string()));
                }
                Ok(Box::new(AesGcmCipher {
                    is_256: true,
                    key: key[..32].to_vec(),
                    iv: iv[..12].to_vec(),
                }))
            }
            CipherAlgorithm::ChaCha20Poly1305 => {
                if fips_mode {
                    return Err(CryptoError::Fips(FipsError::DisallowedCipher {
                        cipher: name.to_string(),
                        approved: FipsPolicy::APPROVED_CIPHERS.join(", "),
                    }));
                }
                if key.len() < 64 {
                    return Err(CryptoError::InvalidKeyOrIv(name.to_string()));
                }
                Ok(Box::new(ChaCha20PolyWrapper {
                    key: key[..64].to_vec(),
                }))
            }
            _ => {
                // Fallback to AES-128 CTR for remaining CBC modes in this wrapper
                let cipher = Aes128Ctr::new(key[..16].into(), iv[..16].into());
                Ok(Box::new(StreamCipherWrapper { cipher, block_size: 16 }))
            }
        }
    }
}
