use crate::cipher::CryptoError;
use putty_fips::{FipsError, FipsPolicy};
use hmac::Hmac;
use sha2::{Sha256, Sha512};
use sha1::Sha1;
use md5::Md5;
use hmac::digest::Mac;
use zeroize::Zeroize;

pub trait MacTrait: Send {
    fn update(&mut self, data: &[u8]);
    fn finalize_reset(&mut self) -> Vec<u8>;
    fn verify(&mut self, expected: &[u8]) -> bool;
    fn mac_len(&self) -> usize;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacAlgorithm {
    HmacSha256,
    HmacSha512,
    HmacSha256Etm,
    HmacSha512Etm,
    HmacSha1,
    HmacMd5,
}

impl MacAlgorithm {
    pub fn from_ssh_name(name: &str) -> Option<Self> {
        match name {
            "hmac-sha2-256" => Some(Self::HmacSha256),
            "hmac-sha2-512" => Some(Self::HmacSha512),
            "hmac-sha2-256-etm@openssh.com" => Some(Self::HmacSha256Etm),
            "hmac-sha2-512-etm@openssh.com" => Some(Self::HmacSha512Etm),
            "hmac-sha1" => Some(Self::HmacSha1),
            "hmac-md5" => Some(Self::HmacMd5),
            _ => None,
        }
    }

    pub fn to_ssh_name(&self) -> &'static str {
        match self {
            Self::HmacSha256 => "hmac-sha2-256",
            Self::HmacSha512 => "hmac-sha2-512",
            Self::HmacSha256Etm => "hmac-sha2-256-etm@openssh.com",
            Self::HmacSha512Etm => "hmac-sha2-512-etm@openssh.com",
            Self::HmacSha1 => "hmac-sha1",
            Self::HmacMd5 => "hmac-md5",
        }
    }

    pub fn key_len(&self) -> usize {
        match self {
            Self::HmacSha256 | Self::HmacSha256Etm => 32,
            Self::HmacSha512 | Self::HmacSha512Etm => 64,
            Self::HmacSha1 => 20,
            Self::HmacMd5 => 16,
        }
    }

    pub fn is_etm(&self) -> bool {
        matches!(self, Self::HmacSha256Etm | Self::HmacSha512Etm)
    }
}



pub struct HmacSha256Impl {
    key: Vec<u8>,
    hmac: Hmac<Sha256>,
}

impl Drop for HmacSha256Impl {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl MacTrait for HmacSha256Impl {
    fn update(&mut self, data: &[u8]) {
        self.hmac.update(data);
    }

    fn finalize_reset(&mut self) -> Vec<u8> {
        let hmac = std::mem::replace(
            &mut self.hmac,
            <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("valid key"),
        );
        hmac.finalize().into_bytes().to_vec()
    }

    fn verify(&mut self, expected: &[u8]) -> bool {
        let tag = self.finalize_reset();
        subtle::ConstantTimeEq::ct_eq(&tag[..], expected).into()
    }

    fn mac_len(&self) -> usize {
        32
    }
}

pub struct HmacSha512Impl {
    key: Vec<u8>,
    hmac: Hmac<Sha512>,
}

impl Drop for HmacSha512Impl {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl MacTrait for HmacSha512Impl {
    fn update(&mut self, data: &[u8]) {
        self.hmac.update(data);
    }

    fn finalize_reset(&mut self) -> Vec<u8> {
        let hmac = std::mem::replace(
            &mut self.hmac,
            <Hmac<Sha512> as Mac>::new_from_slice(&self.key).expect("valid key"),
        );
        hmac.finalize().into_bytes().to_vec()
    }

    fn verify(&mut self, expected: &[u8]) -> bool {
        let tag = self.finalize_reset();
        subtle::ConstantTimeEq::ct_eq(&tag[..], expected).into()
    }

    fn mac_len(&self) -> usize {
        64
    }
}

pub struct HmacSha1Impl {
    key: Vec<u8>,
    hmac: Hmac<Sha1>,
}

impl Drop for HmacSha1Impl {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl MacTrait for HmacSha1Impl {
    fn update(&mut self, data: &[u8]) {
        self.hmac.update(data);
    }

    fn finalize_reset(&mut self) -> Vec<u8> {
        let hmac = std::mem::replace(
            &mut self.hmac,
            <Hmac<Sha1> as Mac>::new_from_slice(&self.key).expect("valid key"),
        );
        hmac.finalize().into_bytes().to_vec()
    }

    fn verify(&mut self, expected: &[u8]) -> bool {
        let tag = self.finalize_reset();
        subtle::ConstantTimeEq::ct_eq(&tag[..], expected).into()
    }

    fn mac_len(&self) -> usize {
        20
    }
}

pub struct HmacMd5Impl {
    key: Vec<u8>,
    hmac: Hmac<Md5>,
}

impl Drop for HmacMd5Impl {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl MacTrait for HmacMd5Impl {
    fn update(&mut self, data: &[u8]) {
        self.hmac.update(data);
    }

    fn finalize_reset(&mut self) -> Vec<u8> {
        let hmac = std::mem::replace(
            &mut self.hmac,
            <Hmac<Md5> as Mac>::new_from_slice(&self.key).expect("valid key"),
        );
        hmac.finalize().into_bytes().to_vec()
    }

    fn verify(&mut self, expected: &[u8]) -> bool {
        let tag = self.finalize_reset();
        subtle::ConstantTimeEq::ct_eq(&tag[..], expected).into()
    }

    fn mac_len(&self) -> usize {
        16
    }
}

pub struct MacCalculator;

impl MacCalculator {
    pub fn create(
        name: &str,
        key: &[u8],
        fips_mode: bool,
    ) -> Result<Box<dyn MacTrait>, CryptoError> {
        // Enforce FIPS 140-3 policy check
        FipsPolicy::validate_mac(name, fips_mode)?;

        let alg = MacAlgorithm::from_ssh_name(name)
            .ok_or_else(|| CryptoError::UnsupportedCipher(name.to_string()))?;

        match alg {
            MacAlgorithm::HmacSha256 | MacAlgorithm::HmacSha256Etm => {
                let hmac = <Hmac<Sha256> as Mac>::new_from_slice(key)
                    .map_err(|e| CryptoError::CipherError(e.to_string()))?;
                Ok(Box::new(HmacSha256Impl {
                    key: key.to_vec(),
                    hmac,
                }))
            }
            MacAlgorithm::HmacSha512 | MacAlgorithm::HmacSha512Etm => {
                let hmac = <Hmac<Sha512> as Mac>::new_from_slice(key)
                    .map_err(|e| CryptoError::CipherError(e.to_string()))?;
                Ok(Box::new(HmacSha512Impl {
                    key: key.to_vec(),
                    hmac,
                }))
            }
            MacAlgorithm::HmacSha1 => {
                if fips_mode {
                    return Err(CryptoError::Fips(FipsError::DisallowedMac {
                        mac: name.to_string(),
                        approved: FipsPolicy::APPROVED_MACS.join(", "),
                    }));
                }
                let hmac = <Hmac<Sha1> as Mac>::new_from_slice(key)
                    .map_err(|e| CryptoError::CipherError(e.to_string()))?;
                Ok(Box::new(HmacSha1Impl {
                    key: key.to_vec(),
                    hmac,
                }))
            }
            MacAlgorithm::HmacMd5 => {
                if fips_mode {
                    return Err(CryptoError::Fips(FipsError::DisallowedMac {
                        mac: name.to_string(),
                        approved: FipsPolicy::APPROVED_MACS.join(", "),
                    }));
                }
                let hmac = <Hmac<Md5> as Mac>::new_from_slice(key)
                    .map_err(|e| CryptoError::CipherError(e.to_string()))?;
                Ok(Box::new(HmacMd5Impl {
                    key: key.to_vec(),
                    hmac,
                }))
            }
        }
    }
}
