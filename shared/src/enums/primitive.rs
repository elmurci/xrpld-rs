use serde::{Deserialize, Serialize};

use crate::{errors::binary_codec::BinaryCodecError::{self, InvalidData}, structs::st_object::StObject};
use core::{fmt, fmt::{Debug, Formatter}};

use super::amount::Amount;

#[derive(Clone, Eq, PartialEq, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum XrplType {
    AccountId(AccountId),
    Blob(Blob),
    Hash128(Hash128),
    Hash160(Hash160),
    Hash256(Hash256),
    UInt8(UInt8),
    UInt16(UInt16),
    UInt32(UInt32),
    Uint64(Uint64),
    Amount(Amount),
    Array(Vec<u8>),
    StObject(StObject),
}

#[derive(Clone, Copy, Default, Eq, Deserialize, Serialize, PartialEq, Hash)]
pub struct AccountId(pub [u8; 20]);

impl AccountId {
    /// Decodes account id from address, see <https://xrpl.org/accounts.html#address-encoding>
    pub fn from_address(address: &str) -> Result<Self, BinaryCodecError> {
        let decoded = bs58::decode(address)
            .with_alphabet(bs58::Alphabet::RIPPLE)
            .with_check(Some(0u8))
            .into_vec()
            .map_err(|err| InvalidData(format!("invalid address: {}", err)))?;

        // Skip the 0x00 ('r') version prefix
        let decoded = &decoded[1..];

        let bytes: [u8; 20] = decoded.try_into().map_err(|_| {
            InvalidData("address does not encode exactly 20 bytes".to_string())
        })?;

        Ok(Self(bytes))
    }

    /// Encodes account id to address, see <https://xrpl.org/accounts.html#address-encoding>
    pub fn to_address(&self) -> String {
        bs58::encode(&self.0)
            .with_alphabet(bs58::Alphabet::RIPPLE)
            .with_check_version(0u8) // Add the 0x00 ('r') version prefix
            .into_string()
    }
}

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize, Hash)]
pub struct Blob(pub Vec<u8>);

#[derive(Clone, Copy, Eq, Serialize, Deserialize, PartialEq, Hash)]
pub struct Hash128(pub [u8; 16]);

#[derive(Clone, Copy, Eq, Serialize, Deserialize, PartialEq, Hash)]
pub struct Hash160(pub [u8; 20]);

#[derive(Clone, Copy, Eq, Serialize, Deserialize, PartialEq, Hash)]
pub struct Hash256(pub [u8; 32]);

pub type UInt8 = u8;
pub type UInt16 = u16;
pub type UInt32 = u32;
pub type Uint64 = u64;

impl XrplType {
    pub fn unwrap_u32(self) -> UInt32 {
        match self {
            XrplType::UInt32(v) => v,
            _ => panic!("not a UInt32 type"),
        }
    }
    pub fn unwrap_string(self) -> String {
        match self {
            XrplType::Hash256(v) => v.to_hex(),
            XrplType::Blob(v) => v.to_hex(),
            _ => panic!("not a Blob type"),
        }
    }
    pub fn unwrap_object(self) -> StObject {
        match self {
            XrplType::StObject(v) => v,
            _ => panic!("not a Blob type"),
        }
    }
}

impl Hash128 {
    pub fn from_hex(hex: &str) -> Result<Self, BinaryCodecError> {
        let decoded =
            hex::decode(hex).map_err(|err| InvalidData(format!("invalid hex: {}", err)))?;

        let bytes: [u8; 16] = decoded.try_into().map_err(|_| {
            InvalidData("address does not encode exactly 16 bytes".to_string())
        })?;

        Ok(Hash128(bytes))
    }

    pub fn to_hex(&self) -> String {
        hex::encode_upper(self.0)
    }
}

impl Hash160 {
    pub fn from_hex(hex: &str) -> Result<Self, BinaryCodecError> {
        let decoded =
            hex::decode(hex).map_err(|err| InvalidData(format!("invalid hex: {}", err)))?;

        let bytes: [u8; 20] = decoded.try_into().map_err(|_| {
            InvalidData("address does not encode exactly 20 bytes".to_string())
        })?;

        Ok(Hash160(bytes))
    }

    pub fn to_hex(&self) -> String {
        hex::encode_upper(self.0)
    }
}

impl Hash256 {
    pub fn from_hex(hex: &str) -> Result<Self, BinaryCodecError> {
        let decoded =
            hex::decode(hex).map_err(|err| InvalidData(format!("invalid hex: {}", err)))?;

        let bytes: [u8; 32] = decoded.try_into().map_err(|_| {
            InvalidData("address does not encode exactly 32 bytes".to_string())
        })?;

        Ok(Hash256(bytes))
    }

    pub fn to_hex(&self) -> String {
        hex::encode_upper(self.0)
    }
}

impl Blob {
    pub fn from_hex(hex: &str) -> Result<Self, BinaryCodecError> {
        let decoded =
            hex::decode(hex).map_err(|err| InvalidData(format!("invalid hex: {}", err)))?;

        Ok(Blob(decoded))
    }

    pub fn to_hex(&self) -> String {
        hex::encode_upper(&self.0)
    }
}

impl Debug for Hash128 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        for i in &self.0 {
            write!(f, "{:02X}", i)?;
        }
        Ok(())
    }
}

impl Debug for Hash160 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        for i in &self.0 {
            write!(f, "{:02X}", i)?;
        }
        Ok(())
    }
}

impl Debug for Hash256 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        for i in &self.0 {
            write!(f, "{:02X}", i)?;
        }
        Ok(())
    }
}

impl Debug for Blob {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        for i in &self.0 {
            write!(f, "{:02X}", i)?;
        }
        Ok(())
    }
}

impl Debug for AccountId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        for i in &self.0 {
            write!(f, "{:02X}", i)?;
        }
        Ok(())
    }
}