use serde::Deserialize;
use xrpl_types::{
    AccountId, Blob, CurrencyCode, Hash128, Hash160, Hash256, StandardCurrencyCode, UInt16, UInt32, UInt8, Uint64
};
use bytes::{Buf, Bytes};
use core::str;
use std::collections::HashMap;
use crate::structs::{amount::{Amount, DropsAmount, IssuedAmount, IssuedValue}, field_id::{FieldId, TypeCode}, field_info::FieldInfo};
use crate::utils::string::to_3_ascii_chars;

#[derive(Debug, Clone, PartialEq)]
pub enum BinaryCodecError {
    OutOfRange(String),
    FieldOrder(String),
    InvalidField(String),
    InvalidLength(String),
    FieldNotFound(String),
    InsufficientBytes(String),
    Overflow,
}

const OBJECT_NAME: &str = "STObject";
const OBJECT_END_MARKER_NAME: &str = "ObjectEndMarker";
const OBJECT_END_MARKER_BYTE: &[u8] = &[0xE1];

const ARRAY_END_MARKER: &[u8] = &[0xf1];
const ARRAY_END_MARKER_NAME: &str = "ArrayEndMarker";
const OBJECT_END_MARKER_ARRAY: &[u8] = &[0xE1];


#[derive(Debug, Clone, Deserialize)]
pub struct FieldInstance {
    pub info: FieldInfo,
    pub name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Deserializer {
    bytes: Bytes,
    field_ordinal_lookup: HashMap<u32, FieldInstance>,
}

impl Deserializer {
    pub fn new(bytes: Vec<u8>, field_info_map: HashMap<String, FieldInfo>) -> Self {
        let mut field_ordinal_lookup = HashMap::new();
        for (name, info) in field_info_map {
            let ordinal = info.ordinal();
            let field = FieldInstance {
                info: info.clone(),
                name: name.clone(),
            };
            field_ordinal_lookup.insert(ordinal, field);
        }
        Self {
            bytes: Bytes::from(bytes),
            field_ordinal_lookup,
        }
    }

    fn peek(&mut self) -> Result<u8, BinaryCodecError> {
        if self.bytes.remaining() < 1 {
            return Err(BinaryCodecError::InsufficientBytes("read".into()));
        }
        Ok(self.bytes.to_vec()[0])
    }

    fn read(&mut self, n: usize) -> Result<Vec<u8>, BinaryCodecError> {
        if self.bytes.remaining() < n {
            return Err(BinaryCodecError::InsufficientBytes("read".into()));
        }
        let bytes = self.bytes.split_to(n);
        Ok(bytes.to_vec())
    }

    fn read_u8(&mut self) -> Result<u8, BinaryCodecError> {
        if self.bytes.has_remaining() {
            Ok(self.bytes.get_u8())
        } else {
            Err(BinaryCodecError::InsufficientBytes("read_u8".into()))
        }
    }

    fn read_variable_length(&mut self) -> Result<usize, BinaryCodecError> {
        let b1 = self.read_u8()? as usize;
        if b1 <= 192 {
            Ok(b1)
        } else if b1 <= 240 {
            let b2 = self.read_u8()? as usize;
            Ok(193 + (b1 - 193) * 256 + b2)
        } else if b1 <= 254 {
            let b2 = self.read_u8()? as usize;
            let b3 = self.read_u8()? as usize;
            Ok(12481 + (b1 - 241) * 65536 + b2 * 256 + b3)
        } else {
            Err(BinaryCodecError::InvalidLength(
                "Invalid variable length indicator".into(),
            ))
        }
    }

    fn read_field_ordinal(&mut self) -> Result<u32, BinaryCodecError> {
        let mut type_code = self.read_u8()? as u32;
        let mut nth = type_code & 15;
        
        type_code >>= 4;
        if type_code == 0 {
            type_code = self.read_u8()? as u32;
            if type_code == 0 || type_code < 16 {
                return Err(BinaryCodecError::OutOfRange(
                    "FieldOrdinal, type_code out of range".into(),
                ));
            }
        }
        if nth == 0 {
            nth = self.read_u8()? as u32;
            if nth == 0 || nth < 16 {
                return Err(BinaryCodecError::OutOfRange(
                    "FieldOrdinal, type_code out of range".into(),
                ));
            }
        }
        Ok((type_code << 16) | nth)
    }

    pub fn read_field(&mut self) -> Result<FieldInstance, BinaryCodecError> {
        let ordinal = self.read_field_ordinal()?;
        self.field_ordinal_lookup
            .get(&ordinal)
            .cloned()
            .ok_or(BinaryCodecError::FieldNotFound(format!("Field {} not found", ordinal)))
    }

    pub fn read_field_value(&mut self, info: &FieldInfo) -> Result<TypeCode, BinaryCodecError> {
        let size_hint: Option<usize> = if info.is_vl_encoded {
            Some(self.read_variable_length()?)
        } else {
            None
        };

        let bytes: = match info.field_type {
            TypeCode::Hash256 => self.deserialize_hash256()?,
            TypeCode::AccountId => self.deserialize_account_id()?,
            TypeCode::Blob => {
                let hint =
                    size_hint.ok_or(BinaryCodecError::FieldNotFound("missing hint".into()))?;
                self.deserialize_blob(hint)?.0.to_vec()
            }
            // TypeCode::Object => self.deserialize_object()?,
            TypeCode::Array => self.deserialize_array()?,
            TypeCode::Amount => self.deserialize_amount()?,
            TypeCode::UInt8 => self.deserialize_uint8()?.to_be_bytes().to_vec(),
            TypeCode::UInt16 => self.deserialize_uint16()?.to_be_bytes().to_vec(),
            TypeCode::UInt32 => self.deserialize_uint32()?.to_be_bytes().to_vec(),
            TypeCode::UInt64 => self.deserialize_uint64()?.to_be_bytes().to_vec(),
            _ => vec![], // TODO: default other types to Blob for now
        };
        Ok(bytes)
    }

    pub fn end(&mut self) -> bool {
        self.bytes.remaining() == 0
    }

}

#[allow(dead_code)]
impl Deserializer {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), BinaryCodecError> {
        if self.bytes.remaining() < buf.len() {
            return Err(BinaryCodecError::InsufficientBytes("read_exact".into()));
        }
        self.bytes.copy_to_slice(buf);
        Ok(())
    }

    fn deserialize_account_id(&mut self) -> Result<AccountId, BinaryCodecError> {
        let mut bytes = [0u8; 20];
        self.read_exact(&mut bytes)?;
        Ok(AccountId(bytes))
    }

    fn deserialize_amount(&mut self) -> Result<Amount, BinaryCodecError> {
        let byte = self.peek()?;
        let is_xrp = byte & 0x80 == 0;
        log::debug!("is_xrp {:?}", is_xrp);
        if is_xrp {
            self.deserialize_native_amount()
        } else {
            self.deserialize_issued_amount()
        }
    }

    fn deserialize_issued_amount(&mut self) -> Result<Amount, BinaryCodecError> {

        // 1 bit - XRP or Issued
        // 1 bit - Sign
        // 8 bits - Exponent
        // 54 bits - Significant digits
        // 20 bits - Currency
        // 20 bits - Issuer

        log::debug!("empezamos {:?}", self.bytes.to_vec().len());

        let mut bytes = [0u8; 48];
        
        self.read_exact(&mut bytes)?;

        log::debug!("Is it Issued? {:?}", (bytes[0] & 0b1000_0000) != 0);

        log::debug!("Is it positive sign? {:?}",  (bytes[0] & 0b0100_0000) != 0);

        let exponent: i32 = ((((&bytes[0] & 0x3f) << 2) + ((&bytes[1] & 0xff) >> 6)) as i16 - 97).into();

        bytes[0] = 0;
        bytes[1] &= 0x3f;

        let mantissa = i64::from_be_bytes(bytes[0..8].try_into().expect("slice with incorrect length"));
        let value = mantissa as f64 * f64::powi(10f64, exponent);
   
        log::debug!("value {}", value);
        let currency_code_bytes: [u8; 20] = bytes[8..28].try_into().expect("slice with incorrect length");
        let currency_code_str = String::from_utf8_lossy(&currency_code_bytes[12..15]);
        log::debug!("currency code {}", currency_code_str);
        let issuer_bytes: [u8; 20] = bytes[28..48].try_into().expect("slice with incorrect length");
        log::debug!("issuer {:?}", AccountId(issuer_bytes).to_address());

        let issued_amount = IssuedAmount::from_issued_value(IssuedValue::from_mantissa_exponent(mantissa, exponent as i8).unwrap(), CurrencyCode::Standard(StandardCurrencyCode::from_ascii_chars(to_3_ascii_chars(&currency_code_str.to_string()).unwrap()).unwrap()), AccountId(issuer_bytes)).unwrap();

        Ok(Amount::Issued(issued_amount))
    }

    fn deserialize_native_amount(&mut self) -> Result<Amount, BinaryCodecError> {
        self.deserialize_amount()?;
        let mut bytes = [0u8; 8];
        self.read_exact(&mut bytes)?;
        
        // Convert the byte array to a u64 integer using big-endian order
        let value = u64::from_be_bytes(bytes);

        // Mask the value to keep only the lower 62 bits
        let masked_value = value & 0x3FFFFFFFFFFFFFFF;
        Ok(Amount::Drops(DropsAmount(masked_value)))
    }

    pub fn deserialize_blob(&mut self, len: usize) -> Result<Blob, BinaryCodecError> {
        let mut bytes = vec![0u8; len];
        self.read_exact(&mut bytes)?;
        log::debug!("Blob(bytes) {:?}", Blob(bytes.clone()));
        Ok(Blob(bytes))
    }

    fn deserialize_hash128(&mut self) -> Result<Hash128, BinaryCodecError> {
        let mut bytes = [0u8; 16];
        self.read_exact(&mut bytes)?;
        Ok(Hash128(bytes))
    }

    fn deserialize_hash160(&mut self) -> Result<Hash160, BinaryCodecError> {
        let mut bytes = [0u8; 20];
        self.read_exact(&mut bytes)?;
        Ok(Hash160(bytes))
    }

    fn deserialize_hash256(&mut self) -> Result<Hash256, BinaryCodecError> {
        let mut bytes = [0u8; 32];
        self.read_exact(&mut bytes)?;
        Ok(Hash256(bytes))
    }

    fn deserialize_uint8(&mut self) -> Result<UInt8, BinaryCodecError> {
        let mut bytes = [0u8; 1];
        self.read_exact(&mut bytes)?;
        Ok(UInt8::from_be_bytes(bytes))
    }

    fn deserialize_uint16(&mut self) -> Result<UInt16, BinaryCodecError> {
        let mut bytes = [0u8; 2];
        self.read_exact(&mut bytes)?;
        Ok(UInt16::from_be_bytes(bytes))
    }

    fn deserialize_uint32(&mut self) -> Result<UInt32, BinaryCodecError> {
        let mut bytes = [0u8; 4];
        self.read_exact(&mut bytes)?;
        Ok(UInt32::from_be_bytes(bytes))
    }

    fn deserialize_uint64(&mut self) -> Result<Uint64, BinaryCodecError> {
        let mut bytes = [0u8; 8];
        self.read_exact(&mut bytes)?;
        Ok(Uint64::from_be_bytes(bytes))
    }

    fn deserialize_array(&mut self) -> Result<Vec<u8>, BinaryCodecError> {
        let mut bytes = Vec::new();
        while !self.end() {
            let field = self.read_field()?;
            if field.name == ARRAY_END_MARKER_NAME {
                break;
            }
            let header: Vec<u8> = FieldId::from(field.info.clone()).into();
            bytes.extend_from_slice(&header);
            let data = self.read_field_value(&field.info)?;
            bytes.extend_from_slice(data.as_ref());
            bytes.extend_from_slice(OBJECT_END_MARKER_ARRAY);
        }
        bytes.extend_from_slice(ARRAY_END_MARKER);
        Ok(bytes)
    }

    pub fn deserialize_object(&mut self) -> Result<HashMap<String, String>, BinaryCodecError> {
        let mut result = HashMap::new();
        while !self.end() {
            let field = self.read_field()?;
            if field.name == OBJECT_END_MARKER_NAME {
                break;
            }
            let data = self.read_field_value(&field.info)?;
            let d = match field.info.field_type {
                TypeCode::UInt16 => {
                    u16::from_be_bytes(data.try_into().unwrap()).to_string()
                }
                TypeCode::UInt32 => {
                    u32::from_be_bytes(data.try_into().unwrap()).to_string()
                }
                _ => {
                    "".to_string()
                }
            };
            result.insert(field.name, d);
        }

        log::debug!("Deserialize result {:?}", result);

        Ok(result)
    }
}

fn encode_variable_length(length: usize) -> Result<Vec<u8>, BinaryCodecError> {
    let mut len_bytes = [0u8; 3];
    if length <= 192 {
        len_bytes[0] = length as u8;
        Ok(len_bytes[0..1].to_vec())
    } else if length <= 12480 {
        let length = length - 193;
        len_bytes[0] = 193 + ((length >> 8) as u8);
        len_bytes[1] = (length & 0xff) as u8;
        Ok(len_bytes[0..2].to_vec())
    } else if length <= 918744 {
        let length = length - 12481;
        len_bytes[0] = 241 + ((length >> 16) as u8);
        len_bytes[1] = ((length >> 8) & 0xff) as u8;
        len_bytes[2] = (length & 0xff) as u8;
        Ok(len_bytes[0..3].to_vec())
    } else {
        Err(BinaryCodecError::Overflow)
    }
}
