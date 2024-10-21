use ascii::{AsciiChar, AsciiStr, AsciiString};
use core::{fmt, fmt::{Debug, Display, Formatter}, str::FromStr};
use crate::errors::binary_codec::BinaryCodecError::InvalidData;
use crate::errors::binary_codec::BinaryCodecError;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum CurrencyCode {
    /// Xrp special case, see <https://xrpl.org/currency-formats.html#standard-currency-codes>
    Xrp,
    /// Iso style currency code <https://xrpl.org/currency-formats.html#standard-currency-codes>
    Standard(StandardCurrencyCode),
    /// Hex style currency code <https://xrpl.org/currency-formats.html#nonstandard-currency-codes>
    NonStandard(NonStandardCurrencyCode),
}

impl CurrencyCode {
    pub fn xrp() -> Self {
        CurrencyCode::Xrp
    }

    pub fn standard(chars: [AsciiChar; 3]) -> Result<Self, BinaryCodecError> {
        Ok(CurrencyCode::Standard(
            StandardCurrencyCode::from_ascii_chars(chars)?,
        ))
    }

    pub fn non_standard(bytes: [u8; 20]) -> Result<Self, BinaryCodecError> {
        Ok(CurrencyCode::NonStandard(
            NonStandardCurrencyCode::from_bytes(bytes)?,
        ))
    }

    pub fn is_xrp(&self) -> bool {
        matches!(self, CurrencyCode::Xrp)
    }

    pub fn is_standard(&self) -> bool {
        matches!(self, CurrencyCode::Standard(_))
    }

    pub fn is_non_standard(&self) -> bool {
        matches!(self, CurrencyCode::NonStandard(_))
    }
}

impl FromStr for CurrencyCode {
    type Err = BinaryCodecError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "XRP" {
            Ok(CurrencyCode::Xrp)
        } else if s.len() == 3 {
            let ascii_chars = to_3_ascii_chars(s)?;
            CurrencyCode::standard(ascii_chars)
        } else {
            let bytes = hex::decode(s).map_err(|_| {
                InvalidData(format!(
                    "Currency code is neither three letter symbol neither hex string: {}",
                    s
                ))
            })?;
            let bytes: [u8; 20] = bytes.try_into().map_err(|_| {
                InvalidData("Currency code hex string is not 20 bytes".to_string())
            })?;
            CurrencyCode::non_standard(bytes)
        }
    }
}

impl fmt::Display for CurrencyCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CurrencyCode::Xrp => f.write_str("XRP"),
            CurrencyCode::Standard(code) => Display::fmt(&code, f),
            CurrencyCode::NonStandard(code) => Display::fmt(&code, f),
        }
    }
}

/// Iso style currency code <https://xrpl.org/currency-formats.html#standard-currency-codes>
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
// tuple element is private since it is validated when the StandardCurrencyCode value is created
pub struct StandardCurrencyCode([AsciiChar; 3]);

impl StandardCurrencyCode {
    pub fn from_ascii_chars(chars: [AsciiChar; 3]) -> Result<Self, BinaryCodecError> {
        if chars == [AsciiChar::X, AsciiChar::R, AsciiChar::P] {
            return Err(InvalidData(
                "XRP is not a valid standard currency code".to_string(),
            ));
        }
        Ok(Self(chars))
    }

    pub fn as_bytes(&self) -> [u8; 3] {
        *<&[u8; 3]>::try_from(self.as_ascii_str().as_bytes()).expect("has length 3")
    }

    pub fn as_ascii_chars(&self) -> [AsciiChar; 3] {
        self.0
    }

    pub fn as_str(&self) -> &str {
        self.as_ascii_str().as_str()
    }

    pub fn as_ascii_str(&self) -> &AsciiStr {
        <&AsciiStr>::from(&self.0 as &[AsciiChar])
    }
}

impl AsRef<[u8]> for StandardCurrencyCode {
    fn as_ref(&self) -> &[u8] {
        self.as_ascii_str().as_bytes()
    }
}

impl AsRef<str> for StandardCurrencyCode {
    fn as_ref(&self) -> &str {
        self.as_ascii_str().as_str()
    }
}

impl Display for StandardCurrencyCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self.as_ascii_str(), f)
    }
}

/// Hex style currency code <https://xrpl.org/currency-formats.html#nonstandard-currency-codes>
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
// tuple element is private since it is validated when the NonStandardCurrencyCode value is created
pub struct NonStandardCurrencyCode([u8; 20]);

impl NonStandardCurrencyCode {
    pub fn from_bytes(bytes: [u8; 20]) -> Result<Self, BinaryCodecError> {
        if bytes[0] == 0x00 {
            return Err(InvalidData(
                "Non-standard Currency code must start with byte of value zero".to_string(),
            ));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl AsRef<[u8]> for NonStandardCurrencyCode {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Display for NonStandardCurrencyCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode_upper(self.as_bytes()))
    }
}

fn to_3_ascii_chars(str: &str) -> Result<[AsciiChar; 3], BinaryCodecError> {
    let ascii_string = AsciiString::from_str(str)
        .map_err(|err| InvalidData(format!("Not valid ascii string: {}", err)))?;
    let ascii_chars = <&[AsciiChar; 3]>::try_from(ascii_string.as_slice())
        .map_err(|err| InvalidData(format!("String does not have length 3: {}", err)))?;
    Ok(*ascii_chars)
}