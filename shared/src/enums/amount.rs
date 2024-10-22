use serde::{Deserialize, Serialize};

use crate::errors::binary_codec::BinaryCodecError;
use crate::errors::binary_codec::BinaryCodecError::{InvalidData, OutOfRange};
use super::{currency_code::CurrencyCode, primitive::AccountId};

#[derive(Debug, Eq, PartialEq, Deserialize, Serialize, Clone, Copy)]
pub enum Amount {
    Issued(IssuedAmount),
    Drops(DropsAmount),
}

impl Amount {
    pub fn drops(drops: u64) -> Result<Self, BinaryCodecError> {
        Ok(Self::Drops(DropsAmount::from_drops(drops)?))
    }

    pub fn issued(
        value: IssuedValue,
        currency: CurrencyCode,
        issuer: AccountId,
    ) -> Result<Self, BinaryCodecError> {
        Ok(Self::Issued(IssuedAmount::from_issued_value(
            value, currency, issuer,
        )?))
    }

    pub fn is_drops(&self) -> bool {
        matches!(self, Amount::Drops(_))
    }

    pub fn is_issued(&self) -> bool {
        matches!(self, Amount::Issued(_))
    }
}

/// Amount of XRP in drops, see <https://xrpl.org/currency-formats.html#xrp-amounts>
/// and <https://xrpl.org/serialization.html#amount-fields>
#[derive(Debug, Eq, PartialEq, Deserialize, Serialize, Clone, Copy)]
// tuple element is private since it is validated when the DropsAmount value is created
pub struct DropsAmount(pub u64);

impl DropsAmount {
    pub fn from_drops(drops: u64) -> Result<Self, BinaryCodecError> {
        if drops & (0b11 << 62) != 0 {
            return Err(OutOfRange(
                "Drop amounts cannot use the two must significant bits".to_string(),
            ));
        }
        Ok(Self(drops))
    }

    /// Amount of XRP in drops
    pub fn drops(&self) -> u64 {
        self.0
    }
}

/// Amount of issued token. See <https://xrpl.org/currency-formats.html#token-amounts>
/// and <https://xrpl.org/serialization.html#amount-fields>
#[derive(Debug, Eq, PartialEq, Deserialize, Serialize, Clone, Copy)]
pub struct IssuedAmount {
    // fields are private since it is validated when the IssuedAmount value is created
    value: IssuedValue,
    currency: CurrencyCode,
    issuer: AccountId,
}

impl IssuedAmount {
    pub fn from_issued_value(
        value: IssuedValue,
        currency: CurrencyCode,
        issuer: AccountId,
    ) -> Result<Self, BinaryCodecError> {
        if currency.is_xrp() {
            return Err(InvalidData(
                "Issued amount cannot have XRP currency code".to_string(),
            ));
        }
        Ok(Self {
            value,
            currency,
            issuer,
        })
    }

    /// Decimal representation of token amount, see <https://xrpl.org/serialization.html#amount-fields>
    pub fn value(&self) -> IssuedValue {
        self.value
    }

    /// Currency code, see <https://xrpl.org/serialization.html#amount-fields>
    pub fn currency(&self) -> CurrencyCode {
        self.currency
    }

    /// Issuer of token, see <https://xrpl.org/serialization.html#amount-fields>
    pub fn issuer(&self) -> AccountId {
        self.issuer
    }
}

/// The value of issued amount, see <https://xrpl.org/serialization.html#token-amount-format>
#[derive(Debug, Eq, PartialEq, Deserialize, Serialize, Clone, Copy)]
pub struct IssuedValue {
    // fields are private since it is validated when the IssuedValue value is created
    mantissa: i64,
    exponent: i8,
}

impl IssuedValue {
    /// Creates value from given mantissa and exponent. The created value will be normalized
    /// according to <https://xrpl.org/serialization.html#token-amount-format>. If the value
    /// cannot be represented, an error is returned.
    pub fn from_mantissa_exponent(mantissa: i64, exponent: i8) -> Result<Self, BinaryCodecError> {
        Self { mantissa, exponent }.normalize()
    }

    /// The value zero
    pub fn zero() -> Self {
        Self {
            mantissa: 0,
            exponent: 0,
        }
    }

    /// Signed and normalized mantissa, see <https://xrpl.org/serialization.html#token-amount-format>
    pub fn mantissa(&self) -> i64 {
        self.mantissa
    }

    /// Normalized exponent, see <https://xrpl.org/serialization.html#token-amount-format>
    pub fn exponent(&self) -> i8 {
        self.exponent
    }

    /// Normalizes value into the ranges specified at <https://xrpl.org/serialization.html#token-amount-format>
    fn normalize(self) -> Result<Self, BinaryCodecError> {
        // rippled implementation: https://github.com/seelabs/rippled/blob/cecc0ad75849a1d50cc573188ad301ca65519a5b/src/ripple/protocol/impl/IOUAmount.cpp#L38

        const MANTISSA_MIN: i64 = 1000000000000000;
        const MANTISSA_MAX: i64 = 9999999999999999;
        const EXPONENT_MIN: i8 = -96;
        const EXPONENT_MAX: i8 = 80;

        let mut exponent = self.exponent;
        let (mut mantissa, negative) = match self.mantissa {
            0 => {
                return Ok(Self::zero());
            }
            1.. => (self.mantissa, false),
            ..=-1 => (
                self.mantissa.checked_neg().ok_or_else(|| {
                    OutOfRange("Specified mantissa cannot be i64::MIN".to_string())
                })?,
                true,
            ),
        };

        while mantissa < MANTISSA_MIN && exponent > EXPONENT_MIN {
            mantissa *= 10;
            exponent -= 1;
        }

        while mantissa > MANTISSA_MAX && exponent < EXPONENT_MAX {
            mantissa /= 10;
            exponent += 1;
        }

        if mantissa > MANTISSA_MAX || exponent > EXPONENT_MAX {
            return Err(OutOfRange(format!(
                "Issued value too big to be normalized: {:?}",
                self
            )));
        }

        if mantissa < MANTISSA_MIN || exponent < EXPONENT_MIN {
            return Ok(Self::zero());
        }

        if negative {
            mantissa = -mantissa;
        }

        Ok(Self { mantissa, exponent })
    }
}