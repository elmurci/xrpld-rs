use serde::{Deserialize, Serialize};
use core::fmt;

/// Field data type codes <https://xrpl.org/serialization.html#type-list>
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize)]
#[repr(u8)]
pub enum TypeCode {
    // Discriminant values can be found at https://xrpl.org/serialization.html#type-list and also at https://github.com/XRPLF/xrpl.js/blob/main/packages/ripple-binary-codec/src/enums/definitions.json
    AccountId = 8,
    Amount = 6,
    Blob = 7,
    Hash128 = 4,
    Hash160 = 17,
    Hash256 = 5,
    UInt8 = 16,
    UInt16 = 1,
    UInt32 = 2,
    UInt64 = 3,
    Array = 15,
    Object = 14,
}

impl fmt::Display for TypeCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}