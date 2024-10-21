#[derive(Debug, Clone, PartialEq)]
pub enum BinaryCodecError {
    OutOfRange(String),
    FieldOrder(String),
    InvalidField(String),
    InvalidLength(String),
    FieldNotFound(String),
    InvalidData(String),
    InsufficientBytes(String),
    Overflow,
}