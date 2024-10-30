use ascii::{AsciiChar, AsciiString};
use core::str::FromStr;
use crate::errors::binary_codec::BinaryCodecError::InvalidData;
use crate::errors::error::Error;

// pub fn get_bits_of_byte(&mut self, byte: u8) -> [u8; 8] {
//     let mut bits = [0u8; 8];
//     for i in 0..=7 {
//         let shifted_byte = byte >> i;
//         // Get the rightmost bit of the shifted byte (least significant bit)
//         let cur_bit = shifted_byte & 1;
//         // For the first iteration, the cur_bit is the
//         // least significant bit and therefore we place
//         // that bit at index 7 of the array (rightmost bit)
//         bits[7 - i] = cur_bit;
//     }
//     bits
// }

pub fn to_3_ascii_chars(str: &str) -> Result<[AsciiChar; 3], Error> {
    let ascii_string = AsciiString::from_str(str)
        .map_err(|err| Error::BinaryCodec(InvalidData(format!("Not valid ascii string: {}", err))))?;
    let ascii_chars = <&[AsciiChar; 3]>::try_from(ascii_string.as_slice())
        .map_err(|err| InvalidData(format!("String does not have length 3: {}", err)))?;
    Ok(*ascii_chars)
}