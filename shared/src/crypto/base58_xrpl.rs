//! Base58 encode/decode for XRP Ledger, with checks and prefixes.

use crate::enums::base58::Version;

/// Encode given input with prefix to base58-check based on Ripple alphabet.
pub fn encode<I: AsRef<[u8]>>(version: Version, input: I) -> String {
    bs58::encode(input)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .with_check_version(version.value())
        .into_string()
}

/// Decode given input in base58-check based on Ripple alphabet.
pub fn decode<I: AsRef<[u8]>>(version: Version, input: I) -> bs58::decode::Result<Vec<u8>> {
    bs58::decode(input)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .with_check(Some(version.value()))
        .into_vec()
        .map(|mut vec| {
            let _ = vec.remove(0);
            vec
        })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_public() {
        let data = "n9KAa2zVWjPHgfzsE3iZ8HAbzJtPrnoh4H2M2HgE7dfqtvyEb1KJ";

        let bytes = decode(Version::NodePublic, &data);
        assert!(bytes.is_ok());

        let bytes = bytes.unwrap();
        let value = encode(Version::NodePublic, &bytes);
        assert_eq!(value, data);
    }
}
