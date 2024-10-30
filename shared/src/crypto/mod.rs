use once_cell::sync::Lazy;
/// Crypto structs and functions used in ripple protocol.

// re-export internal
pub use secp256k1;
pub use sha2;

pub mod base58_xrpl;

pub static SECP256K1: Lazy<secp256k1::Secp256k1<secp256k1::All>> = Lazy::new(|| {
    secp256k1::Secp256k1::new()
});
