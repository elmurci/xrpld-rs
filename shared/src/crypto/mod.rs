/// Crypto structs and functions used in ripple protocol.

// re-export internal
pub use secp256k1;
pub use sha2;

// re-export own
pub use secp256k1_keys::Secp256k1Keys;

mod secp256k1_keys;
pub mod base58_xrpl;

// static secp256k1 context
lazy_static! {
    /// Initialized Secp256k1 context with all capabilities
    pub static ref SECP256K1: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}
