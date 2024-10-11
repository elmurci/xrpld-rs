use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeysError {
    #[error("Invalid Secret Key in hex")]
    InvalidSecretKeyHex(),

    #[error("Invalid Secret Key")]
    InvalidSecretKey(),
}