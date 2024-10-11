use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValidatorBlobInfo {
    pub blob: Vec<ValidatorBlob>,
    pub signature: Vec<u8>,
    pub manifest: Vec<u8>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValidatorBlob {
    pub sequence: u16,
    pub expiration: u32,
    pub validators: Vec<ValidatorInfo>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValidatorInfo {
    pub validation_public_key: String,
    pub manifest: String, // TODO: for now
}