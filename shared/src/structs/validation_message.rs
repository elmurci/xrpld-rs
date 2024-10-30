use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ValidationMessage {
    pub flags: u32,
    pub ledger_sequence: u32,
    pub signing_type: u32,
    pub cookie: u32,
    pub ledger_hash: String, // TODO: Blob?
    pub consensus_hash: String, // TODO: Blob?
    pub validated_hash: String, // TODO: Blob?
    pub signing_pub_key: String, // TODO: Blob?
    pub signature: String, // TODO: Blob?
}