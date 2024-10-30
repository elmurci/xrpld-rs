use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::enums::{amount::Amount, primitive::{AccountId, Blob, XrplType}};

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
// TODO: Revise structure, common fields? separate in structs
pub struct StObject {
    pub transaction_type: Option<String>, // TODO
    pub flags: Option<u32>,
    pub sequence: Option<u32>,
    pub last_ledger_sequence: Option<u32>,
    pub amount: Option<Amount>,
    pub fee: Option<String>,
    pub send_max: Option<String>,
    pub signing_pub_key: Option<String>,
    pub txt_signature: Option<String>,
    pub signature: Option<String>,
    pub consensus_hash: Option<String>,
    pub ledger_sequence: Option<u32>,
    pub signing_time: Option<u32>,
    pub account: Option<String>,
    pub destination: Option<String>,
    // pub paths: Option<Vec<u8>>, // TODO: Path
    // pub memos: Option<Vec<u8>>, // TODO: Memo
}

impl Default for StObject {
    fn default() -> StObject {
        StObject {
            transaction_type: None,
            flags: None,
            sequence: None,
            last_ledger_sequence: None,
            amount: None,
            fee: None,
            send_max: None,
            signing_pub_key: None,
            txt_signature: None,
            signature: None,
            consensus_hash: None,
            ledger_sequence: None,
            signing_time: None,
            account: None,
            destination: None,
        }
    }
}

impl From<HashMap<String, XrplType>> for StObject {
    fn from(item: HashMap<String, XrplType>) -> Self {
        // TODO: is there a better way than this?
        let flags = if item.get("Flags").is_some() {
            Some(item.get("Flags").unwrap().clone().unwrap_u32())
        } else {
            None
        };
        let signature = if item.get("Signature").is_some() {
            Some(item.get("Signature").unwrap().clone().unwrap_string())
        } else {
            None
        };
        let consensus_hash = if item.get("ConsensusHash").is_some() {
            Some(item.get("ConsensusHash").unwrap().clone().unwrap_string())
        } else {
            None
        };
        let ledger_sequence = if item.get("LedgerSequence").is_some() {
            Some(item.get("LedgerSequence").unwrap().clone().unwrap_u32())
        } else {
            None
        };
        let signing_time = if item.get("SigningTime").is_some() {
            Some(item.get("SigningTime").unwrap().clone().unwrap_u32())
        } else {
            None
        };
        let signing_pub_key = if item.get("SigningPubKey").is_some() {
            Some(item.get("SigningPubKey").unwrap().clone().unwrap_string())
        } else {
            None
        };
        StObject {
            transaction_type: None, // item.get("TransactionType").into(),
            flags,
            sequence: None,
            last_ledger_sequence: None,
            amount: None,
            fee: None,
            send_max: None, // item.get("SendMax").and_then(|v| v.into_amount()),
            signing_pub_key,
            txt_signature: None,
            signature,
            consensus_hash,
            account: None,
            destination: None,
            ledger_sequence,
            signing_time,
        }
    }
}