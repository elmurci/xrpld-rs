use serde::{Deserialize, Serialize};

use crate::enums::{amount::Amount, primitive::{AccountId, Blob}};

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
// TODO: Revise structure, common fields? separate in structs
pub struct StObject {
    pub transaction_type: Option<String>, // TODO
    pub flags: Option<u32>,
    pub sequence: Option<u32>,
    pub last_ledger_sequence: Option<u32>,
    pub amount: Option<Amount>,
    pub fee: Option<Amount>,
    pub send_max: Option<Amount>,
    pub signing_pub_key: Option<Blob>,
    pub txt_signature: Option<Blob>,
    pub account: Option<AccountId>,
    pub destination: Option<AccountId>,
    pub paths: Option<Vec<u8>>, // TODO: Path
    pub memos: Option<Vec<u8>>, // TODO: Memo
}

impl StObject {
    pub fn from_parser(&self) -> String {
        format!("{:?}", self.transaction_type)
    }
}
