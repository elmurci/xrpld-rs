use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::DisplayFromStr;

use crate::enums::network::NetworkId;

use super::field_info::FieldInfo;

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct XrpldConfig {
    pub ips: Vec<IpItem>,
    #[serde_as(as = "DisplayFromStr")]
    pub network_id: NetworkId,
    pub ssl_verify: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IpItem {
    pub ip: String,
    pub port: String,
}

impl IpItem {
    pub fn to_socket(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct XrplServerDefinitions {
    #[serde(alias="FIELDS")]
    pub fields: HashMap<String, FieldInfo>,
    #[serde(alias="LEDGER_ENTRY_TYPES")]
    pub ledger_entry_types: HashMap<String, i16>,
    #[serde(alias="TRANSACTION_RESULTS")]
    pub transaction_results: HashMap<String, i16>,
    #[serde(alias="TRANSACTIN_TYPES")]
    pub transaction_types: HashMap<String, i16>,
    #[serde(alias="TYPES")]
    pub types: HashMap<String,i16>,
    pub hash: String,
    pub status: String,
}