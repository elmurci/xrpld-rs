use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::DisplayFromStr;

use crate::enums::network::NetworkId;

#[serde_as]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct XrpldConfig {
    pub ips: Vec<IpItem>,
    #[serde_as(as = "DisplayFromStr")]
    pub network_id: NetworkId,
    pub ssl_verify: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]pub struct IpItem {
    pub ip: String,
    pub port: String,
}
