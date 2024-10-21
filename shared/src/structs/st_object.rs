use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StObject {
    pub ip: String,
    pub port: String,
}

impl StObject {
    pub fn from_parser(&self) -> String {
        format!("{}:{}", self.ip, self.port)
    }
}