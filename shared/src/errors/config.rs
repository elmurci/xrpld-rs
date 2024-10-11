use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid value for the port field `{0}`")]
    Port(String),
}