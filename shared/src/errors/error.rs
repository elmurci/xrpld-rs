use crate::errors::binary_codec::BinaryCodecError;
use super::{config::ConfigError, crypto::KeysError, network::{ConnectError, HandshakeError, PeerError, SendRecvError}};

pub type Result<T> = core::result::Result<T, Error>;
// pub type Error = Box<dyn std::error::Error>; // For early dev.

#[derive(Debug)]
pub enum Error {
    BinaryCodec(BinaryCodecError),
    Config(ConfigError),
    Peer(PeerError),
    Handshake(HandshakeError),
    SendRecv(SendRecvError),
    Connect(ConnectError),
    Keys(KeysError),
}

impl From<BinaryCodecError> for Error {
    fn from(e: BinaryCodecError) -> Self {
        Error::BinaryCodec(e)
    }
}

impl From<PeerError> for Error {
    fn from(e: PeerError) -> Self {
        Error::Peer(e)
    }
}

impl From<ConfigError> for Error {
    fn from(e: ConfigError) -> Self {
        Error::Config(e)
    }
}

impl From<HandshakeError> for Error {
    fn from(e: HandshakeError) -> Self {
        Error::Handshake(e)
    }
}

impl From<SendRecvError> for Error {
    fn from(e: SendRecvError) -> Self {
        Error::SendRecv(e)
    }
}

impl From<ConnectError> for Error {
    fn from(e: ConnectError) -> Self {
        Error::Connect(e)
    }
}

impl From<KeysError> for Error {
    fn from(e: KeysError) -> Self {
        Error::Keys(e)
    }
}