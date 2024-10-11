use std::io;
use bytes::BytesMut;
use proto::{DecodeError, EncodeError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PeerError {
    #[error("Peer Connect error: {0}")]
    Connect(String),

    #[error("Peer handshake error: {0}")]
    Handshake(HandshakeError),

    #[error("Peer Unavailable, peers")]
    Unavailable(Vec<std::net::SocketAddr>),
}

#[derive(Error, Debug)]
pub enum HandshakeError {
    #[error("Handshake io error: {0}")]
    Io(io::Error),

    #[error("Handshake missing header: {0}")]
    MissingHeader(String),

    #[error("Handshake missing header error. name: {0}, reason: {1}")]
    InvalidHeader(String, String),

    #[error("Handshake Invalid network id: {0}")]
    InvalidNetworkId(String),

    #[error("Handshake Invalid network time: {0}")]
    InvalidNetworkTime(String),

    #[error("Handshake Invalid remote ip: {0}")]
    InvalidRemoteIp(String),

    #[error("Handshake Invalid local ip: {0}")]
    InvalidLocalIp(String),

    #[error("Handshake Invalid message")]
    InvalidMessage(),

    #[error("Handshake Invalid Public Key: {0}")]
    InvalidPublicKey(String),

    #[error("Handshake Signature: {0}")]
    InvalidSignature(String),

    #[error("Handshake Signature verification failed")]
    SignatureVerificationFailed(),

    #[error("Handshake Invalid chunked body")]
    InvalidChunkedBody(BytesMut),

    #[error("Handshake Bad request: {0}")]
    BadRequest(String),

    #[error("Handshake Unavailable peers")]
    Unavailable(Vec<std::net::SocketAddr>),

    #[error("Handshake Unavailable, can't parse body: {0}")]
    UnavailableBadBody(String),

    #[error("Handshake Unexpected HTTP status: {0}, body: {1}")]
    UnexpectedHttpStatus(u16, String),
}

#[derive(Error, Debug)]
pub enum SendRecvError {
    #[error("SendReceive {0}")]
    Io(io::Error),

    #[error("SendReceive Unknow version header: {0}")]
    UnknowVersionHeader(u8),

    #[error("SendReceive Message payload too big: {0}")]
    PayloadTooBig(usize),

    #[error("SendReceive Message encode error: {0}")]
    Encode(EncodeError),

    #[error("SendReceive Message decode error: {0}")]
    Decode(DecodeError),
}

#[derive(Error, Debug)]
pub enum ConnectError {
    #[error("ConnectError: {0}")]
    Io(io::Error),
    #[error("ConnectError: {0}")]
    Tls(native_tls::Error),
}

