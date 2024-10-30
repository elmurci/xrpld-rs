use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use base64::Engine;
use shared::enums::base58::Version;
use shared::enums::utils::{LogType, Process};
use shared::errors::network::{ConnectError, HandshakeError, SendRecvError};
use shared::structs::field_info::field_info_lookup;
use shared::structs::validator_message::ValidatorBlob;
use shared::structs::secp256k1_keys::Secp256k1Keys;
use std::sync::Arc;
use base64::prelude::BASE64_STANDARD;
use shared::crypto::secp256k1::ecdsa::Signature;
use proto::{EncodeDecode, Message as ProtoMessage, PingPong};
use proto::Message::{PingPong as PingPongMsg, Endpoints, Validation, Validatorlistcollection, Manifests, StatusChange, GetObject, GetLedger, Transaction, ProposeLedger, HaveSet};
use bytes::{Buf, BufMut, BytesMut};
use shared::crypto::secp256k1::{Message, PublicKey};
use shared::crypto::sha2::{Digest, Sha512};
use openssl::ssl::{SslRef, SslVerifyMode};
use shared::xrpl::deserializer::Deserializer as XrplDeserializer;
use serde::{de, Deserialize, Deserializer, Serialize};
use shared::enums::network::NetworkId;
use shared::utils::logger::log;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use openssl::ssl::{SslMethod, SslConnector};
use tokio_openssl::SslStream;
use tokio::net::TcpStream;
use super::PeerTable;

const LOG_KEY:&str = "Peer";

#[derive(Debug)]
struct PeerPing {
    pub seq: Option<u32>,
    pub no_ping: u8,
}

/// Single connection to ripple node.
#[derive(Debug)]
pub struct Peer {
    // node_key as ref?
    node_key: Arc<Secp256k1Keys>,
    peer_table: Arc<PeerTable>,
    network_id: Arc<NetworkId>,
    peer_addr: SocketAddr,
    ping_data: Mutex<PeerPing>,
    stream: Mutex<SslStream<tokio::net::TcpStream>>,
    // TODO: add last message timestamp
}

impl Peer {

    /// Create [`Peer`][Peer] from given [`SocketAddr`][std::net::SocketAddr].
    pub async fn from_addr(
        addr: SocketAddr,
        node_key: Arc<Secp256k1Keys>,
        peer_table: Arc<PeerTable>,
        network_id: Arc<NetworkId>,
        ssl_verify: bool,
    ) -> Result<Arc<Peer>, ConnectError> {
        
        let mut connector_builder = SslConnector::builder(SslMethod::tls()).unwrap();
        if !ssl_verify {
            connector_builder.set_verify(SslVerifyMode::NONE);
        }

        let connector = connector_builder.build();
        
        let tcp_stream = TcpStream::connect(addr).await;

        if tcp_stream.is_err() {

            let err = tcp_stream.unwrap_err();
            log(Process::Networking, LogType::Warn, &LOG_KEY, format!("Could not connect with peer: {}: {}", addr, err));
            return Err(ConnectError::Io(err));
        }
        
        let ssl_stream = connector.configure().unwrap().into_ssl("localhost").unwrap();
        let mut stream = SslStream::new(ssl_stream, tcp_stream.unwrap()).unwrap();
        let _ = SslStream::connect(Pin::<_>::new(&mut stream)).await;
        
        log(Process::Networking, LogType::Debug, &LOG_KEY, format!("Network:Peer Connected to server {:?}", addr));

        Ok(Arc::new(Peer {
            node_key,
            peer_table,
            network_id,
            peer_addr: addr,
            ping_data: Mutex::new(PeerPing {
                no_ping: 0,
                seq: None,
            }),
            stream: Mutex::new(stream),
        }))
    }

    /// Outgoing handshake process.
    pub async fn connect(self: &Arc<Self>) -> Result<(), HandshakeError> {
        log(Process::Networking, LogType::Debug, &LOG_KEY, format!("Starting handshake with: {}", self.peer_addr));
        self.handshake_send_request().await?;
        self.handshake_read_response().await?;
        Arc::clone(&self).spawn_read_messages();
        // Arc::clone(&self).spawn_ping_loop();
        Ok(())
    }

    /// Send handshake request.
    async fn handshake_send_request(&self) -> Result<(), HandshakeError> {
        let mut stream = self.stream.lock().await;
        // TODO: get version from package
        // TODO: crawl private/public
        let mut content = format!(
            "\
            GET / HTTP/1.1\r\n\
            User-Agent: xrpld-0.0.1\r\n\
            Connection: Upgrade\r\n\
            Upgrade: XRPL/2.2\r\n\
            Connect-As: Peer\r\n\
            Network-ID: {}\r\n\
            Network-Time: {}\r\n\
            Public-Key: {}\r\n\
            Session-Signature: {}\r\n\
            Crawl: private\r\n",
            self.network_id.value(),
            network_time(),
            self.node_key.get_public_key_bs58(),
            self.handshake_create_signature(stream.ssl()).await?
        );

        let remote = self.peer_addr.ip();
        if remote.is_global() {
            content += &format!("Remote-IP: {}\r\n", remote);
        }

        content += "\r\n";

        let fut = stream.write_all(content.as_bytes());
        fut.await.map_err(HandshakeError::Io)
    }

    /// Read peer handshake response for our handshake request.
    async fn handshake_read_response(&self) -> Result<(), HandshakeError> {
        let mut buf = BytesMut::new();
        
        let mut stream = self.stream.lock().await;

        let code = loop {
            let fut = stream.read_buf(&mut buf);

            if fut.await.map_err(HandshakeError::Io)? == 0 {
                let error = io::Error::new(io::ErrorKind::UnexpectedEof, "early eof");
                return Err(HandshakeError::Io(error));
            }

            let mut headers = [httparse::EMPTY_HEADER; 32];

            let mut resp = httparse::Response::new(&mut headers);
            let status = resp.parse(&buf).expect("response parse success");

            if status.is_partial() {
                continue;
            }

            log(Process::Networking, LogType::Debug, &LOG_KEY, format!("Handshake response status {:?}", status));

            let find_header = |name| {
                resp.headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case(name))
                    .map(|h| String::from_utf8_lossy(h.value))
            };

            let get_header =
                |name| find_header(name).ok_or_else(|| HandshakeError::MissingHeader(name.to_string()));

            let code = resp.code.unwrap();

            log(Process::Networking, LogType::Debug, &LOG_KEY, format!("Handshake response: {} - {:#?}", code, resp.reason));

            if code == 101 {
                // self.peer_user_agent = Some(get_header!("Server").to_string());
                let _ = get_header("Server")?;

                if get_header("Connection")? != "Upgrade" {
                    let reason = r#"expect "Upgrade""#.to_owned();
                    return Err(HandshakeError::InvalidHeader("Connection".to_string(), reason));
                }

                let upgrade_header = get_header("Upgrade")?;

                if upgrade_header != "XRPL/2.1" && upgrade_header != "XRPL/2.2" {
                    let reason = r#"Only "XRPL/2.1" or "XRPL/2.2" supported"#.to_owned();
                    return Err(HandshakeError::InvalidHeader("Upgrade".to_string(), reason));
                }

                if !get_header("Connect-As")?.eq_ignore_ascii_case("peer") {
                    let reason = r#"Only "Peer" supported right now"#.to_owned();
                    return Err(HandshakeError::InvalidHeader("Connect-As".to_string(), reason));
                }

                if let Some(value) = find_header("Remote-IP") {
                    let parsed = value.parse::<IpAddr>();
                    let _ip = parsed.map_err(|e| HandshakeError::InvalidRemoteIp(e.to_string()))?;
                    
                    // TODO
                    // if ip.is_global() && `public ip specified in config` && ip != `specified global ip from config` {
                    //     let reason = format!("{} instead of {}", ip, ?);
                    //     return Err(HandshakeError::InvalidRemoteIp(reason));
                    // }
                }

                if let Some(value) = find_header("Local-IP") {
                    let parsed = value.parse::<IpAddr>();
                    let ip = parsed.map_err(|e| HandshakeError::InvalidLocalIp(e.to_string()))?;

                    let remote = self.peer_addr.ip();
                    if remote.is_global() && remote != ip {
                        let reason = format!("{} instead of {}", ip, remote);
                        return Err(HandshakeError::InvalidLocalIp(reason));
                    }
                }

                let network_id = match find_header("Network-Id") {
                    Some(value) => value
                        .parse::<NetworkId>()
                        .map_err(|e| HandshakeError::InvalidNetworkId(e.to_string()))?,
                    None => NetworkId::Main,
                };
                if network_id.value() != self.network_id.value() {
                    let expected = self.network_id.value();
                    let received = network_id.value();
                    let reason = format!("{} instead of {}", received, expected);
                    return Err(HandshakeError::InvalidNetworkId(reason));
                }

                if let Some(value) = find_header("Network-Time") {
                    let peer_time = value
                        .parse::<u64>()
                        .map_err(|e| HandshakeError::InvalidNetworkTime(e.to_string()))?;
                    let local_time = network_time();

                    use std::cmp::{max, min};
                    let diff = max(peer_time, local_time) - min(peer_time, local_time);
                    if diff > 20 {
                        let reason = "Peer clock is too far off".to_owned();
                        return Err(HandshakeError::InvalidNetworkTime(reason));
                    }
                }

                let public_key = get_header("Public-Key")?;
                let sig = get_header("Session-Signature")?;

                let _verify_signature = self.handshake_verify_signature(sig, public_key.clone(), stream.ssl()).await?;
                
                log(Process::Networking, LogType::Debug, &LOG_KEY, format!("Peer Public Key: {}", public_key.to_string()));

                buf.advance(status.unwrap());
            } else {
                let body_size = match find_header("Content-Length") {
                    Some(header) => Some(header.parse::<usize>().map_err(|error| {
                        HandshakeError::InvalidHeader("Content-Length".to_string(), error.to_string())
                    })?),
                    None => None,
                };

                buf.advance(status.unwrap());

                // TODO: parse on the fly for chunked-encoding
                // TODO: read exact content-length
                loop {
                    let fut = stream.read_buf(&mut buf);
                    if fut.await.map_err(HandshakeError::Io)? == 0 {
                        break;
                    }
                }

                // chunked-encoding...
                if body_size.is_none() {
                    let mut buf2 = BytesMut::with_capacity(buf.len());
                    while !buf.is_empty() {
                        let status = match httparse::parse_chunk_size(&buf) {
                            Ok(status) => status,
                            Err(_) => return Err(HandshakeError::InvalidChunkedBody(buf)),
                        };

                        if status.is_partial() {
                            return Err(HandshakeError::InvalidChunkedBody(buf));
                        }

                        let (start, size) = status.unwrap();
                        if size == 0 {
                            break;
                        }

                        let end = start + size as usize;
                        buf2.extend_from_slice(&buf.chunk()[start..end]);
                        buf.advance(end);
                    }

                    buf = buf2;
                }
            }

            break code;
        };

        match code {
            101 => {
                if !buf.is_empty() {
                    let error_str = String::from("Read more data than expected on successful handshake..");
                    log(Process::Networking, LogType::Debug, &LOG_KEY, error_str.clone());
                    return Err(HandshakeError::BadRequest(
                        error_str,
                    ));
                }

                Ok(())
            }
            400 => Err(HandshakeError::BadRequest(
                String::from_utf8_lossy(&buf).trim().to_string(),
            )),
            503 => match serde_json::from_slice::<PeerUnavailableBody>(&buf) {
                Ok(body) => Err(HandshakeError::Unavailable(body.ips)),
                Err(_) => Err(HandshakeError::UnavailableBadBody(
                    String::from_utf8_lossy(&buf).to_string(),
                )),
            },
            _ => Err(HandshakeError::UnexpectedHttpStatus(
                code,
                String::from_utf8_lossy(&buf).trim().to_string(),
            )),
        }
    }

    /// Create message for create/verify signature.
    async fn handshake_mkshared(&self, ssl: &SslRef) -> Result<Message, HandshakeError> {
        let mut buf = Vec::<u8>::with_capacity(1024);
        buf.resize(buf.capacity(), 0);

        let mut size = ssl.finished(&mut buf[..]);
        if size > buf.len() {
            buf.resize(size, 0);
            size = ssl.finished(&mut buf[..]);
        }
        let cookie1 = Sha512::digest(&buf[..size]);

        let mut size = ssl.peer_finished(&mut buf[..]);
        if size > buf.len() {
            buf.resize(size, 0);
            size = ssl.peer_finished(&mut buf[..]);
        }
        let cookie2 = Sha512::digest(&buf[..size]);

        let mix = cookie1
            .iter()
            .zip(cookie2.iter())
            .map(|(a, b)| a ^ b)
            .collect::<Vec<u8>>();
        let hash = Sha512::digest(&mix[..]);

        let pac = Message::from_digest_slice(&hash[0..32]).map_err(|_| HandshakeError::InvalidMessage());

        pac
    }

    /// Create base64 encoded signature for handshake with node keys ([`Secp256k1Keys`][crypto::Secp256k1Keys]).
    async fn handshake_create_signature(&self, ssl: &SslRef) -> Result<String, HandshakeError> {
        let msg = self.handshake_mkshared(ssl).await?;
        let sig = self.node_key.sign(&msg).serialize_der();
        Ok(BASE64_STANDARD.encode(&sig))
    }

    /// Verify base64 encoded signature for handshake with base58 encoded Public Key.
    /// Return [`PublicKey`][crypto::secp256k1::PublicKey] on success.
    async fn handshake_verify_signature(
        &self,
        sig_header: Cow<'_, str>,
        pk_header: Cow<'_, str>,
        ssl: &SslRef,
    ) -> Result<PublicKey, HandshakeError> {
        let pk_bytes = shared::crypto::base58_xrpl::decode(Version::NodePublic, &*pk_header)
            .map_err(|_| HandshakeError::InvalidPublicKey(pk_header.to_string()))?;
        let pk = PublicKey::from_slice(&pk_bytes)
            .map_err(|_| HandshakeError::InvalidPublicKey(pk_header.to_string()))?;

        let sig_bytes = BASE64_STANDARD.decode(&*sig_header)
            .map_err(|_| HandshakeError::InvalidSignature(sig_header.to_string()))?;
        let sig = Signature::from_der(&sig_bytes)
            .map_err(|_| HandshakeError::InvalidSignature(sig_header.to_string()))?;

        let msg = self.handshake_mkshared(ssl).await?;

        match shared::crypto::SECP256K1.verify_ecdsa(&msg, &sig, &pk) {
            Ok(_) => Ok(pk),
            Err(_) => Err(HandshakeError::SignatureVerificationFailed()),
        }
    }

    // Send ping message in loop for checking that peer is alive.
    fn spawn_ping_loop(self: Arc<Peer>) {
        let _join_handle = tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(8);
            loop {
                tokio::time::sleep(interval).await;

                let mut ping = self.ping_data.lock().await;

                ping.no_ping += 1;
                if ping.no_ping > 10 {
                    // TODO: shutdown
                    log(Process::Networking, LogType::Warn, &LOG_KEY, format!("No ping response for more than 10 seconds, shutdown: {}", self.peer_addr));
                }

                if ping.seq.is_none() {
                    ping.seq = Some(rand::random::<u32>());

                    let msg = PingPong::build_ping(ping.seq);
                    Arc::clone(&self).spawn_send_message(ProtoMessage::PingPong(msg));
                }
            }
        });
    }

    ///  Send message to peer.
    pub async fn send_message(&self, msg: ProtoMessage) -> Result<(), SendRecvError> {
        log(Process::Networking, LogType::Debug, &LOG_KEY, format!("Send message to peer: {:?}", msg));
        let size = msg.encoded_len();
        let mut bytes = BytesMut::with_capacity(size + 4);
        // Uncompressed value, the top six bits of the first byte are 0.
        bytes.put_u32((size - 2) as u32); // 2 is message type
        msg.encode(&mut bytes).map_err(SendRecvError::Encode)?;

        let mut stream = self.stream.lock().await;
        let _ = stream.write_all(&bytes).await.map_err(SendRecvError::Io);
        stream.flush().await.map_err(SendRecvError::Io)
    }

    /// Send message to peer in new asynchronous task.
    pub fn spawn_send_message(self: Arc<Self>, msg: ProtoMessage) {
        let _join_handle = tokio::spawn(async move {
            // TODO: shutdown
            if let Err(error) = self.send_message(msg).await {
                log(Process::Networking, LogType::Error, &LOG_KEY, format!("Peer send error: {}", error));
            }
        });
    }

    // Read message from peer.
    fn spawn_read_messages(self: Arc<Peer>) {
        let _join_handle = tokio::spawn(async move {

            loop {
            
                let msg: ProtoMessage = match self.read_message().await {
                    Ok(msg) => {
                        msg
                    },
                    Err(error) => {
                        log(Process::Networking, LogType::Error, &LOG_KEY, format!("Error: Peer spawn_read_messages: {}", error));
                        // log::debug!("{:?}", hex::encode(&read_buf.chunk()));
                        break;
                    }
                };

                let result = match msg {
                    PingPongMsg(msg) => {
                        if msg.is_ping() {
                            self.on_message_ping(msg).await
                        } else {
                            self.on_message_pong(msg).await
                        }
                    }
                    Manifests(msg) => {
                        log(Process::Networking, LogType::Info, &LOG_KEY, format!("Peer Manifests message received. {} received", msg.list.len()));
                        // for item in &msg.list {
                        //     // log::debug!("Network:Peer Peer Manifest");
                        //     // BASE64_STANDARD.encode(&item.stobject)
                        // }
                        // TODO
                        Ok(())
                    }
                    GetLedger(msg) => {
                        log(Process::Networking, LogType::Info, &LOG_KEY, format!("GetLedger message received for {:?} - {:?}", hex::encode(&msg.ledger_hash.unwrap()).to_uppercase(), &msg.ledger_seq.unwrap()));
                        // TODO
                        Ok(())
                    }
                    StatusChange(msg) => {
                        log(Process::Networking, LogType::Info, &LOG_KEY, format!("Status Change message received, new ledger sequence is {:?}", msg.ledger_seq.unwrap()));
                        // TODO
                        Ok(())
                    }
                    Validatorlistcollection(msg) => {
                        log(Process::Networking, LogType::Info, &LOG_KEY, format!("Validator List Collection received: {}", msg.blobs.len()));
                        for blob in &msg.blobs {
                            // First, validate the signature
                            // Check expiration
                            // process validators
                            let validators = serde_json::from_slice::<ValidatorBlob>(&BASE64_STANDARD.decode(&blob.blob).unwrap()).unwrap();
                            for validator in &validators.validators {
                                log(Process::Networking, LogType::Debug, &LOG_KEY, format!("Validator List Collection message received - Validator: {}", validator.validation_public_key));
                            }
                        }
                        // TODO
                        Ok(())
                    }
                    GetObject(msg) => {
                        log(Process::Networking, LogType::Info, &LOG_KEY, format!("Get Object by hash message received. {:?} ({})", msg.r#type(), hex::encode(msg.ledger_hash.unwrap()).to_uppercase()));
                        // TODO
                        Ok(())
                    }
                    Validation(msg) => {
                        let deserializer = &mut XrplDeserializer::new(
                            msg.validation.clone(),
                            field_info_lookup().clone(),
                        );
                        let msg = deserializer.deserialize_object();
                        log(Process::Networking, LogType::Info, &LOG_KEY, format!("Validation message received from {:?}", msg.unwrap().unwrap_object().consensus_hash));
                        // TODO
                        Ok(())
                    }
                    Transaction(msg) => {
                        // let tx_hex = hex::encode(&msg.raw_transaction).to_uppercase();
                        let deserializer = &mut XrplDeserializer::new(
                            msg.raw_transaction.clone(),
                            field_info_lookup().clone(), // TODO: review this
                        );
                        let data = deserializer.deserialize_object().unwrap();
                        log(Process::Networking, LogType::Info, &LOG_KEY, format!("Transaction message received. signing_pub_key: {}", data.clone().unwrap_object().signing_pub_key.unwrap()));
                        log(Process::Networking, LogType::Debug, &LOG_KEY, format!("Transaction message received: {:?}", data));
                        // TODO
                        Ok(())
                    }
                    ProposeLedger(msg) => {
                        log(Process::Networking, LogType::Info, &LOG_KEY, format!("ProposeLedger message received from {}", hex::encode(&msg.node_pub_key).to_uppercase()));
                        // TODO
                        Ok(())
                    }
                    HaveSet(msg) => {
                        log(Process::Networking, LogType::Info, &LOG_KEY, format!("HaveSet message received. (Hash: {})", hex::encode(msg.hash).to_uppercase()));
                        // TODO
                        Ok(())
                    }
                    Endpoints(msg) => self.on_message_endpoints(msg).await,
                    _ => {
                        // log::error!("Network:Peer Unhandled type. {:?}", msg);
                        Ok(())
                    },
                };
                if let Err(error) = result {
                    log(Process::Networking, LogType::Error, &LOG_KEY, format!("Peer message handler error: {}", error));
                    break;
                }
            }
        });
    }

    async fn read_message(
        self: &Arc<Self>,
    ) -> Result<proto::Message, SendRecvError> {

        loop {
            
            // Message Header
            // --------------
            //
            // The header is a variable-sized structure that contains information about
            // the type of the message and the length and encoding of the payload.
        
            // The first bit determines whether a message is compressed or uncompressed;
            // for compressed messages, the next three bits identify the compression
            // algorithm.
        
            // All multi-byte values are represented in big endian.
        
            // For uncompressed messages (6 bytes), numbering bits from left to right:
        
            //     - The first 6 bits are set to 0.
            //     - The next 26 bits represent the payload size.
            //     - The remaining 16 bits represent the message type.
        
            // For compressed messages (10 bytes), numbering bits from left to right:
        
            //     - The first 32 bits, together, represent the compression algorithm
            //       and payload size:
            //         - The first bit is set to 1 to indicate the message is compressed.
            //         - The next 3 bits indicate the compression algorithm.
            //         - The next 2 bits are reserved at this time and set to 0.
            //         - The remaining 26 bits represent the payload size.
            //     - The next 16 bits represent the message type.
            //     - The remaining 32 bits are the uncompressed message size.
        
            // The maximum size of a message at this time is 64 MB. Messages larger than
            // this will be dropped and the recipient may, at its option, sever the link.

            // 
            let mut payload_size_buf = [0u8; 4];
            let mut stream = self.stream.lock().await;

            if let Err(error) = stream.read_exact(&mut payload_size_buf).await {
                return Err(SendRecvError::Io(error));
            }

            const VERSION_MASK: u8 = 0xFC;

            // For uncompressed messages the first 6 bits of the first byte are should be set to 0
            // TODO: Handle compressed messages
            if payload_size_buf[0] & VERSION_MASK != 0 {
                // Handle unknown version header
                let error = SendRecvError::UnknowVersionHeader(payload_size_buf[0]);
                return Err(error);
            }

            let payload_size = u32::from_be_bytes(payload_size_buf) as usize;

            // Limit is 64 MB
            if payload_size > 64 * 1024 * 1024 {
                let error = SendRecvError::PayloadTooBig(payload_size);
                return Err(error);
            }

            // Calculate the total message size (payload + header)
            let msg_size = payload_size + 2;
   
            // Log the received payload size and message type
            let message_type = ((payload_size_buf[0] as u16) << 8) + (payload_size_buf[1] as u16);

            // Allocate a buffer large enough to hold the entire message
            let mut buffer = vec![0u8; msg_size];

            // Read the message from the stream into the buffer
            if let Err(error) = stream.read_exact(&mut buffer).await {
                return Err(SendRecvError::Io(error));
            }

            if ProtoMessage::is_valid_type(&buffer.as_slice()) {
                let msg = proto::Message::decode(&mut buffer.as_slice());
                return Ok(msg.map_err(SendRecvError::Decode)?);
            }    
  
        }

    }

    async fn on_message_ping(
        self: &Arc<Self>,
        msg: PingPong,
    ) -> Result<(), std::convert::Infallible> {
        log(Process::Networking, LogType::Debug, &LOG_KEY, format!("Received ping message: {:?}", msg));
        let msg = PingPong::build_pong(msg.sequence());
        Arc::clone(self).spawn_send_message(ProtoMessage::PingPong(msg));
        Ok(())
    }

    async fn on_message_pong(
        self: &Arc<Self>,
        msg: PingPong,
    ) -> Result<(), std::convert::Infallible> {
        let mut ping = self.ping_data.lock().await;
        if ping.seq == msg.sequence() {
            ping.seq = None;
            ping.no_ping = 0;
        }

        Ok(())
    }

    async fn on_message_endpoints(
        self: &Arc<Self>,
        msg: proto::Endpoints,
    ) -> Result<(), std::convert::Infallible> {
        let mut endpoints = msg.endpoints;
        for ep in endpoints.iter_mut().filter(|ep| ep.hops == 0) {
            ep.addr = self.peer_addr;
        }
        self.peer_table.on_endpoints(endpoints).await;
        Ok(())
    }
}

/// If peer response with 503 (unavailable) on handshake, in body we receive
#[derive(Debug, Deserialize, Serialize)]
struct PeerUnavailableBody {
    #[serde(
        rename = "peer-ips",
        deserialize_with = "PeerUnavailableBody::ips_deserialize"
    )]
    pub ips: Vec<SocketAddr>,
}

impl PeerUnavailableBody {
    fn ips_deserialize<'de, D>(deserializer: D) -> Result<Vec<SocketAddr>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut raw: Vec<&str> = Deserialize::deserialize(deserializer)?;

        let mut addrs = Vec::with_capacity(raw.len());
        for data in raw.iter_mut() {
            match SocketAddr::from_str(data) {
                Ok(addr) => addrs.push(addr),
                Err(error) => {
                    return Err(de::Error::invalid_value(
                        de::Unexpected::Other(&format!("{}", error)),
                        &"an Array of SocketAddr",
                    ))
                }
            }
        }
        Ok(addrs)
    }
}

/// Get Ripple time ([docs](https://xrpl.org/basic-data-types.html#specifying-time)).
fn network_time() -> u64 {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("You came from the past")
        .checked_sub(Duration::from_secs(946_684_800)) // 10_957 (days) * 86_400 (seconds)
        .expect("You came from the past")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_ips_decode_encode() {
        let data = r#"{"peer-ips":["54.68.219.39:51235","54.187.191.179:51235"]}"#;

        let body = serde_json::from_str::<PeerUnavailableBody>(data);
        assert!(body.is_ok());
        let body = body.unwrap();

        let value = serde_json::to_string(&body);
        assert!(value.is_ok());
        assert_eq!(value.unwrap(), data);
    }
}