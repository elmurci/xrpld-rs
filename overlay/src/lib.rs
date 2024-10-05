#![feature(ip)]
#![feature(read_buf)]

use quick_error::quick_error;
use shared::enums::network::NetworkId;
use shared::log;
use shared::structs::config::{IpItem, XrpldConfig};
use tokio::time::sleep;
use std::net::SocketAddr;
use std::sync::Arc;

use shared::crypto::Secp256k1Keys;

pub use peer::Peer;
pub use peer_table::PeerTable;

mod peer;
mod peer_table;

/// Peers collection and communication through the XRPL protocol.
#[derive(Debug)]
pub struct Network {
    // peers: Vec<Peer>,
    node_key: Arc<Secp256k1Keys>,
    peer_table: Arc<PeerTable>,
    network_id: NetworkId,
    ips: Vec<IpItem>,
    ssl_verify: bool,
    // nodes_max: usize,
}

impl Network {
    /// Create new Network.
    pub fn new(config: XrpldConfig) -> Network {
        Network {
            // nodes_max: 1,
            // peers: vec![],
            node_key: Arc::new(Secp256k1Keys::random()),
            peer_table: Arc::new(PeerTable::default()),
            network_id: config.network_id,
            ips: config.ips,
            ssl_verify: config.ssl_verify.unwrap_or(true),
            // nodes_max: 2, // TODO: fix
        }
    }

    /// Start network. Resolve nodes addrs, connect and communicate.
    /// 1. Setup: Set IP Limit, Set Public IP, [crawl] section config, vlEnabled, network_id
    /// 2. TODO...
    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {

        use std::time::Duration;
        
        loop {
            let _ = self.update().await;
            sleep(Duration::from_millis(2000)).await;
        }

    }

    pub async fn update(&mut self) -> Result<(), Box<dyn std::error::Error>> {

        self.peer_table.load_peer_addrs(
            if self.ips.is_empty() {
                None
            } else {
                Some(self.ips.to_vec())
            }
        ).await;

        let peer = loop {
            let addr = match self.peer_table.get_peer_address().await {
                Some(addr) => addr,
                None => break None,
            };

            match self.connect_to(addr, self.network_id.clone(), self.ssl_verify).await {
                Ok(peer) => break Some(peer),
                Err(PeerError::Connect(error)) => {
                    log::error!("Failed connect to peer {}: {}", addr, error)
                }
                Err(PeerError::Handshake(error)) => {
                    log::error!("Failed handshake with peer {}: {}", addr, error);
                }
                Err(PeerError::Unavailable(ips)) => {
                    log::error!("Peer unavailable, give {} peers", ips.len());
                    self.peer_table.on_redirect(ips).await;
                }
            }
            let connect = self.connect_to(addr, self.network_id.clone(), self.ssl_verify).await;

            log::debug!("Connect to peer {}: {:?}", addr, connect);
        };
        
        if peer.is_none() {
            log::warn!("No peers available.");
        }

        Ok(())
        
    }

    /// Connect to address.
    pub async fn connect_to(&self, addr: SocketAddr, network_id: NetworkId, ssl_verify: bool) -> Result<Arc<Peer>, PeerError> {
        match Peer::from_addr(
            addr,
            Arc::clone(&self.node_key),
            Arc::clone(&self.peer_table),
            network_id,
            ssl_verify
        )
        .await
        {
            Ok(peer) => match peer.connect().await {
                Ok(_) => Ok(peer),
                Err(peer::HandshakeError::Unavailable(ips)) => Err(PeerError::Unavailable(ips)),
                Err(error) => Err(PeerError::Handshake(error)),
            },
            Err(error) => Err(PeerError::Connect(error)),
        }
    }
}

quick_error! {
    /// Possible peer errors.
    #[derive(Debug)]
    pub enum PeerError {
        Connect(error: peer::ConnectError) {
            display("{}", error)
        }
        Handshake(error: peer::HandshakeError) {
            display("{}", error)
        }
        Unavailable(ips: Vec<SocketAddr>) {
            display("Unavailable, give peers: {:?}", ips)
        }
    }
}