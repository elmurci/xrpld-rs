use shared::enums::network::NetworkId;
use shared::enums::utils::{LogType, Process};
use shared::errors::error::Error;
use shared::errors::network::{HandshakeError, PeerError};
use shared::utils::logger::log;
use shared::structs::config::{IpItem, XrpldConfig};
use shared::structs::secp256k1_keys::Secp256k1Keys;
use tokio::time::sleep;
use std::net::SocketAddr;
use std::sync::Arc;

const LOG_KEY:&str = "Network";

use crate::{Peer, PeerTable};

/// Peers collection and communication through the XRPL protocol.
#[derive(Debug)]
pub struct Network {
    // peers: Vec<Peer>,
    node_key: Arc<Secp256k1Keys>,
    peer_table: Arc<PeerTable>, // RwLock<PeerTable>
    network_id: Arc<NetworkId>,
    ips: Arc<Vec<IpItem>>,
    ssl_verify: bool,
    // nodes_max: usize,
}

impl Network {
    /// Create new Network.
    pub fn new(config: Arc<XrpldConfig>) -> Network {
        let ips = Arc::new(if config.ips.is_empty() {
            config.bootstrap_nodes.clone()
        } else {
            config.ips.clone()
        });
        Network {
            // nodes_max: 1,
            // peers: vec![],
            node_key: Arc::new(Secp256k1Keys::random()),
            peer_table: Arc::new(PeerTable::default()),
            network_id: Arc::new(config.network_id.clone()),
            ips,
            ssl_verify: config.ssl_verify.unwrap_or(true),
            // nodes_max: 2, // TODO: fix
        }
    }

    /// Start network. Resolve nodes addrs, connect and communicate.
    /// 1. Setup: Set IP Limit, Set Public IP, [crawl] section config, vlEnabled, network_id
    /// 2. TODO...
    pub async fn start(&mut self) -> Result<(), Error> {

        use std::time::Duration;

        self.peer_table.load_peer_addrs(self.ips.to_vec()).await?;
        
        loop {
            let _ = self.update().await?;
            sleep(Duration::from_millis(2000)).await;
        }

    }

    pub async fn update(&mut self) -> Result<(), Error> {

        let peer = loop {
            let addr = match self.peer_table.get_peer_address().await {
                Some(addr) => addr,
                None => break None,
            };
            log(Process::Networking, LogType::Debug, &LOG_KEY, format!("Connecting to peer {}...", addr));
            match self.connect_to(addr, self.network_id.clone(), self.ssl_verify).await {
                Ok(peer) => {
                    log(Process::Networking, LogType::Info, &LOG_KEY, format!("Connected successfully to peer {}...", addr));
                    break Some(peer)
                },
                Err(Error::Peer(PeerError::Connect(error))) => {
                    log(Process::Networking, LogType::Warn, &LOG_KEY, format!("Failed connect to peer {}: {}", addr, error));
                }
                Err(Error::Peer(PeerError::Handshake(error))) => {
                    log(Process::Networking, LogType::Warn, &LOG_KEY, format!("Failed handshake with peer {}: {}", addr, error));
                }
                Err(Error::Peer(PeerError::Unavailable(ips))) => {
                    log(Process::Networking, LogType::Warn, &LOG_KEY, format!("Peer unavailable, current peers: {}", ips.len()));
                    self.peer_table.on_redirect(ips).await;
                }
                _ => {}
            }
        };
        
        if peer.is_none() {
            log(Process::Networking, LogType::Info, &LOG_KEY, String::from("No new peers on peers table to connect"));
            // TODO: no successful peers, we should re try to connect to bootstrap nodes
        }

        Ok(())
        
    }

    /// Connect to address.
    pub async fn connect_to(&self, addr: SocketAddr, network_id: Arc<NetworkId>, ssl_verify: bool) -> Result<Arc<Peer>, Error> {
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
                Err(HandshakeError::Unavailable(ips)) => Err(Error::Peer(PeerError::Unavailable(ips))),
                Err(error) => Err(Error::Peer(PeerError::Handshake(error))),
            },
            Err(error) => Err(Error::Peer(PeerError::Connect(error.to_string()))),
        }
    }
}