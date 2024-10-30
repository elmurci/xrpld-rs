use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use futures::future::join_all;
use rand::seq::SliceRandom;
use shared::enums::utils::{LogType, Process};
use shared::errors::config::ConfigError;
use shared::errors::error::Error;
use shared::utils::logger::log;
use shared::structs::config::IpItem;
use tokio::net::lookup_host;
use tokio::sync::Mutex;

const LOG_KEY:&str = "PeerTable";

#[derive(Debug)]
pub struct PeerTable {
    addrs: Mutex<Vec<SocketAddr>>,
}

impl Default for PeerTable {
    fn default() -> Self {
        PeerTable {
            addrs: Mutex::new(vec![]),
        }
    }
}

impl PeerTable {
    /// Add given addresses to table.
    async fn push_addrs(&self, mut other: Vec<SocketAddr>) {
        let mut addrs = self.addrs.lock().await;
        addrs.append(&mut other);
        addrs.dedup();
    }

    async fn get_ips_from_hostname(hostname: String) -> Vec<std::net::SocketAddr> {
        let ips = match lookup_host(&hostname).await {
            Ok(addrs) => addrs.collect(),
            Err(error) => {
                log(Process::Networking, LogType::Error, &LOG_KEY, format!("Failed resolve bootstrap node {}: {}", hostname, error));
                vec![]
            }
        };
        ips
    }

    /// Load peers addresses from config (or fallback to default) with resolving bootstrap nodes.
    pub async fn load_peer_addrs(&self, ips: Vec<IpItem>) -> Result<Vec<std::net::SocketAddr>, Error> {
        // TODO: support ips_fixed
        let addrs = {
            let mut socket_addrs:Vec<SocketAddr> = vec![];
            for ip_item in ips.iter() {
                let ip = IpAddr::from_str(&ip_item.ip);
                let port = ip_item.port.parse();
                if port.is_err() {
                    log(Process::Networking, LogType::Error, &LOG_KEY, format!("Failed to parse port {}", ip_item.port));
                    return Err(Error::Config(ConfigError::Port(ip_item.port.clone())));
                }
                let p = port.unwrap();
                if ip.is_err() {
                    let ips = Self::get_ips_from_hostname(ip_item.to_socket()).await;
                    for ip in ips {
                        socket_addrs.push(ip);
                    }
                } else {
                    socket_addrs.push(
                        SocketAddr::new(IpAddr::V4(
                            Ipv4Addr::from_str(&ip_item.ip).unwrap(), // TODO: remove unwrap
                        ), p)
                    );
                }
            }
            socket_addrs
        };
        self.push_addrs(addrs.clone()).await;
        Ok(addrs)
    }

    /// Resolve bootstrap nodes to addrs.
    // async fn get_bootstrap_peer_addrs() -> Vec<SocketAddr> {
    //     let nodes = Self::get_bootstrap_peer_nodes();

    //     let futs = nodes.iter().map(|node| async move {
    //         Self::get_ips_from_hostname(node.to_string()).await
    //     });
    //     let addrs = join_all(futs).await;
    //     addrs.into_iter().flatten().collect()
    // }

    /// Add peers endpoints on Endpoint message.
    pub async fn on_endpoints(&self, endpoints: Vec<proto::Endpoint>) {
        // TODO: Check endpoint with hops eq 1 (neighbor)
        let addrs = endpoints
            .iter()
            .filter_map(|ep| if ep.hops == 0 { None } else { Some(ep.addr) })
            .collect();
        self.push_addrs(addrs).await;
    }

    /// Add peers addresses on 503 (unavailable) error.
    pub async fn on_redirect(&self, addrs: Vec<SocketAddr>) {
        self.push_addrs(addrs).await;
    }

    /// Get and remove address from peer table.
    /// TODO: I don't quite understand why this method
    pub async fn get_peer_address(&self) -> Option<SocketAddr> {
        let mut addrs = self.addrs.lock().await;
        loop {
            addrs.shuffle(&mut rand::thread_rng());
            match addrs.pop() {
                Some(addr) => {
                    if addr.is_ipv4() {
                        break Some(addr);
                    }
                }
                None => break None,
            }
        }
    }
}
