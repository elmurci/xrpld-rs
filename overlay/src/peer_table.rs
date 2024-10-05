use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use futures::future::join_all;
use rand::seq::SliceRandom;
use shared::log;
use shared::structs::config::IpItem;
use tokio::net::lookup_host;
use tokio::sync::Mutex;

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

    /// Load peers addresses from config (or fallback to default) with resolving bootstrap nodes.
    pub async fn load_peer_addrs(&self, ips: Option<Vec<IpItem>>) {
        let addrs = if ips.is_some() {
            let mut socket_addrs:Vec<SocketAddr> = vec![];
            for ip_item in ips.unwrap().iter() {
                let ip = &ip_item.ip;
                let port:u16 = ip_item.port.parse().unwrap();
                socket_addrs.push(
                    SocketAddr::new(IpAddr::V4(
                        Ipv4Addr::from_str(ip).unwrap()
                    ), port)
                );
            }
            socket_addrs
        } else {
            Self::get_bootstrap_peer_addrs().await
        };
        self.push_addrs(addrs).await;
    }

    /// Resolve bootstrap nodes to addrs.
    async fn get_bootstrap_peer_addrs() -> Vec<SocketAddr> {
        let nodes = Self::get_bootstrap_peer_nodes();

        let futs = nodes.iter().map(|node| async move {
            match lookup_host(node).await {
                Ok(addrs) => addrs.collect(),
                Err(error) => {
                    log::error!("Failed resolve bootstrap node {}: {}", node, error);
                    vec![]
                }
            }
        });
        let addrs = join_all(futs).await;
        addrs.into_iter().flatten().collect()
    }

    /// Return pre-defined nodes.
    /// https://github.com/ripple/rippled/blob/1.5.0/src/ripple/overlay/impl/OverlayImpl.cpp#L536-L544
    const fn get_bootstrap_peer_nodes() -> [&'static str; 2] {
        [
            // Pool of servers operated by Ripple Labs Inc. - https://ripple.com
            "r.ripple.com:51235",
            // Pool of servers operated by ISRDC - https://isrdc.in
            "sahyadri.isrdc.in:51235",
        ]
    }

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
