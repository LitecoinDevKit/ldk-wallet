//! Finding public MWEB-serving peers, so the wallet works without litecoind.
//!
//! Litecoin's DNS seeders implement the `x<flags>` service-bit query, but only
//! answer it for the low flags — `x1` and `x9` return records while
//! `x8388608` (`NODE_MWEB_LIGHT_CLIENT`) returns nothing. So candidates come
//! back unfiltered and we check the bit ourselves with a short version
//! handshake. In practice most seeder results do serve MWEB, so a single round
//! of probes fills the pool.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bdk_wallet::bitcoin::consensus::encode::{deserialize, serialize};
use bdk_wallet::bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bdk_wallet::bitcoin::p2p::message_network::VersionMessage;
use bdk_wallet::bitcoin::p2p::{Address, ServiceFlags};

use crate::network::WalletNetwork;

/// `NODE_MWEB_LIGHT_CLIENT` from Litecoin Core `protocol.h`: the peer answers
/// LIP-0006 light-client requests.
const NODE_MWEB_LIGHT_CLIENT: u64 = 1 << 23;

const PROBE_TIMEOUT: Duration = Duration::from_secs(4);
/// Once at least [`MIN_EARLY_PEERS`] have answered, wait at most this much
/// longer for slower peers before returning the pool to the syncer.
const EARLY_RETURN_GRACE: Duration = Duration::from_millis(600);
const MIN_EARLY_PEERS: usize = 2;
/// Sync runs every 60s; re-crawling that often would be rude to the seeders.
const CACHE_TTL: Duration = Duration::from_secs(15 * 60);
const MAX_PROBES_PER_SEED: usize = 10;
const WANT_PEERS: usize = 8;

struct Cached {
    network: WalletNetwork,
    at: Instant,
    addrs: Vec<SocketAddr>,
}

static CACHE: Mutex<Option<Cached>> = Mutex::new(None);
/// Serializes cache-miss crawls so `warm_mweb_peers_in_background` and `sync`
/// share a single crawl instead of racing two parallel crawls.
static CRAWL_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
thread_local! {
    static OFFLINE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Make discovery on this thread find no peers, so a test can run a sync pass
/// without touching the network.
#[cfg(test)]
pub(crate) fn go_offline_for_test() {
    OFFLINE.with(|offline| offline.set(true));
}

/// Peers that completed a handshake advertising MWEB light-client support.
///
/// Cached for [`CACHE_TTL`]. Returns an empty vec when the seeds are
/// unreachable or nothing answers, which callers treat as "MWEB unavailable"
/// rather than an error.
pub fn discover_mweb_peers(network: WalletNetwork) -> Vec<SocketAddr> {
    #[cfg(test)]
    if OFFLINE.with(std::cell::Cell::get) {
        return Vec::new();
    }
    if let Some(addrs) = cached_peers(network) {
        return addrs;
    }
    let _crawl_guard = CRAWL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(addrs) = cached_peers(network) {
        return addrs;
    }
    let addrs = crawl(network);
    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some(Cached {
            network,
            at: Instant::now(),
            addrs: addrs.clone(),
        });
    }
    addrs
}

fn cached_peers(network: WalletNetwork) -> Option<Vec<SocketAddr>> {
    let guard = CACHE.lock().ok()?;
    let cached = guard.as_ref()?;
    if cached.network == network && cached.at.elapsed() < CACHE_TTL && !cached.addrs.is_empty() {
        Some(cached.addrs.clone())
    } else {
        None
    }
}

/// Forget cached peers so the next call re-crawls (used after a settings change).
pub fn clear_cache() {
    if let Ok(mut guard) = CACHE.lock() {
        *guard = None;
    }
}

/// Pre-warm the MWEB peer cache on a background thread when it is cold.
pub(crate) fn warm_mweb_peers_in_background(network: WalletNetwork) {
    #[cfg(test)]
    if OFFLINE.with(std::cell::Cell::get) {
        return;
    }
    if cached_peers(network).is_some() {
        return;
    }
    std::thread::spawn(move || {
        let _ = discover_mweb_peers(network);
    });
}

fn crawl(network: WalletNetwork) -> Vec<SocketAddr> {
    let port = network.p2p_port();
    let seeds = network.dns_seeds();
    if seeds.is_empty() {
        return Vec::new();
    }

    // Do NOT wrap `to_socket_addrs()` in `std::thread::scope`: a single dead DNS
    // seeder can stall `getaddrinfo` for 30s on macOS. Instead, each seed thread
    // resolves detached and immediately spawns probes for its own candidates.
    let (tx, rx) = mpsc::channel();
    for &host in seeds {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let Ok(resolved) = (host, port).to_socket_addrs() else {
                return;
            };
            let mut candidates: Vec<SocketAddr> = resolved.collect();
            shuffle(&mut candidates);
            candidates.truncate(MAX_PROBES_PER_SEED);
            for addr in candidates {
                let tx = tx.clone();
                std::thread::spawn(move || {
                    if serves_mweb(addr, network) {
                        let _ = tx.send(addr);
                    }
                });
            }
        });
    }
    drop(tx);

    let hard_deadline = Instant::now() + PROBE_TIMEOUT;
    let mut grace_deadline: Option<Instant> = None;
    let mut addrs = Vec::with_capacity(WANT_PEERS);
    while addrs.len() < WANT_PEERS {
        let effective_deadline = match grace_deadline {
            Some(g) => hard_deadline.min(g),
            None => hard_deadline,
        };
        let Some(wait) = effective_deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match rx.recv_timeout(wait) {
            Ok(addr) => {
                if !addrs.contains(&addr) {
                    addrs.push(addr);
                    if addrs.len() >= MIN_EARLY_PEERS && grace_deadline.is_none() {
                        grace_deadline = Some(Instant::now() + EARLY_RETURN_GRACE);
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    addrs
}

fn serves_mweb(addr: SocketAddr, network: WalletNetwork) -> bool {
    peer_services(addr, network).is_some_and(|s| s & NODE_MWEB_LIGHT_CLIENT != 0)
}

/// Handshake far enough to read the peer's advertised service flags, then hang up.
fn peer_services(addr: SocketAddr, network: WalletNetwork) -> Option<u64> {
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let magic = network.to_bitcoin_network().magic();
    let mut stream = TcpStream::connect_timeout(&addr, PROBE_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(PROBE_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(PROBE_TIMEOUT)).ok()?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let ours = ServiceFlags::from(
        u64::from(ServiceFlags::NETWORK)
            | u64::from(ServiceFlags::WITNESS)
            | NODE_MWEB_LIGHT_CLIENT,
    );
    let version = VersionMessage {
        version: 70017,
        services: ours,
        timestamp: now,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&([0, 0, 0, 0], 0).into(), ours),
        nonce: 0,
        user_agent: "/ltc-wallet:0.4.9/".into(),
        start_height: 0,
        relay: false,
    };
    let raw = RawNetworkMessage::new(magic, NetworkMessage::Version(version));
    stream.write_all(&serialize(&raw)).ok()?;

    for _ in 0..8 {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        if remaining.is_zero() {
            return None;
        }
        stream.set_read_timeout(Some(remaining)).ok()?;
        let msg = recv(&mut stream)?;
        if let NetworkMessage::Version(peer) = msg.payload() {
            let verack = RawNetworkMessage::new(magic, NetworkMessage::Verack);
            let _ = stream.write_all(&serialize(&verack));
            return Some(u64::from(peer.services));
        }
    }
    None
}

fn recv(stream: &mut TcpStream) -> Option<RawNetworkMessage> {
    let mut header = [0u8; 24];
    stream.read_exact(&mut header).ok()?;
    let len = u32::from_le_bytes(header[16..20].try_into().ok()?) as usize;
    // A peer that claims a huge payload is broken or hostile; drop it.
    if len > 4_000_000 {
        return None;
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).ok()?;
    }
    let mut full = Vec::with_capacity(24 + len);
    full.extend_from_slice(&header);
    full.extend_from_slice(&payload);
    deserialize(&full).ok()
}

/// Fisher-Yates with a xorshift seeded from the clock. Peer choice only needs
/// to be spread out, not unpredictable, so this avoids pulling in `rand`.
fn shuffle(addrs: &mut [SocketAddr]) {
    let mut state = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
        | 1;
    for i in (1..addrs.len()).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        addrs.swap(i, (state % (i as u64 + 1)) as usize);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mweb_light_client_bit_matches_core() {
        assert_eq!(NODE_MWEB_LIGHT_CLIENT, 8_388_608);
    }

    #[test]
    fn shuffle_preserves_membership() {
        let mut addrs: Vec<SocketAddr> = (0..16u16)
            .map(|i| SocketAddr::from(([127, 0, 0, 1], 9000 + i)))
            .collect();
        let original = addrs.clone();
        shuffle(&mut addrs);
        assert_eq!(addrs.len(), original.len());
        for addr in &original {
            assert!(addrs.contains(addr), "{addr} lost in shuffle");
        }
    }

    /// Hits the real DNS seeds and real peers; run with `--ignored`.
    #[test]
    #[ignore = "requires network access"]
    fn discovers_live_mainnet_peers() {
        let peers = discover_mweb_peers(WalletNetwork::Mainnet);
        println!("discovered {} MWEB peers: {peers:?}", peers.len());
        assert!(!peers.is_empty(), "no MWEB peers found via DNS seeds");

        // Advertising the bit is not the same as accepting our handshake.
        let net = WalletNetwork::Mainnet.to_bitcoin_network();
        let accepted = peers
            .iter()
            .filter(|addr| bdk_mweb::lip0006_tcp::TcpMwebPeer::connect(**addr, net).is_ok())
            .count();
        println!("{accepted}/{} completed a LIP-0006 handshake", peers.len());
        assert!(
            accepted > 0,
            "no discovered peer accepted a LIP-0006 handshake"
        );
    }

    #[test]
    fn every_network_has_seeds_and_a_port() {
        for network in [WalletNetwork::Mainnet, WalletNetwork::Testnet] {
            assert!(!network.dns_seeds().is_empty());
            assert_ne!(network.p2p_port(), 0);
        }
    }
}
