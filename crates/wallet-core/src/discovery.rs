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
/// Sync runs every 60s; re-crawling that often would be rude to the seeders,
/// while keeping a pool for 15+ minutes lets lagging or dead peers linger.
const CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_PROBES_PER_SEED: usize = 10;
const WANT_PEERS: usize = 8;

struct Cached {
    network: WalletNetwork,
    at: Instant,
    /// Wall-clock timestamp (ms since UNIX_EPOCH) so laptop sleep on macOS
    /// (where `Instant` / `mach_absolute_time` pauses during suspend) still
    /// expires the peer cache.
    at_unix_ms: u64,
    addrs: Vec<SocketAddr>,
    demoted: Vec<SocketAddr>,
}

fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Cached {
    fn is_fresh(&self, network: WalletNetwork, now_unix_ms: u64) -> bool {
        let ttl_ms = CACHE_TTL.as_millis() as u64;
        self.network == network
            && !self.addrs.is_empty()
            && self.at.elapsed() < CACHE_TTL
            && now_unix_ms.saturating_sub(self.at_unix_ms) < ttl_ms
    }
}

static CACHE: Mutex<Option<Cached>> = Mutex::new(None);
/// Serializes cache-miss crawls so `warm_mweb_peers_in_background` and `sync`
/// share a single crawl instead of racing two parallel crawls.
static CRAWL_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
#[derive(Default)]
struct TestDiscoveryState {
    offline: bool,
    peers: Option<Vec<SocketAddr>>,
    demoted: Vec<SocketAddr>,
}

#[cfg(test)]
thread_local! {
    static TEST_STATE: std::cell::RefCell<std::sync::Arc<Mutex<TestDiscoveryState>>> =
        std::cell::RefCell::new(std::sync::Arc::new(Mutex::new(TestDiscoveryState::default())));
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestDiscoveryContext(std::sync::Arc<Mutex<TestDiscoveryState>>);

#[cfg(test)]
pub(crate) fn capture_test_context() -> TestDiscoveryContext {
    TEST_STATE.with(|slot| TestDiscoveryContext(slot.borrow().clone()))
}

#[cfg(test)]
pub(crate) fn install_test_context(ctx: TestDiscoveryContext) {
    TEST_STATE.with(|slot| *slot.borrow_mut() = ctx.0);
}

#[cfg(test)]
fn with_test_state<R>(f: impl FnOnce(&mut TestDiscoveryState) -> R) -> R {
    TEST_STATE.with(|slot| {
        let arc = slot.borrow().clone();
        let mut guard = arc.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    })
}

/// Make discovery on this thread find no peers, so a test can run a sync pass
/// without touching the network.
#[cfg(test)]
pub(crate) fn go_offline_for_test() {
    with_test_state(|st| st.offline = true);
}

/// Seed discovery on this thread with a fixed peer list for deterministic tests.
#[cfg(test)]
pub(crate) fn set_peers_for_test(addrs: Option<Vec<SocketAddr>>) {
    with_test_state(|st| {
        st.peers = addrs;
        st.demoted.clear();
    });
}

/// Current thread-local test peer pool, if seeded.
#[cfg(test)]
pub(crate) fn peers_for_test() -> Option<Vec<SocketAddr>> {
    with_test_state(|st| st.peers.clone())
}

/// Peers that completed a handshake advertising MWEB light-client support.
///
/// Cached for [`CACHE_TTL`]. Returns an empty vec when the seeds are
/// unreachable or nothing answers, which callers treat as "MWEB unavailable"
/// rather than an error.
pub fn discover_mweb_peers(network: WalletNetwork) -> Vec<SocketAddr> {
    #[cfg(test)]
    {
        if let Some(res) = with_test_state(|st| {
            if let Some(addrs) = st.peers.clone() {
                Some(addrs)
            } else if st.offline {
                Some(Vec::new())
            } else {
                None
            }
        }) {
            return res;
        }
    }
    if let Some(addrs) = cached_peers(network) {
        return addrs;
    }
    let _crawl_guard = CRAWL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(addrs) = cached_peers(network) {
        return addrs;
    }
    let crawl_started = Instant::now();
    let addrs = crawl(network);
    let crawl_ms = crawl_started.elapsed().as_millis() as u64;
    crate::diag::log(format!(
        "discovery: crawled {} mweb peers in {crawl_ms} ms",
        addrs.len()
    ));
    if let Ok(mut guard) = CACHE.lock() {
        *guard = Some(Cached {
            network,
            at: Instant::now(),
            at_unix_ms: unix_now_ms(),
            addrs: addrs.clone(),
            demoted: Vec::new(),
        });
    }
    addrs
}

fn cached_peers(network: WalletNetwork) -> Option<Vec<SocketAddr>> {
    let guard = CACHE.lock().ok()?;
    let cached = guard.as_ref()?;
    if cached.is_fresh(network, unix_now_ms()) {
        Some(cached.addrs.clone())
    } else {
        None
    }
}

/// Forget cached peers so the next call re-crawls (used after a settings change
/// or when every cached peer in a sync pass failed).
pub fn clear_cache() {
    #[cfg(test)]
    with_test_state(|st| {
        if let Some(addrs) = st.peers.as_mut() {
            addrs.clear();
        }
        st.demoted.clear();
    });
    if let Ok(mut guard) = CACHE.lock() {
        *guard = None;
    }
}

/// Remove failed/unresponsive peers from the discovery cache.
///
/// When eviction leaves fewer than [`MIN_EARLY_PEERS`] addresses, the cache is
/// cleared outright so the next [`discover_mweb_peers`] call re-crawls rather
/// than limping along on a single survivor.
pub fn evict_peers(bad: &[SocketAddr]) {
    if bad.is_empty() {
        return;
    }
    #[cfg(test)]
    let handled_by_test = with_test_state(|st| {
        if let Some(addrs) = st.peers.as_mut() {
            if !evict_from_pool(addrs, bad) {
                addrs.clear();
            }
            st.demoted.retain(|a| !bad.contains(a));
            true
        } else {
            false
        }
    });
    #[cfg(test)]
    if handled_by_test {
        return;
    }
    if let Ok(mut guard) = CACHE.lock() {
        if let Some(cached) = guard.as_mut() {
            cached.demoted.retain(|a| !bad.contains(a));
            if !evict_from_pool(&mut cached.addrs, bad) {
                *guard = None;
            }
        }
    }
}

/// Move slow or unconfirmed peers to the back of the discovery cache so healthy
/// peers are tried first on the next sync pass.
pub fn demote_peers(slow: &[SocketAddr]) {
    if slow.is_empty() {
        return;
    }
    #[cfg(test)]
    let handled_by_test = with_test_state(|st| {
        if let Some(addrs) = st.peers.as_mut() {
            demote_in_pool(addrs, slow);
            for &addr in slow {
                if !st.demoted.contains(&addr) {
                    st.demoted.push(addr);
                }
            }
            true
        } else {
            false
        }
    });
    #[cfg(test)]
    if handled_by_test {
        return;
    }
    if let Ok(mut guard) = CACHE.lock() {
        if let Some(cached) = guard.as_mut() {
            demote_in_pool(&mut cached.addrs, slow);
            for &addr in slow {
                if cached.addrs.contains(&addr) && !cached.demoted.contains(&addr) {
                    cached.demoted.push(addr);
                }
            }
        }
    }
}

/// Whether `addr` is still in the active discovery pool and has not been
/// demoted since it last served a sync pass.
pub fn should_prefer_peer(addr: &SocketAddr) -> bool {
    #[cfg(test)]
    if let Some(prefer) = with_test_state(|st| {
        st.peers
            .as_ref()
            .map(|addrs| addrs.contains(addr) && !st.demoted.contains(addr))
    }) {
        return prefer;
    }
    let Ok(guard) = CACHE.lock() else {
        return false;
    };
    let Some(cached) = guard.as_ref() else {
        return false;
    };
    cached.addrs.contains(addr) && !cached.demoted.contains(addr)
}

/// Clear any prior demotion once `addr` completes a verified sync pass.
pub fn note_good_peer(addr: SocketAddr) {
    #[cfg(test)]
    with_test_state(|st| st.demoted.retain(|a| *a != addr));
    if let Ok(mut guard) = CACHE.lock() {
        if let Some(cached) = guard.as_mut() {
            cached.demoted.retain(|a| *a != addr);
        }
    }
}

fn evict_from_pool(pool: &mut Vec<SocketAddr>, bad: &[SocketAddr]) -> bool {
    pool.retain(|addr| !bad.contains(addr));
    pool.len() >= MIN_EARLY_PEERS
}

fn demote_in_pool(pool: &mut Vec<SocketAddr>, slow: &[SocketAddr]) {
    let mut tail = Vec::new();
    pool.retain(|addr| {
        if slow.contains(addr) {
            tail.push(*addr);
            false
        } else {
            true
        }
    });
    pool.extend(tail);
}

/// Pre-warm the MWEB peer cache on a background thread when it is cold.
pub(crate) fn warm_mweb_peers_in_background(network: WalletNetwork) {
    #[cfg(test)]
    {
        let _ = network;
    }
    #[cfg(not(test))]
    {
        if cached_peers(network).is_some() {
            return;
        }
        std::thread::spawn(move || {
            let _ = discover_mweb_peers(network);
        });
    }
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

    #[test]
    fn cache_ttl_is_five_minutes() {
        assert_eq!(CACHE_TTL, Duration::from_secs(5 * 60));
    }

    #[test]
    fn evict_removes_bad_peers_and_clears_when_below_threshold() {
        let a = SocketAddr::from(([10, 0, 0, 1], 9333));
        let b = SocketAddr::from(([10, 0, 0, 2], 9333));
        let c = SocketAddr::from(([10, 0, 0, 3], 9333));
        set_peers_for_test(Some(vec![a, b, c]));

        evict_peers(&[b]);
        assert_eq!(discover_mweb_peers(WalletNetwork::Mainnet), vec![a, c]);

        // Dropping below MIN_EARLY_PEERS (2) flushes the pool so the next call
        // does not stay pinned to a single survivor.
        evict_peers(&[a]);
        assert!(discover_mweb_peers(WalletNetwork::Mainnet).is_empty());
        set_peers_for_test(None);
    }

    #[test]
    fn demote_moves_slow_peers_to_the_back_preserving_order() {
        let a = SocketAddr::from(([10, 0, 0, 1], 9333));
        let b = SocketAddr::from(([10, 0, 0, 2], 9333));
        let c = SocketAddr::from(([10, 0, 0, 3], 9333));
        let d = SocketAddr::from(([10, 0, 0, 4], 9333));
        set_peers_for_test(Some(vec![a, b, c, d]));

        demote_peers(&[a, c]);
        assert_eq!(
            discover_mweb_peers(WalletNetwork::Mainnet),
            vec![b, d, a, c]
        );
        assert!(!should_prefer_peer(&a));
        assert!(should_prefer_peer(&b));
        note_good_peer(a);
        assert!(should_prefer_peer(&a));
        set_peers_for_test(None);
    }

    /// On macOS, `Instant` (`mach_absolute_time`) pauses while the machine is
    /// asleep, which previously kept a 15-minute `CACHE_TTL` alive across 2+
    /// hours of wall-clock lid-closed gaps. `Cached::is_fresh` checks both
    /// `Instant` and `SystemTime` so wall-clock sleep expires the cache.
    #[test]
    fn wall_clock_sleep_expires_cache_even_when_monotonic_clock_paused() {
        let now_ms = unix_now_ms();
        let fresh = Cached {
            network: WalletNetwork::Mainnet,
            addrs: vec![SocketAddr::from(([10, 0, 0, 1], 9333))],
            demoted: Vec::new(),
            at: Instant::now(),
            at_unix_ms: now_ms,
        };
        assert!(fresh.is_fresh(WalletNetwork::Mainnet, now_ms));

        let slept = Cached {
            at: Instant::now(),
            at_unix_ms: now_ms
                .saturating_sub((CACHE_TTL + Duration::from_secs(1)).as_millis() as u64),
            ..fresh
        };
        assert!(
            !slept.is_fresh(WalletNetwork::Mainnet, now_ms),
            "wall-clock elapsed past CACHE_TTL must expire cache even when Instant did not advance"
        );
    }
}
