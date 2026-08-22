//! The machine reaching the offered ports: dials by endpoint id, binds local
//! listeners, and owns the UDP session table keyed by local source address.
//!
//! Listeners are keyed by (protocol, local port) and reconciled against the live
//! configuration: adding a binding binds a socket, removing one drops it, and both
//! happen without disturbing the QUIC connection or the other listeners.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use iroh::{
    EndpointAddr,
    endpoint::{Connection, ConnectionError},
};
use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    task::AbortHandle,
};
use tracing::{debug, info, warn};

use crate::{
    PortMap,
    config::{Binding, Proto},
    proto::{self, DATAGRAM_HEADER},
    state::{BindState, Shared},
};

/// One buffer per local UDP listener, sized so an oversize datagram arrives whole
/// and is refused by the datagram cap rather than silently truncated here.
const UDP_BUF: usize = 65_535;

/// Retry delay after a lost or refused-to-open connection: doubles from a second
/// to a half-minute ceiling. A peer that comes back in a minute is picked up
/// within a minute; one that is gone all day costs two log lines an hour.
const BACKOFF_START: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// A bound local socket, kept across reconnects so a client reaching 2222 during
/// an outage queues rather than finding nothing listening.
enum Sock {
    Tcp(Arc<TcpListener>),
    Udp(Arc<UdpSocket>),
}

/// The set of currently bound listeners, reconciled against the config.
#[derive(Default)]
struct Listeners {
    bound: HashMap<(Proto, u16), (Sock, u16)>,
}

impl Listeners {
    /// Binds what is newly configured, drops what is gone, and retargets a binding
    /// whose remote port changed. Returns true when the set changed, so the caller
    /// only restarts the forwarders that way.
    async fn reconcile(&mut self, want: &[Binding], shared: &Arc<Shared>) -> bool {
        let mut changed = false;
        let keys: HashSet<(Proto, u16)> = want.iter().map(|b| (b.proto, b.local)).collect();

        // Dropping the Arc closes the socket and frees the port for something else.
        let stale: Vec<_> = self.bound.keys().filter(|k| !keys.contains(k)).copied().collect();
        for k in stale {
            self.bound.remove(&k);
            shared.clear_bind(k.0, k.1);
            info!(proto = %k.0, local = k.1, "stopped listening");
            changed = true;
        }

        for b in want {
            let key = (b.proto, b.local);
            // A changed remote port keeps the socket but must re-point the pump.
            if let Some((_, remote)) = self.bound.get_mut(&key) {
                if *remote != b.remote {
                    *remote = b.remote;
                    info!(proto = %b.proto, local = b.local, remote = b.remote, "retargeted");
                    changed = true;
                }
                continue;
            }
            match bind_one(b).await {
                Ok(sock) => {
                    self.bound.insert(key, (sock, b.remote));
                    shared.set_bind(b.proto, b.local, BindState::Listening);
                    info!(proto = %b.proto, local = b.local, remote = b.remote, "listening");
                    changed = true;
                }
                Err(e) => {
                    // A port in use must not kill the process or the other
                    // listeners: it is reported and retried on the next change.
                    warn!(proto = %b.proto, local = b.local, "cannot bind: {e:#}");
                    shared.set_bind(b.proto, b.local, BindState::Failed {
                        error: format!("{e:#}"),
                    });
                }
            }
        }
        changed
    }

    fn tcp(&self) -> Vec<(Arc<TcpListener>, PortMap)> {
        self.bound
            .iter()
            .filter_map(|((_, local), (s, remote))| match s {
                Sock::Tcp(l) => Some((l.clone(), PortMap { local: *local, remote: *remote })),
                _ => None,
            })
            .collect()
    }

    fn udp(&self) -> Vec<(Arc<UdpSocket>, PortMap)> {
        self.bound
            .iter()
            .filter_map(|((_, local), (s, remote))| match s {
                Sock::Udp(u) => Some((u.clone(), PortMap { local: *local, remote: *remote })),
                _ => None,
            })
            .collect()
    }
}

async fn bind_one(b: &Binding) -> Result<Sock> {
    let addr = (std::net::Ipv4Addr::LOCALHOST, b.local);
    Ok(match b.proto {
        Proto::Tcp => Sock::Tcp(Arc::new(TcpListener::bind(addr).await?)),
        Proto::Udp => Sock::Udp(Arc::new(UdpSocket::bind(addr).await?)),
    })
}

pub async fn run(ep: iroh::Endpoint, peer: EndpointAddr, shared: Arc<Shared>) -> Result<()> {
    println!("endpoint id {}", ep.id());

    let mut listeners = Listeners::default();
    let mut cfg_rx = shared.subscribe();
    let initial = shared.config().active_bindings();
    listeners.reconcile(&initial, &shared).await;
    // A command that asked for listeners and got none is a failure worth exiting
    // for; one that asked for none is a control-plane-only run and is fine.
    if !initial.is_empty() && listeners.bound.is_empty() {
        bail!("no local port could be bound; see the errors above");
    }

    let mut delay = BACKOFF_START;
    loop {
        info!(id = %ep.id(), peer = %peer.id, "dialing");
        // Dialing by id is mutually authenticated by construction: the QUIC
        // handshake cannot complete against anything but the holder of that key.
        match ep.connect(peer.clone(), crate::ALPN).await {
            Ok(conn) => {
                delay = BACKOFF_START; // a link that formed once earns a fresh ladder
                crate::report_path(&conn, &shared);
                shared.peer_connected(conn.remote_id());

                // Forwarders are (re)spawned whenever the listener set changes, so
                // a binding added in the UI starts carrying traffic immediately.
                let mut tasks = spawn_forwarders(&conn, &listeners);
                let reason = loop {
                    tokio::select! {
                        reason = conn.closed() => break reason,
                        changed = cfg_rx.changed() => {
                            if changed.is_err() {
                                break conn.closed().await;
                            }
                            let want = cfg_rx.borrow_and_update().active_bindings();
                            if listeners.reconcile(&want, &shared).await {
                                tasks.iter().for_each(AbortHandle::abort);
                                tasks = spawn_forwarders(&conn, &listeners);
                            }
                        }
                    }
                };
                tasks.iter().for_each(AbortHandle::abort);
                shared.peer_disconnected(&peer.id);
                // "Refused" and "gone" are different answers. The allowlist's close
                // is a permanent no, and retrying it forever would be a busy loop
                // against a decision that will not change.
                if let ConnectionError::ApplicationClosed(c) = &reason {
                    bail!("closed by peer: {} (code {})", c.reason.escape_ascii(), c.error_code);
                }
                warn!(peer = %peer.id, "connection lost: {reason}");
            }
            Err(e) => warn!(peer = %peer.id, "dial failed: {}", anyhow!("{e:#}")),
        }
        info!(peer = %peer.id, retry_in = ?delay, "retrying");
        // Waiting for the retry must still service config edits, or a binding added
        // during an outage would not appear until the peer came back.
        let until = tokio::time::Instant::now() + delay;
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(until) => break,
                changed = cfg_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    let want = cfg_rx.borrow_and_update().active_bindings();
                    listeners.reconcile(&want, &shared).await;
                }
            }
        }
        delay = (delay * 2).min(BACKOFF_MAX);
    }
}

/// Everything that carries bytes for one connection, so that losing the
/// connection tears all of it down and the next one starts clean — in particular
/// the UDP session table, whose ids the far side forgot when the link died.
fn spawn_forwarders(conn: &Connection, listeners: &Listeners) -> Vec<AbortHandle> {
    let (tcp, udp) = (listeners.tcp(), listeners.udp());
    let mut tasks: Vec<AbortHandle> = tcp
        .iter()
        .map(|(l, m)| tokio::spawn(accept_tcp(l.clone(), conn.clone(), *m)).abort_handle())
        .collect();
    if !udp.is_empty() {
        let sessions = Arc::new(Mutex::new(Sessions::default()));
        for (s, m) in &udp {
            tasks.push(
                tokio::spawn(pump_udp_out(s.clone(), conn.clone(), *m, sessions.clone()))
                    .abort_handle(),
            );
        }
        tasks.push(tokio::spawn(pump_udp_in(conn.clone(), sessions.clone())).abort_handle());
        let reaper = sessions.clone();
        tasks.push(
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(crate::UDP_REAP_INTERVAL);
                loop {
                    tick.tick().await;
                    reaper.lock().unwrap().reap();
                }
            })
            .abort_handle(),
        );
    }
    tasks
}

// ---------------------------------------------------------------- TCP

async fn accept_tcp(l: Arc<TcpListener>, conn: Connection, m: PortMap) {
    loop {
        match l.accept().await {
            Ok((sock, from)) => {
                let conn = conn.clone();
                tokio::spawn(async move {
                    if let Err(e) = forward_tcp(&conn, sock, m.remote).await {
                        warn!(%from, port = m.remote, "stream failed: {e:#}");
                    }
                });
            }
            Err(e) => return warn!(local = m.local, "accept failed: {e:#}"),
        }
    }
}

/// One QUIC bidirectional stream per accepted TCP connection. `copy_bidirectional`
/// is the whole data plane: it pumps both directions and maps each EOF onto the
/// other side's shutdown, which is how a stream FIN becomes a TCP FIN.
async fn forward_tcp(conn: &Connection, mut sock: TcpStream, port: u16) -> Result<()> {
    let (mut send, recv) = conn.open_bi().await?;
    proto::write_target_port(&mut send, port).await?;
    let mut quic = tokio::io::join(recv, send);
    let (up, down) = tokio::io::copy_bidirectional(&mut sock, &mut quic).await?;
    debug!(port, up, down, "stream closed");
    Ok(())
}

// ---------------------------------------------------------------- UDP

/// UDP has no connections, so the connecting side synthesises them: the tuple
/// (local source address, target port) is the session, and the `u32` id is what
/// lets a reply find its way back to the right local process.
#[derive(Default)]
struct Sessions {
    by_key: HashMap<(SocketAddr, u16), u32>,
    by_id: HashMap<u32, Session>,
    next_id: u32,
}

struct Session {
    src: SocketAddr,
    sock: Arc<UdpSocket>,
    last: Instant,
}

impl Sessions {
    fn id_for(&mut self, src: SocketAddr, port: u16, sock: &Arc<UdpSocket>) -> u32 {
        if let Some(&id) = self.by_key.get(&(src, port)) {
            self.by_id.get_mut(&id).unwrap().last = Instant::now();
            return id;
        }
        self.next_id += 1;
        let id = self.next_id;
        self.by_key.insert((src, port), id);
        self.by_id.insert(id, Session { src, sock: sock.clone(), last: Instant::now() });
        info!(sessions = self.by_id.len(), session = id, %src, port, "udp session opened");
        id
    }

    /// The reply route, refreshing the idle timer — a service that keeps talking
    /// keeps its session, even if the local process has gone quiet.
    fn reply_route(&mut self, id: u32) -> Option<(Arc<UdpSocket>, SocketAddr)> {
        let s = self.by_id.get_mut(&id)?;
        s.last = Instant::now();
        Some((s.sock.clone(), s.src))
    }

    fn reap(&mut self) {
        let Self { by_key, by_id, .. } = self;
        let before = by_id.len();
        by_id.retain(|_, s| s.last.elapsed() < crate::UDP_IDLE);
        if by_id.len() != before {
            by_key.retain(|_, id| by_id.contains_key(id));
            info!(sessions = by_id.len(), reaped = before - by_id.len(), "udp sessions reaped");
        }
    }
}

async fn pump_udp_out(
    sock: Arc<UdpSocket>,
    conn: Connection,
    m: PortMap,
    sessions: Arc<Mutex<Sessions>>,
) {
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => return warn!(local = m.local, "udp recv failed: {e:#}"),
        };
        let id = sessions.lock().unwrap().id_for(src, m.remote, &sock);
        // ponytail: the cap is whatever QUIC can carry right now, roughly 1200 bytes
        // minus the header — a known ceiling, so the drop only has to be loud. Lift
        // it by fragmenting across a per-session stream when a workload needs it.
        if let Err(e) = conn.send_datagram(proto::encode_datagram(id, m.remote, &buf[..n])) {
            warn!(
                session = id,
                bytes = n,
                cap = conn.max_datagram_size().map(|max| max.saturating_sub(DATAGRAM_HEADER)),
                "dropped datagram: {e}"
            );
        }
    }
}

async fn pump_udp_in(conn: Connection, sessions: Arc<Mutex<Sessions>>) {
    loop {
        let dg: Bytes = match conn.read_datagram().await {
            Ok(dg) => dg,
            Err(e) => return debug!("datagram reader stopped: {e}"),
        };
        let Some((id, _port, payload)) = proto::decode_datagram(&dg) else {
            warn!(bytes = dg.len(), "dropped datagram: shorter than the header");
            continue;
        };
        // Bound out of the match: the guard must not be alive across the send.
        let route = sessions.lock().unwrap().reply_route(id);
        match route {
            Some((sock, src)) => {
                if let Err(e) = sock.send_to(&payload, src).await {
                    warn!(session = id, %src, "reply undeliverable: {e:#}");
                }
            }
            None => debug!(session = id, "reply for a reaped or unknown session"),
        }
    }
}
