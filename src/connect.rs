//! The machine reaching the offered ports: dials by endpoint id, binds local
//! listeners, and owns the UDP session table keyed by local source address.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
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
    proto::{self, DATAGRAM_HEADER},
};

/// One buffer per local UDP listener, sized so an oversize datagram arrives whole
/// and is refused by the datagram cap rather than silently truncated here.
const UDP_BUF: usize = 65_535;

/// Retry delay after a lost or refused-to-open connection: doubles from a second
/// to a half-minute ceiling. A peer that comes back in a minute is picked up
/// within a minute; one that is gone all day costs two log lines an hour.
const BACKOFF_START: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

pub async fn run(
    ep: iroh::Endpoint,
    peer: EndpointAddr,
    tcp: Vec<PortMap>,
    udp: Vec<PortMap>,
) -> Result<()> {
    println!("endpoint id {}", ep.id());

    // Bound before dialing, and kept bound across reconnects: a taken local port
    // must fail the command, and a client reaching 2222 during an outage should
    // queue rather than find nothing listening.
    let mut tcp_listeners = Vec::new();
    for m in &tcp {
        let l = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, m.local))
            .await
            .with_context(|| format!("binding tcp 127.0.0.1:{}", m.local))?;
        info!(proto = "tcp", local = m.local, remote = m.remote, "listening");
        tcp_listeners.push((Arc::new(l), *m));
    }
    let mut udp_sockets = Vec::new();
    for m in &udp {
        let s = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, m.local))
            .await
            .with_context(|| format!("binding udp 127.0.0.1:{}", m.local))?;
        info!(proto = "udp", local = m.local, remote = m.remote, "listening");
        udp_sockets.push((Arc::new(s), *m));
    }

    let mut delay = BACKOFF_START;
    loop {
        info!(id = %ep.id(), peer = %peer.id, "dialing");
        // Dialing by id is mutually authenticated by construction: the QUIC
        // handshake cannot complete against anything but the holder of that key.
        match ep.connect(peer.clone(), crate::ALPN).await {
            Ok(conn) => {
                delay = BACKOFF_START; // a link that formed once earns a fresh ladder
                crate::report_path(&conn);
                let tasks = spawn_forwarders(&conn, &tcp_listeners, &udp_sockets);
                let reason = conn.closed().await;
                tasks.iter().for_each(AbortHandle::abort);
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
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(BACKOFF_MAX);
    }
}

/// Everything that carries bytes for one connection, so that losing the
/// connection tears all of it down and the next one starts clean — in particular
/// the UDP session table, whose ids the far side forgot when the link died.
fn spawn_forwarders(
    conn: &Connection,
    tcp: &[(Arc<TcpListener>, PortMap)],
    udp: &[(Arc<UdpSocket>, PortMap)],
) -> Vec<AbortHandle> {
    let mut tasks: Vec<AbortHandle> = tcp
        .iter()
        .map(|(l, m)| tokio::spawn(accept_tcp(l.clone(), conn.clone(), *m)).abort_handle())
        .collect();
    if !udp.is_empty() {
        let sessions = Arc::new(Mutex::new(Sessions::default()));
        for (s, m) in udp {
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
