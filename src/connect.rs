//! The machine reaching the offered ports: dials by endpoint id, binds local
//! listeners, and owns the UDP session table keyed by local source address.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use iroh::{EndpointAddr, endpoint::Connection};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, info, warn};

use crate::{
    PortMap,
    proto::{self, DATAGRAM_HEADER},
};

/// One buffer per local UDP listener, sized so an oversize datagram arrives whole
/// and is refused by the datagram cap rather than silently truncated here.
const UDP_BUF: usize = 65_535;

pub async fn run(
    ep: iroh::Endpoint,
    peer: EndpointAddr,
    tcp: Vec<PortMap>,
    udp: Vec<PortMap>,
) -> Result<()> {
    println!("endpoint id {}", ep.id());

    // Bound before dialing: a taken local port must fail the command, not leave a
    // connected tunnel with nothing listening on it.
    let mut tcp_listeners = Vec::new();
    for m in &tcp {
        let l = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, m.local))
            .await
            .with_context(|| format!("binding tcp 127.0.0.1:{}", m.local))?;
        info!(proto = "tcp", local = m.local, remote = m.remote, "listening");
        tcp_listeners.push((l, *m));
    }
    let mut udp_sockets = Vec::new();
    for m in &udp {
        let s = UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, m.local))
            .await
            .with_context(|| format!("binding udp 127.0.0.1:{}", m.local))?;
        info!(proto = "udp", local = m.local, remote = m.remote, "listening");
        udp_sockets.push((Arc::new(s), *m));
    }

    info!(id = %ep.id(), peer = %peer.id, "dialing");
    // Dialing by id is mutually authenticated by construction: the QUIC handshake
    // cannot complete against anything but the holder of that key.
    let conn = ep.connect(peer.clone(), crate::ALPN).await.map_err(|e| anyhow!("connect: {e:#}"))?;
    crate::report_path(&conn);

    for (l, m) in tcp_listeners {
        let conn = conn.clone();
        tokio::spawn(accept_tcp(l, conn, m));
    }
    if !udp_sockets.is_empty() {
        let sessions = Arc::new(Mutex::new(Sessions::default()));
        for (s, m) in udp_sockets {
            tokio::spawn(pump_udp_out(s, conn.clone(), m, sessions.clone()));
        }
        tokio::spawn(pump_udp_in(conn.clone(), sessions.clone()));
        let reaper = sessions.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(crate::UDP_REAP_INTERVAL);
            loop {
                tick.tick().await;
                reaper.lock().unwrap().reap();
            }
        });
    }

    let reason = conn.closed().await;
    info!(peer = %peer.id, "closed: {reason}");
    Ok(())
}

// ---------------------------------------------------------------- TCP

async fn accept_tcp(l: TcpListener, conn: Connection, m: PortMap) {
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
