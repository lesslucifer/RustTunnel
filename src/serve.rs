//! The machine offering ports: checks the peer allowlist, then the port allowlist,
//! then makes outbound loopback connections on the peer's behalf.
//!
//! Every check reads the *current* configuration rather than a copy taken at
//! startup, so an edit in the admin UI takes effect on the next stream or
//! datagram. A peer whose grant is withdrawn while it is connected is closed
//! rather than left holding an authorisation that no longer exists.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::Result;
use bytes::Bytes;
use iroh::{
    Endpoint,
    endpoint::{Connection, VarInt},
};
use tokio::{
    net::{TcpStream, UdpSocket},
    task::AbortHandle,
};
use tracing::{debug, info, warn};

use crate::{config::Proto, proto, state::Shared};

/// Application close code for a peer that is not allowlisted — at connect time or
/// because the allowlist changed under it.
pub(crate) const REFUSED: u32 = 1;
/// Stream reset code for a stream naming a port that was not offered.
const REFUSED_PORT: u32 = 2;
/// Matches [`crate::connect::UDP_BUF`]'s reasoning: receive whole, then judge.
const UDP_BUF: usize = 65_535;

pub async fn run(ep: Endpoint, shared: Arc<Shared>) -> Result<()> {
    println!("endpoint id {}", ep.id());
    let cfg = shared.config();
    info!(
        id = %ep.id(),
        peers = cfg.serve.peers.iter().filter(|p| p.enabled).count(),
        shared_offers = cfg.serve.shared.iter().filter(|o| o.enabled).count(),
        "serving"
    );

    while let Some(incoming) = ep.accept().await {
        let shared = shared.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => return warn!("handshake failed: {e:#}"),
            };
            let peer = conn.remote_id();
            // The handshake proved the peer holds this key; the allowlist decides
            // whether that key may in. Read live, so a peer added a second ago is
            // admitted without a restart.
            if !shared.config().admits(&peer) {
                warn!(peer = %peer, "refused: endpoint id not allowlisted");
                conn.close(REFUSED.into(), b"not allowlisted");
                return;
            }
            let name = shared.config().peer(&peer).map(|p| p.name.clone()).unwrap_or_default();
            info!(peer = %peer, name = %name, "admitted");
            shared.peer_connected(peer);
            crate::report_path(&conn, &shared);
            serve_conn(&conn, &shared).await;
            shared.peer_disconnected(&peer);
            match conn.close_reason() {
                Some(r) => info!(peer = %peer, "closed: {r}"),
                None => info!(peer = %peer, "closed"),
            }
        });
    }
    Ok(())
}

/// Closes the connection as soon as the peer stops being admitted. Without this a
/// peer removed in the UI keeps its open connection — and every port on it — until
/// it happens to disconnect, which makes "remove" a lie.
async fn evict_when_revoked(conn: Connection, shared: Arc<Shared>) {
    let peer = conn.remote_id();
    let mut rx = shared.subscribe();
    loop {
        if rx.changed().await.is_err() {
            return; // config channel gone: nothing left to enforce
        }
        if !rx.borrow_and_update().admits(&peer) {
            warn!(peer = %peer, "closing: access revoked");
            conn.close(REFUSED.into(), b"access revoked");
            return;
        }
    }
}

/// Streams and datagrams for one peer, until the connection ends. `serve` outlives
/// any one connection, so everything spawned here is torn down before returning —
/// the session tasks hold the table that holds their abort handles, and that cycle
/// keeps neither end alive on its own.
async fn serve_conn(conn: &Connection, shared: &Arc<Shared>) {
    let sessions = Arc::new(Mutex::new(Sessions::default()));
    let reaper = sessions.clone();
    let pumps = [
        tokio::spawn(pump_udp(conn.clone(), shared.clone(), sessions.clone())).abort_handle(),
        tokio::spawn(evict_when_revoked(conn.clone(), shared.clone())).abort_handle(),
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(crate::UDP_REAP_INTERVAL);
            loop {
                tick.tick().await;
                reaper.lock().unwrap().reap();
            }
        })
        .abort_handle(),
    ];

    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let (shared, peer) = (shared.clone(), conn.remote_id());
                tokio::spawn(async move {
                    if let Err(e) = serve_stream(send, recv, &shared, &peer).await {
                        warn!("stream failed: {e:#}");
                    }
                });
            }
            Err(e) => {
                debug!("stream acceptor stopped: {e}");
                break;
            }
        }
    }

    pumps.iter().for_each(AbortHandle::abort);
    sessions.lock().unwrap().by_id.clear();
}

// ---------------------------------------------------------------- TCP

async fn serve_stream(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    shared: &Arc<Shared>,
    peer: &iroh::EndpointId,
) -> Result<()> {
    let port = proto::read_target_port(&mut recv).await?;
    // Checked per stream against the live config: a port revoked a moment ago is
    // refused even though the connection was authorised when it opened.
    let granted = shared.config().granted(peer, Proto::Tcp).unwrap_or_default();
    if !granted.contains(&port) {
        warn!(port, "refused: tcp port not offered to this peer");
        // Reset both halves so the far side fails at once and its local TCP client
        // sees a closed connection rather than a hang.
        let _ = send.reset(VarInt::from_u32(REFUSED_PORT));
        let _ = recv.stop(VarInt::from_u32(REFUSED_PORT));
        return Ok(());
    }
    info!(port, "stream opened");
    let mut sock = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
    let mut quic = tokio::io::join(recv, send);
    let (down, up) = tokio::io::copy_bidirectional(&mut quic, &mut sock).await?;
    debug!(port, up, down, "stream closed");
    Ok(())
}

// ---------------------------------------------------------------- UDP

/// The serving side keys sessions by the id the connecting side minted, and gives
/// each one its own socket so the local service sees a distinct source per session.
#[derive(Default)]
struct Sessions {
    by_id: HashMap<u32, Session>,
}

struct Session {
    sock: Arc<UdpSocket>,
    reply: AbortHandle,
    last: Instant,
    port: u16,
}

/// Dropping the entry is what releases the kernel socket: the reply task holds the
/// other handle to it, so the table shrinking alone would free nothing.
impl Drop for Session {
    fn drop(&mut self) {
        self.reply.abort();
    }
}

impl Sessions {
    fn touch(&mut self, id: u32) -> Option<Arc<UdpSocket>> {
        let s = self.by_id.get_mut(&id)?;
        s.last = Instant::now();
        Some(s.sock.clone())
    }

    fn reap(&mut self) {
        let before = self.by_id.len();
        self.by_id.retain(|_, s| s.last.elapsed() < crate::UDP_IDLE);
        if self.by_id.len() != before {
            info!(
                sessions = self.by_id.len(),
                reaped = before - self.by_id.len(),
                "udp sessions reaped"
            );
        }
    }

    /// Drops sessions whose port is no longer granted. A UDP session holds an open
    /// socket to the local service, so revoking a port has to close it rather than
    /// wait out the idle timer.
    fn drop_ungranted(&mut self, granted: &[u16]) {
        let before = self.by_id.len();
        self.by_id.retain(|_, s| granted.contains(&s.port));
        if self.by_id.len() != before {
            warn!(
                closed = before - self.by_id.len(),
                "udp sessions closed: port no longer offered"
            );
        }
    }
}

async fn pump_udp(conn: Connection, shared: Arc<Shared>, sessions: Arc<Mutex<Sessions>>) {
    let peer = conn.remote_id();
    let mut cfg_rx = shared.subscribe();
    loop {
        let dg: Bytes = tokio::select! {
            r = conn.read_datagram() => match r {
                Ok(dg) => dg,
                Err(e) => return debug!("datagram reader stopped: {e}"),
            },
            // A config change closes sessions for ports that just lost their grant,
            // then goes back to reading.
            changed = cfg_rx.changed() => {
                if changed.is_err() {
                    return;
                }
                let granted = cfg_rx.borrow_and_update().granted(&peer, Proto::Udp).unwrap_or_default();
                sessions.lock().unwrap().drop_ungranted(&granted);
                continue;
            }
        };
        let Some((id, port, payload)) = proto::decode_datagram(&dg) else {
            warn!(bytes = dg.len(), "dropped datagram: shorter than the header");
            continue;
        };
        if !shared.config().granted(&peer, Proto::Udp).unwrap_or_default().contains(&port) {
            warn!(port, session = id, "refused: udp port not offered to this peer");
            continue;
        }
        // Bound out of the match: the guard must not be alive across the awaits.
        let known = sessions.lock().unwrap().touch(id);
        let sock = match known {
            Some(s) => Some(s),
            None => match open_session(&conn, &sessions, id, port).await {
                Ok(s) => Some(s),
                Err(e) => {
                    warn!(port, session = id, "opening udp session failed: {e:#}");
                    None
                }
            },
        };
        if let Some(sock) = sock
            && let Err(e) = sock.send(&payload).await
        {
            warn!(port, session = id, "undeliverable to the local service: {e:#}");
        }
    }
}

async fn open_session(
    conn: &Connection,
    sessions: &Arc<Mutex<Sessions>>,
    id: u32,
    port: u16,
) -> Result<Arc<UdpSocket>> {
    let sock = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
    // Connected, so replies from anything but the target port are refused by the
    // kernel and `recv` needs no address check of its own.
    sock.connect((Ipv4Addr::LOCALHOST, port)).await?;
    let reply = tokio::spawn(pump_replies(conn.clone(), sock.clone(), sessions.clone(), id, port))
        .abort_handle();
    let mut t = sessions.lock().unwrap();
    t.by_id.insert(id, Session { sock: sock.clone(), reply, last: Instant::now(), port });
    info!(sessions = t.by_id.len(), session = id, port, local = ?sock.local_addr().ok(), "udp session opened");
    Ok(sock)
}

async fn pump_replies(
    conn: Connection,
    sock: Arc<UdpSocket>,
    sessions: Arc<Mutex<Sessions>>,
    id: u32,
    port: u16,
) {
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        let n = match sock.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => return debug!(session = id, "udp session recv stopped: {e}"),
        };
        sessions.lock().unwrap().touch(id);
        if let Err(e) = conn.send_datagram(proto::encode_datagram(id, port, &buf[..n])) {
            warn!(session = id, bytes = n, "dropped datagram: {e}");
        }
    }
}
