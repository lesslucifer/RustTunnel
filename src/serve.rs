//! The machine offering ports: checks the peer allowlist, then the port allowlist,
//! then makes outbound loopback connections on the peer's behalf.

use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::Result;
use bytes::Bytes;
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, VarInt},
};
use tokio::{
    net::{TcpStream, UdpSocket},
    task::AbortHandle,
};
use tracing::{debug, info, warn};

use crate::proto;

/// Application close code for a peer that is not in `--allow`.
pub(crate) const REFUSED: u32 = 1;
/// Stream reset code for a stream naming a port that was not offered.
const REFUSED_PORT: u32 = 2;
/// Matches [`crate::connect::UDP_BUF`]'s reasoning: receive whole, then judge.
const UDP_BUF: usize = 65_535;

/// The port lists are an allowlist, not a mapping: they state which local ports may
/// be reached at all. Without this one allowlisted peer reaches every loopback port,
/// which is a larger grant than `--tcp 22` looks like.
#[derive(Clone)]
pub struct Offered {
    pub tcp: Vec<u16>,
    pub udp: Vec<u16>,
}

pub async fn run(ep: Endpoint, allow: Vec<EndpointId>, offered: Offered) -> Result<()> {
    println!("endpoint id {}", ep.id());
    info!(id = %ep.id(), allowed = allow.len(), tcp = ?offered.tcp, udp = ?offered.udp, "serving");

    while let Some(incoming) = ep.accept().await {
        let (allow, offered) = (allow.clone(), offered.clone());
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => return warn!("handshake failed: {e:#}"),
            };
            let peer = conn.remote_id();
            // The handshake proved the peer holds this key; the allowlist decides
            // whether that key may in.
            if !allow.contains(&peer) {
                warn!(peer = %peer, "refused: endpoint id not in --allow");
                conn.close(REFUSED.into(), b"not in --allow");
                return;
            }
            info!(peer = %peer, "admitted");
            crate::report_path(&conn);
            serve_conn(&conn, offered).await;
            match conn.close_reason() {
                Some(r) => info!(peer = %peer, "closed: {r}"),
                None => info!(peer = %peer, "closed"),
            }
        });
    }
    Ok(())
}

/// Streams and datagrams for one peer, until the connection ends. `serve` outlives
/// any one connection, so everything spawned here is torn down before returning —
/// the session tasks hold the table that holds their abort handles, and that cycle
/// keeps neither end alive on its own.
async fn serve_conn(conn: &Connection, offered: Offered) {
    let sessions = Arc::new(Mutex::new(Sessions::default()));
    let reaper = sessions.clone();
    let pumps = [
        tokio::spawn(pump_udp(conn.clone(), offered.udp.clone(), sessions.clone())).abort_handle(),
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
                let tcp = offered.tcp.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_stream(send, recv, &tcp).await {
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
    tcp: &[u16],
) -> Result<()> {
    let port = proto::read_target_port(&mut recv).await?;
    if !tcp.contains(&port) {
        warn!(port, "refused: port not in --tcp");
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
}

async fn pump_udp(conn: Connection, udp: Vec<u16>, sessions: Arc<Mutex<Sessions>>) {
    loop {
        let dg: Bytes = match conn.read_datagram().await {
            Ok(dg) => dg,
            Err(e) => return debug!("datagram reader stopped: {e}"),
        };
        let Some((id, port, payload)) = proto::decode_datagram(&dg) else {
            warn!(bytes = dg.len(), "dropped datagram: shorter than the header");
            continue;
        };
        if !udp.contains(&port) {
            warn!(port, session = id, "refused: port not in --udp");
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
    t.by_id.insert(id, Session { sock: sock.clone(), reply, last: Instant::now() });
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
