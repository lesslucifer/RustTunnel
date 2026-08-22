//! The one check: both roles in-process on loopback with ephemeral keys, exercised
//! against throwaway echo services. Enough to fail loudly if the framing, session
//! mapping, stream routing or either allowlist breaks. No fixtures, no mocks.
//!
//! What it deliberately does not cover is hole punching — on loopback there is
//! nothing to punch. That is P2.2, on real networks, by hand.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use iroh::{
    Endpoint, EndpointAddr, SecretKey, TransportAddr,
    endpoint::{ConnectionError, presets},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

use crate::{
    ALPN, PortMap,
    config::{Binding, Config, Offer, Peer, Proto},
    state::{BindState, Role, Shared},
};

/// The port allowlist the serving side used to take as a struct. Kept as a test
/// shape so these checks still read as "these ports are offered".
pub struct Offered {
    pub tcp: Vec<u16>,
    pub udp: Vec<u16>,
}

/// Config-backed `Shared` for a test, written to a throwaway path. Nothing here
/// touches a real state directory, and `mutate` is never called, so the file is
/// only ever a destination the code under test could write to.
fn shared_serve(allow: &[iroh::EndpointId], offered: &Offered) -> std::sync::Arc<Shared> {
    let mut cfg = Config::default();
    cfg.serve.shared = offered
        .tcp
        .iter()
        .map(|p| Offer { proto: Proto::Tcp, port: *p, name: String::new(), enabled: true })
        .chain(offered.udp.iter().map(|p| Offer {
            proto: Proto::Udp,
            port: *p,
            name: String::new(),
            enabled: true,
        }))
        .collect();
    cfg.serve.peers = allow
        .iter()
        .map(|id| Peer { id: *id, name: String::new(), enabled: true, offers: vec![] })
        .collect();
    Shared::new(cfg, temp_config_path(), Role::Serve)
}

fn shared_connect(tcp: &[PortMap], udp: &[PortMap]) -> std::sync::Arc<Shared> {
    let mut cfg = Config::default();
    cfg.connect.bindings = tcp
        .iter()
        .map(|m| Binding {
            proto: Proto::Tcp,
            local: m.local,
            remote: m.remote,
            name: String::new(),
            enabled: true,
        })
        .chain(udp.iter().map(|m| Binding {
            proto: Proto::Udp,
            local: m.local,
            remote: m.remote,
            name: String::new(),
            enabled: true,
        }))
        .collect();
    Shared::new(cfg, temp_config_path(), Role::Connect)
}

fn temp_config_path() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("rtun-tunnel-test-{}-{}.toml", std::process::id(), rand::random::<u64>()));
    p
}

const LOCAL: (Ipv4Addr, u16) = (Ipv4Addr::LOCALHOST, 0);
/// Every assertion is bounded, so a regression is a failure rather than a hang.
const PATIENCE: Duration = Duration::from_secs(10);

/// Loopback-only endpoint: no relay, no discovery, no network.
async fn local_endpoint(alpns: Vec<Vec<u8>>) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .alpns(alpns)
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap()
}

fn addr_of(ep: &Endpoint) -> EndpointAddr {
    EndpointAddr::from_parts(ep.id(), ep.bound_sockets().into_iter().map(TransportAddr::Ip))
}

/// Both roles, wired to each other, with the connecting side's key allowlisted.
async fn tunnel(offered: Offered, tcp: Vec<PortMap>, udp: Vec<PortMap>) {
    live_tunnel(offered, tcp, udp).await;
}

/// The same wiring, but handing back both roles' live state so a test can change
/// the configuration of a running tunnel — which is the whole point of the
/// dynamic feature and cannot be checked any other way.
struct Live {
    serve: std::sync::Arc<Shared>,
    connect: std::sync::Arc<Shared>,
    client_id: iroh::EndpointId,
}

async fn live_tunnel(offered: Offered, tcp: Vec<PortMap>, udp: Vec<PortMap>) -> Live {
    let server = local_endpoint(vec![ALPN.to_vec()]).await;
    let client = local_endpoint(vec![]).await;
    let server_addr = addr_of(&server);
    let client_id = client.id();
    let sv = shared_serve(&[client_id], &offered);
    let cn = shared_connect(&tcp, &udp);
    tokio::spawn(crate::serve::run(server, sv.clone()));
    tokio::spawn(crate::connect::run(client, server_addr, cn.clone()));
    Live { serve: sv, connect: cn, client_id }
}

/// Polls a condition to a deadline. The control plane is asynchronous — an edit
/// propagates through a watch channel and a socket bind — so a test asserts
/// "becomes true", never "is true one instant later".
async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    while tokio::time::Instant::now() < deadline {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("{what} did not happen within {PATIENCE:?}");
}

/// An ephemeral port, released immediately so a listener can claim it. Racy in
/// principle; the alternative is fixed numbers that collide between tests that
/// cargo runs concurrently.
async fn free_tcp_port() -> u16 {
    TcpListener::bind(LOCAL).await.unwrap().local_addr().unwrap().port()
}

async fn free_udp_port() -> u16 {
    UdpSocket::bind(LOCAL).await.unwrap().local_addr().unwrap().port()
}

async fn tcp_echo() -> u16 {
    let l = TcpListener::bind(LOCAL).await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

async fn udp_echo() -> u16 {
    let s = UdpSocket::bind(LOCAL).await.unwrap();
    let port = s.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok((n, from)) = s.recv_from(&mut buf).await {
            let _ = s.send_to(&buf[..n], from).await;
        }
    });
    port
}

/// Connect, send, half-close, read to EOF. The write shutdown is the point: the
/// reply can only arrive if the FIN crossed the tunnel, reached the echo service
/// and its own close came back — which is the clean-close half of P3.3.
async fn round_trip(port: u16, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut sock = retry_connect(port).await;
    sock.write_all(payload).await?;
    sock.shutdown().await?;
    let mut got = Vec::new();
    sock.read_to_end(&mut got).await?;
    Ok(got)
}

/// The listener is bound before the dial, but both happen in a spawned task, so the
/// test can win the race on the first attempt.
async fn retry_connect(port: u16) -> TcpStream {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        match TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await {
            Ok(s) => return s,
            Err(e) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
                let _ = e;
            }
            Err(e) => panic!("nothing listening on 127.0.0.1:{port} after {PATIENCE:?}: {e}"),
        }
    }
}

/// Byte-exact TCP round trip through the tunnel.
#[tokio::test]
async fn tcp_round_trip_is_byte_exact() {
    let remote = tcp_echo().await;
    let local = free_tcp_port().await;
    tunnel(Offered { tcp: vec![remote], udp: vec![] }, vec![PortMap { local, remote }], vec![]).await;

    let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    let got = tokio::time::timeout(PATIENCE, round_trip(local, &payload)).await.unwrap().unwrap();
    assert_eq!(got, payload, "payload did not survive the tunnel");
}

/// Two simultaneous connections stay independent. Distinct fill bytes *and*
/// distinct lengths, so neither a swap nor a partial cross can look like a pass.
#[tokio::test]
async fn concurrent_tcp_connections_do_not_interleave() {
    let remote = tcp_echo().await;
    let local = free_tcp_port().await;
    tunnel(Offered { tcp: vec![remote], udp: vec![] }, vec![PortMap { local, remote }], vec![]).await;

    let red = vec![0xA5u8; 64 * 1024];
    let blue = vec![0x5Au8; 48 * 1024];
    let (a, b) = tokio::time::timeout(PATIENCE, async {
        tokio::join!(round_trip(local, &red), round_trip(local, &blue))
    })
    .await
    .unwrap();
    assert_eq!(a.unwrap(), red, "red stream came back wrong");
    assert_eq!(b.unwrap(), blue, "blue stream came back wrong");
}

/// A datagram round trip, and — the part the session table exists for — each reply
/// reaching the local source that sent it rather than the other one.
#[tokio::test]
async fn udp_replies_reach_the_correct_local_source() {
    let remote = udp_echo().await;
    let local = free_udp_port().await;
    tunnel(Offered { tcp: vec![], udp: vec![remote] }, vec![], vec![PortMap { local, remote }]).await;

    let target: SocketAddr = (Ipv4Addr::LOCALHOST, local).into();
    let one = UdpSocket::bind(LOCAL).await.unwrap();
    let two = UdpSocket::bind(LOCAL).await.unwrap();
    let mut buf = [0u8; 64];

    // Retried because the far listener may still be coming up and UDP will not
    // tell us so — which is also true of the protocols this carries.
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        one.send_to(b"one", target).await.unwrap();
        two.send_to(b"two", target).await.unwrap();
        let a = tokio::time::timeout(Duration::from_millis(500), one.recv(&mut buf)).await;
        if let Ok(Ok(n)) = a {
            assert_eq!(&buf[..n], b"one", "reply went to the wrong local source");
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "no datagram came back within {PATIENCE:?}");
    }
    let n = tokio::time::timeout(PATIENCE, two.recv(&mut buf)).await.unwrap().unwrap();
    assert_eq!(&buf[..n], b"two", "reply went to the wrong local source");
}

/// P1.3: an unlisted key is turned away, a listed one is let in. A silent
/// regression here is not a broken feature, it is an open door.
#[tokio::test]
async fn allowlist_admits_only_listed_peers() {
    let server = local_endpoint(vec![ALPN.to_vec()]).await;
    let allowed = local_endpoint(vec![]).await;
    let stranger = local_endpoint(vec![]).await;
    let server_addr = addr_of(&server);

    tokio::spawn(crate::serve::run(
        server,
        shared_serve(&[allowed.id()], &Offered { tcp: vec![], udp: vec![] }),
    ));

    let conn = stranger.connect(server_addr.clone(), ALPN).await.unwrap();
    match tokio::time::timeout(PATIENCE, conn.closed()).await {
        Ok(ConnectionError::ApplicationClosed(c)) => {
            assert_eq!(c.error_code.into_inner(), crate::serve::REFUSED as u64)
        }
        other => panic!("unlisted peer was not refused: {other:?}"),
    }

    let conn = allowed.connect(server_addr, ALPN).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), conn.closed()).await.is_err(),
        "allowlisted peer was refused"
    );
}

/// P5.1's other half: a refusal is terminal. Now that `connect` retries a lost
/// link forever, it must still give up — with an error, so the exit status is
/// non-zero — when the allowlist turns it away. Otherwise the retry loop hammers
/// a permanent answer for as long as the process lives.
#[tokio::test]
async fn a_refused_connect_gives_up_instead_of_retrying() {
    let server = local_endpoint(vec![ALPN.to_vec()]).await;
    let someone_else = local_endpoint(vec![]).await;
    let stranger = local_endpoint(vec![]).await;
    let server_addr = addr_of(&server);
    tokio::spawn(crate::serve::run(
        server,
        shared_serve(&[someone_else.id()], &Offered { tcp: vec![], udp: vec![] }),
    ));

    let gave_up =
        tokio::time::timeout(PATIENCE, crate::connect::run(stranger, server_addr, shared_connect(&[], &[])))
            .await;
    assert!(matches!(gave_up, Ok(Err(_))), "a refused connect must not retry: {gave_up:?}");
}

/// The other open door: an admitted peer naming a port the serving side never
/// offered. Without this, `--tcp 22` grants every port on the loopback interface.
#[tokio::test]
async fn unoffered_tcp_port_is_refused() {
    // Two live echo services, one of them offered. Pointing the mapping at a dead
    // port would pass whether or not the check exists — the refused port has to be
    // one that would answer if the stream ever reached it.
    let offered = tcp_echo().await;
    let unoffered = tcp_echo().await;
    let local = free_tcp_port().await;
    tunnel(
        Offered { tcp: vec![offered], udp: vec![] },
        vec![PortMap { local, remote: unoffered }],
        vec![],
    )
    .await;

    let got = tokio::time::timeout(PATIENCE, round_trip(local, b"knock knock")).await.unwrap();
    assert!(
        matches!(&got, Ok(v) if v.is_empty()) || got.is_err(),
        "an unoffered port answered: {got:?}"
    );
}

// ------------------------------------------------- dynamic reconfiguration

/// A port added to a *running* server becomes reachable without a restart. This
/// is the core promise of the feature: before the edit the stream is refused,
/// after it the same mapping carries bytes.
#[tokio::test]
async fn offering_a_port_at_runtime_makes_it_reachable() {
    let remote = tcp_echo().await;
    let local = free_tcp_port().await;
    // Nothing offered yet, but the mapping exists on the connecting side.
    let live =
        live_tunnel(Offered { tcp: vec![], udp: vec![] }, vec![PortMap { local, remote }], vec![])
            .await;

    // Refused while unoffered: an empty read or a reset, never echoed bytes.
    let before = tokio::time::timeout(PATIENCE, round_trip(local, b"before")).await.unwrap();
    assert!(
        matches!(&before, Ok(v) if v.is_empty()) || before.is_err(),
        "an unoffered port answered: {before:?}"
    );

    live.serve
        .mutate(|c| {
            c.serve.shared.push(Offer {
                proto: Proto::Tcp,
                port: remote,
                name: "added live".into(),
                enabled: true,
            });
            Ok(())
        })
        .unwrap();

    // Now the very same mapping works, with no restart of either side.
    let got = tokio::time::timeout(PATIENCE, round_trip(local, b"after")).await.unwrap().unwrap();
    assert_eq!(got, b"after", "a port offered at runtime did not carry traffic");
}

/// Withdrawing a port stops new streams on a connection that stays up. Without
/// this, "remove" would only take effect on the next reconnect.
#[tokio::test]
async fn withdrawing_a_port_at_runtime_refuses_new_streams() {
    let remote = tcp_echo().await;
    let local = free_tcp_port().await;
    let live = live_tunnel(
        Offered { tcp: vec![remote], udp: vec![] },
        vec![PortMap { local, remote }],
        vec![],
    )
    .await;

    let got = tokio::time::timeout(PATIENCE, round_trip(local, b"hello")).await.unwrap().unwrap();
    assert_eq!(got, b"hello", "the tunnel did not work before the withdrawal");

    live.serve
        .mutate(|c| {
            c.serve.shared.retain(|o| o.port != remote);
            Ok(())
        })
        .unwrap();

    // Polled: the connection is already open, so the refusal appears as soon as
    // the next stream is judged against the new config.
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        let r = tokio::time::timeout(PATIENCE, round_trip(local, b"knock")).await.unwrap();
        if matches!(&r, Ok(v) if v.is_empty()) || r.is_err() {
            break; // refused, as it must be
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "a withdrawn port still carried traffic after {PATIENCE:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Revoking a peer closes the connection it is already holding. A peer that keeps
/// its authorised connection after removal is an open door.
#[tokio::test]
async fn revoking_a_peer_closes_its_live_connection() {
    let server = local_endpoint(vec![ALPN.to_vec()]).await;
    let client = local_endpoint(vec![]).await;
    let server_addr = addr_of(&server);
    let client_id = client.id();
    let sv = shared_serve(&[client_id], &Offered { tcp: vec![], udp: vec![] });
    tokio::spawn(crate::serve::run(server, sv.clone()));

    let conn = client.connect(server_addr, ALPN).await.unwrap();
    // Admitted: the connection stays up while the peer is allowlisted.
    assert!(
        tokio::time::timeout(Duration::from_secs(2), conn.closed()).await.is_err(),
        "an allowlisted peer was refused"
    );

    sv.mutate(|c| {
        c.serve.peers.retain(|p| p.id != client_id);
        Ok(())
    })
    .unwrap();

    match tokio::time::timeout(PATIENCE, conn.closed()).await {
        Ok(ConnectionError::ApplicationClosed(c)) => {
            assert_eq!(c.error_code.into_inner(), crate::serve::REFUSED as u64)
        }
        other => panic!("a revoked peer kept its connection: {other:?}"),
    }
}

/// Disabling a peer, rather than removing it, also closes the connection — a
/// parked entry is a remembered name, not a standing grant.
#[tokio::test]
async fn disabling_a_peer_closes_its_live_connection() {
    let server = local_endpoint(vec![ALPN.to_vec()]).await;
    let client = local_endpoint(vec![]).await;
    let server_addr = addr_of(&server);
    let client_id = client.id();
    let sv = shared_serve(&[client_id], &Offered { tcp: vec![], udp: vec![] });
    tokio::spawn(crate::serve::run(server, sv.clone()));

    let conn = client.connect(server_addr, ALPN).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(2), conn.closed()).await.is_err());

    sv.mutate(|c| {
        c.serve.peers[0].enabled = false;
        Ok(())
    })
    .unwrap();

    assert!(
        matches!(
            tokio::time::timeout(PATIENCE, conn.closed()).await,
            Ok(ConnectionError::ApplicationClosed(_))
        ),
        "a disabled peer kept its connection"
    );
}

/// A binding added on the connecting side binds its local port and forwards
/// through the existing QUIC connection, with no restart and no disturbance to
/// the binding that was already there.
#[tokio::test]
async fn adding_a_binding_at_runtime_binds_and_forwards() {
    let remote = tcp_echo().await;
    let first_local = free_tcp_port().await;
    let later_local = free_tcp_port().await;
    let live = live_tunnel(
        Offered { tcp: vec![remote], udp: vec![] },
        vec![PortMap { local: first_local, remote }],
        vec![],
    )
    .await;

    // The pre-existing binding works.
    let got =
        tokio::time::timeout(PATIENCE, round_trip(first_local, b"one")).await.unwrap().unwrap();
    assert_eq!(got, b"one");
    // Nothing is listening on the port we have not bound yet.
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, later_local)).await.is_err(),
        "something was already listening on the port under test"
    );

    live.connect
        .mutate(|c| {
            c.connect.bindings.push(Binding {
                proto: Proto::Tcp,
                local: later_local,
                remote,
                name: "added live".into(),
                enabled: true,
            });
            Ok(())
        })
        .unwrap();

    let got =
        tokio::time::timeout(PATIENCE, round_trip(later_local, b"two")).await.unwrap().unwrap();
    assert_eq!(got, b"two", "a binding added at runtime did not forward");
    // And the original binding still works: reconciling must not disturb it.
    let got =
        tokio::time::timeout(PATIENCE, round_trip(first_local, b"three")).await.unwrap().unwrap();
    assert_eq!(got, b"three", "reconciling broke an existing binding");
}

/// Removing a binding releases the local port, so the socket is actually closed
/// rather than merely ignored.
#[tokio::test]
async fn removing_a_binding_releases_the_local_port() {
    let remote = tcp_echo().await;
    let local = free_tcp_port().await;
    let live = live_tunnel(
        Offered { tcp: vec![remote], udp: vec![] },
        vec![PortMap { local, remote }],
        vec![],
    )
    .await;

    let got = tokio::time::timeout(PATIENCE, round_trip(local, b"hi")).await.unwrap().unwrap();
    assert_eq!(got, b"hi");
    assert_eq!(
        live.connect.bind_state(&Binding {
            proto: Proto::Tcp,
            local,
            remote,
            name: String::new(),
            enabled: true,
        }),
        Some(BindState::Listening),
        "a working binding should report itself as listening"
    );

    live.connect
        .mutate(|c| {
            c.connect.bindings.clear();
            Ok(())
        })
        .unwrap();

    // The port is free again once the listener is dropped — provable by binding it.
    eventually("the released port became bindable", || {
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, local)).is_ok()
    })
    .await;
    let _ = live.client_id;
}

/// Disabling a binding parks it without losing the row, and re-enabling it binds
/// again. This is the "toggle" the UI offers, end to end.
#[tokio::test]
async fn a_binding_can_be_parked_and_restored() {
    let remote = tcp_echo().await;
    let local = free_tcp_port().await;
    let live = live_tunnel(
        Offered { tcp: vec![remote], udp: vec![] },
        vec![PortMap { local, remote }],
        vec![],
    )
    .await;
    let got = tokio::time::timeout(PATIENCE, round_trip(local, b"up")).await.unwrap().unwrap();
    assert_eq!(got, b"up");

    live.connect
        .mutate(|c| {
            c.connect.bindings[0].enabled = false;
            Ok(())
        })
        .unwrap();
    eventually("the parked port was released", || {
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, local)).is_ok()
    })
    .await;
    // The row survives being parked, so its label and mapping are not lost.
    assert_eq!(live.connect.config().connect.bindings.len(), 1);

    live.connect
        .mutate(|c| {
            c.connect.bindings[0].enabled = true;
            Ok(())
        })
        .unwrap();
    let got = tokio::time::timeout(PATIENCE, round_trip(local, b"again")).await.unwrap().unwrap();
    assert_eq!(got, b"again", "a re-enabled binding did not forward");
}

/// Per-peer grants are per peer: a port on one peer's list must not become
/// reachable by another. Two clients, one grant.
#[tokio::test]
async fn a_per_peer_grant_does_not_leak_to_another_peer() {
    let remote = tcp_echo().await;
    let granted_local = free_tcp_port().await;
    let other_local = free_tcp_port().await;

    let server = local_endpoint(vec![ALPN.to_vec()]).await;
    let granted = local_endpoint(vec![]).await;
    let other = local_endpoint(vec![]).await;
    let server_addr = addr_of(&server);

    // Both peers are admitted; only the first is granted the port.
    let mut cfg = Config::default();
    cfg.serve.peers = vec![
        Peer {
            id: granted.id(),
            name: "granted".into(),
            enabled: true,
            offers: vec![Offer {
                proto: Proto::Tcp,
                port: remote,
                name: String::new(),
                enabled: true,
            }],
        },
        Peer { id: other.id(), name: "other".into(), enabled: true, offers: vec![] },
    ];
    let sv = Shared::new(cfg, temp_config_path(), Role::Serve);
    tokio::spawn(crate::serve::run(server, sv));
    tokio::spawn(crate::connect::run(
        granted,
        server_addr.clone(),
        shared_connect(&[PortMap { local: granted_local, remote }], &[]),
    ));
    tokio::spawn(crate::connect::run(
        other,
        server_addr,
        shared_connect(&[PortMap { local: other_local, remote }], &[]),
    ));

    let ok = tokio::time::timeout(PATIENCE, round_trip(granted_local, b"mine")).await.unwrap();
    assert_eq!(ok.unwrap(), b"mine", "the granted peer could not reach its own port");

    let leaked = tokio::time::timeout(PATIENCE, round_trip(other_local, b"theirs")).await.unwrap();
    assert!(
        matches!(&leaked, Ok(v) if v.is_empty()) || leaked.is_err(),
        "a per-peer grant leaked to another peer: {leaked:?}"
    );
}
