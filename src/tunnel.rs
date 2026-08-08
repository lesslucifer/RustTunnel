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

use crate::{ALPN, PortMap, serve::Offered};

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
    let server = local_endpoint(vec![ALPN.to_vec()]).await;
    let client = local_endpoint(vec![]).await;
    let server_addr = addr_of(&server);
    let client_id = client.id();
    tokio::spawn(crate::serve::run(server, vec![client_id], offered));
    tokio::spawn(crate::connect::run(client, server_addr, tcp, udp));
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

    tokio::spawn(crate::serve::run(server, vec![allowed.id()], Offered {
        tcp: vec![],
        udp: vec![],
    }));

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
