//! The machine offering ports: accepts connections, checks the peer allowlist.

use anyhow::Result;
use iroh::{Endpoint, EndpointId};
use tracing::{info, warn};

/// Application close code for a peer that is not in `--allow`.
const REFUSED: u32 = 1;

pub async fn run(ep: Endpoint, allow: Vec<EndpointId>) -> Result<()> {
    println!("endpoint id {}", ep.id());
    info!(id = %ep.id(), allowed = allow.len(), "serving");

    while let Some(incoming) = ep.accept().await {
        let allow = allow.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => return warn!("handshake failed: {e:#}"),
            };
            let peer = conn.remote_id();
            // The handshake proved the peer holds this key; the allowlist decides
            // whether that key may in. Refusing here is the whole of P1.3.
            if !allow.contains(&peer) {
                warn!(peer = %peer, "refused: endpoint id not in --allow");
                conn.close(REFUSED.into(), b"not in --allow");
                return;
            }
            info!(peer = %peer, "admitted");
            crate::report_path(&conn);
            // ponytail: nothing to serve until P3 lands the data plane; holding the
            // connection open is what lets the path upgrade be observed.
            let reason = conn.closed().await;
            info!(peer = %peer, "closed: {reason}");
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh::{
        Endpoint, EndpointAddr, SecretKey, TransportAddr,
        endpoint::{ConnectionError, presets},
    };

    use crate::ALPN;

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

    /// P1.3: an unlisted key is turned away, a listed one is let in. A silent
    /// regression here is not a broken feature, it is an open door.
    #[tokio::test]
    async fn allowlist_admits_only_listed_peers() {
        let server = local_endpoint(vec![ALPN.to_vec()]).await;
        let allowed = local_endpoint(vec![]).await;
        let stranger = local_endpoint(vec![]).await;
        let server_addr = addr_of(&server);

        tokio::spawn(super::run(server, vec![allowed.id()]));

        let conn = stranger.connect(server_addr.clone(), ALPN).await.unwrap();
        match tokio::time::timeout(Duration::from_secs(10), conn.closed()).await {
            Ok(ConnectionError::ApplicationClosed(c)) => {
                assert_eq!(c.error_code.into_inner(), super::REFUSED as u64)
            }
            other => panic!("unlisted peer was not refused: {other:?}"),
        }

        let conn = allowed.connect(server_addr, ALPN).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), conn.closed()).await.is_err(),
            "allowlisted peer was refused"
        );
    }
}
