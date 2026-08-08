//! The machine reaching the offered ports: dials by endpoint id.

use anyhow::{Result, anyhow};
use iroh::{Endpoint, EndpointId};
use tracing::info;

pub async fn run(ep: Endpoint, peer: EndpointId) -> Result<()> {
    println!("endpoint id {}", ep.id());
    info!(id = %ep.id(), peer = %peer, "dialing");

    // Dialing by id is mutually authenticated by construction: the QUIC handshake
    // cannot complete against anything but the holder of that key.
    let conn = ep.connect(peer, crate::ALPN).await.map_err(|e| anyhow!("connect: {e:#}"))?;
    crate::report_path(&conn);

    // ponytail: no local listeners until P3; reconnect with backoff is P5. Holding
    // the link is what 2.2 and 2.3 observe.
    let reason = conn.closed().await;
    info!(peer = %peer, "closed: {reason}");
    Ok(())
}
