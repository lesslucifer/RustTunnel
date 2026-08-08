//! Wire framing. Two message shapes and no handshake — the identity layer already
//! authenticated both ends, and the port mapping lives on the connecting side.

use anyhow::Result;
use bytes::Bytes;
use iroh::endpoint::{RecvStream, SendStream};

/// `u32` session id plus `u16` target port, in front of every datagram. The port
/// travels in each one rather than being negotiated once, because a setup message
/// could be the datagram that gets lost.
pub const DATAGRAM_HEADER: usize = 6;

/// A TCP data stream opens with the target port on the serving side.
pub async fn write_target_port(s: &mut SendStream, port: u16) -> Result<()> {
    Ok(s.write_all(&port.to_be_bytes()).await?)
}

pub async fn read_target_port(s: &mut RecvStream) -> Result<u16> {
    let mut b = [0u8; 2];
    s.read_exact(&mut b).await?;
    Ok(u16::from_be_bytes(b))
}

pub fn encode_datagram(session: u32, port: u16, payload: &[u8]) -> Bytes {
    let mut b = Vec::with_capacity(DATAGRAM_HEADER + payload.len());
    b.extend_from_slice(&session.to_be_bytes());
    b.extend_from_slice(&port.to_be_bytes());
    b.extend_from_slice(payload);
    b.into()
}

/// `None` for anything shorter than the header — a truncated datagram has no
/// session to route it to. The payload is a slice of the original, not a copy.
pub fn decode_datagram(dg: &Bytes) -> Option<(u32, u16, Bytes)> {
    if dg.len() < DATAGRAM_HEADER {
        return None;
    }
    let session = u32::from_be_bytes(dg[0..4].try_into().unwrap());
    let port = u16::from_be_bytes(dg[4..6].try_into().unwrap());
    Some((session, port, dg.slice(DATAGRAM_HEADER..)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_round_trips_and_rejects_runts() {
        let dg = encode_datagram(7, 51820, b"payload");
        assert_eq!(decode_datagram(&dg), Some((7, 51820, Bytes::from_static(b"payload"))));
        // an empty payload is legal — a zero-length UDP datagram is a real thing
        assert_eq!(decode_datagram(&encode_datagram(1, 2, b"")).unwrap().2.len(), 0);
        for runt in [0usize, 1, 5] {
            assert!(decode_datagram(&Bytes::from(vec![0u8; runt])).is_none(), "{runt} bytes");
        }
    }
}
