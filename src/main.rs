//! rtun — forwards TCP and UDP ports between two machines you own, over a
//! direct hole-punched QUIC connection. See docs/implementation-plan.html.

mod connect;
mod serve;

use std::{env, fs, path::PathBuf, str::FromStr};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use iroh::{
    Endpoint, EndpointId, SecretKey,
    endpoint::{Connection, PathEvent, presets},
};
use tokio_stream::StreamExt;
use tracing::info;
use tracing_subscriber::EnvFilter;

pub const ALPN: &[u8] = b"rtun/0";

#[derive(Parser)]
#[command(name = "rtun", version, about = "Forward TCP and UDP ports between two machines you own")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Offer local ports to allowlisted peers
    Serve {
        /// Local TCP port that may be reached through the tunnel (repeatable)
        #[arg(long = "tcp", value_name = "PORT")]
        tcp: Vec<u16>,
        /// Local UDP port that may be reached through the tunnel (repeatable)
        #[arg(long = "udp", value_name = "PORT")]
        udp: Vec<u16>,
        /// Endpoint id permitted to connect (repeatable)
        #[arg(long = "allow", value_name = "ENDPOINT_ID", required = true)]
        allow: Vec<EndpointId>,
        /// Disable direct paths and force traffic through the relay
        #[arg(long)]
        relay_only: bool,
    },
    /// Reach a serving peer's ports on this machine's loopback
    Connect {
        /// Endpoint id of the serving peer
        peer: EndpointId,
        /// TCP port mapping, local:remote (repeatable)
        #[arg(long = "tcp", value_name = "LOCAL:REMOTE")]
        tcp: Vec<PortMap>,
        /// UDP port mapping, local:remote (repeatable)
        #[arg(long = "udp", value_name = "LOCAL:REMOTE")]
        udp: Vec<PortMap>,
        /// Disable direct paths and force traffic through the relay
        #[arg(long)]
        relay_only: bool,
    },
    /// Print this machine's endpoint id and exit
    Id,
}

/// A `local:remote` port mapping on the connecting side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortMap {
    pub local: u16,
    pub remote: u16,
}

impl FromStr for PortMap {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let (l, r) = s
            .split_once(':')
            .with_context(|| format!("`{s}`: expected LOCAL:REMOTE, e.g. 2222:22"))?;
        let parse = |p: &str, which| -> Result<u16> {
            match p.parse::<u16>() {
                Ok(0) | Err(_) => bail!("`{s}`: {which} port must be 1-65535"),
                Ok(n) => Ok(n),
            }
        };
        Ok(PortMap { local: parse(l, "local")?, remote: parse(r, "remote")? })
    }
}

impl std::fmt::Display for PortMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.local, self.remote)
    }
}

/// Where the persisted secret key lives. `RTUN_STATE_DIR` overrides everything,
/// which is also how two roles share one machine during testing; systemd's
/// `StateDirectory=rtun` shows up as `STATE_DIRECTORY`.
fn state_dir() -> Result<PathBuf> {
    for k in ["RTUN_STATE_DIR", "STATE_DIRECTORY"] {
        if let Ok(d) = env::var(k)
            && !d.is_empty()
        {
            return Ok(d.into());
        }
    }
    #[cfg(windows)]
    let base = env::var("APPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base = env::var("HOME").map(|h| PathBuf::from(h).join(".local/state"));
    Ok(base
        .map_err(|_| anyhow!("cannot locate a state directory; set RTUN_STATE_DIR"))?
        .join("rtun"))
}

/// The endpoint's identity *is* its keypair, so it is generated once and kept.
/// Regenerating it on every start would silently invalidate every peer's allowlist.
fn load_or_create_key() -> Result<SecretKey> {
    let dir = state_dir()?;
    let path = dir.join("secret.key");
    match fs::read(&path) {
        Ok(bytes) => {
            let bytes: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                anyhow!("{}: not a 32-byte key; delete it to regenerate", path.display())
            })?;
            Ok(SecretKey::from_bytes(&bytes))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(&dir)
                .with_context(|| format!("creating {}", dir.display()))?;
            let key = SecretKey::generate();
            write_key(&path, &key)?;
            info!(path = %path.display(), "generated a new endpoint key");
            Ok(key)
        }
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

#[cfg(unix)]
fn write_key(path: &std::path::Path, key: &SecretKey) -> Result<()> {
    use std::{fs::Permissions, io::Write, os::unix::fs::{OpenOptionsExt, PermissionsExt}};
    // Created 0600 rather than chmod'ed afterwards, so the key is never
    // world-readable for even an instant.
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(&key.to_bytes())?;
    let _ = fs::set_permissions(path.parent().unwrap(), Permissions::from_mode(0o700));
    Ok(())
}

#[cfg(not(unix))]
fn write_key(path: &std::path::Path, key: &SecretKey) -> Result<()> {
    // ponytail: Windows inherits the user profile ACL, which is already
    // owner-only. Add an explicit DACL if rtun ever runs as a shared service.
    fs::write(path, key.to_bytes()).with_context(|| format!("creating {}", path.display()))
}

pub async fn bind_endpoint(relay_only: bool, alpns: Vec<Vec<u8>>) -> Result<Endpoint> {
    let mut b = Endpoint::builder(presets::N0).secret_key(load_or_create_key()?).alpns(alpns);
    if relay_only {
        // Dropping the IP transports leaves only the relay, which is how the
        // relayed path is exercised on demand rather than by finding a bad network.
        b = b.clear_ip_transports();
    }
    b.bind().await.map_err(|e| anyhow!("binding endpoint: {e:#}"))
}

fn path_kind(addr: &iroh::TransportAddr) -> &'static str {
    if addr.is_relay() { "relayed" } else { "direct" }
}

/// How often a held connection restates its path. Slow enough to be quiet, often
/// enough that a log answers "was it still direct at 03:00" without inference.
const PATH_HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(60);

fn log_selected(conn: &Connection, msg: &'static str) {
    let peer = conn.remote_id().fmt_short();
    let paths = conn.paths();
    match paths.iter().find(|p| p.is_selected()) {
        Some(p) => {
            info!(peer = %peer, path = %path_kind(p.remote_addr()), addr = %p.remote_addr(), rtt = ?p.rtt(), "{msg}")
        }
        None => info!(peer = %peer, path = "pending", "{msg}"),
    }
}

/// Logs the path on establishment, on every upgrade, and once a minute while the
/// connection is held. Direct versus relayed is the single most useful diagnostic
/// this tool has.
pub fn report_path(conn: &Connection) {
    log_selected(conn, "established");
    let conn = conn.clone();
    tokio::spawn(async move {
        let mut events = conn.path_events();
        let mut tick = tokio::time::interval(PATH_HEARTBEAT);
        tick.tick().await; // the first tick is immediate; establishment already logged
        loop {
            tokio::select! {
                ev = events.next() => match ev {
                    Some(PathEvent::Selected { remote_addr, .. }) => {
                        info!(peer = %conn.remote_id().fmt_short(), path = %path_kind(&remote_addr), addr = %remote_addr, "path selected")
                    }
                    Some(_) => {}
                    None => break, // connection closed
                },
                _ = tick.tick() => log_selected(&conn, "still up"),
            }
        }
    });
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        // Logs on stderr, so `rtun id` stdout stays a bare id that a script can
        // capture. Colour codes in a redirected evidence file are noise.
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            EnvFilter::try_from_env("RTUN_LOG").unwrap_or_else(|_| EnvFilter::new("rtun=info")),
        )
        .init();

    match Cli::parse().cmd {
        Cmd::Id => {
            println!("{}", load_or_create_key()?.public());
            Ok(())
        }
        Cmd::Serve { tcp, udp, allow, relay_only } => {
            let ep = bind_endpoint(relay_only, vec![ALPN.to_vec()]).await?;
            // ponytail: the port lists are the serve-side allowlist; they are
            // enforced once there is a data plane to enforce them on (P3/P4).
            info!(?tcp, ?udp, "offered ports");
            serve::run(ep, allow).await
        }
        Cmd::Connect { peer, tcp, udp, relay_only } => {
            let ep = bind_endpoint(relay_only, vec![]).await?;
            info!(
                tcp = ?tcp.iter().map(|m| m.to_string()).collect::<Vec<_>>(),
                udp = ?udp.iter().map(|m| m.to_string()).collect::<Vec<_>>(),
                "port mappings"
            );
            connect::run(ep, peer).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_map_parses_and_rejects_junk() {
        assert_eq!("2222:22".parse::<PortMap>().unwrap(), PortMap { local: 2222, remote: 22 });
        for bad in ["2222", "2222:", ":22", "0:22", "2222:0", "a:22", "70000:22", "2222:22:22"] {
            assert!(bad.parse::<PortMap>().is_err(), "{bad} should not parse");
        }
    }
}
