//! The persisted, hand-editable source of truth for both roles' allowlists.
//!
//! Everything the admin UI mutates lands here and is written back atomically, so
//! a change survives a restart and `cat config.toml` explains the running state.
//! CLI flags seed this file on first run and are otherwise a one-shot override —
//! see [`Config::seed_from_flags`].

use std::{
    collections::BTreeMap,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

use crate::PortMap;

/// A human label attached to an allowlist entry. Names are what make a list of
/// 64-character hex keys reviewable a month later, so the UI requires one.
pub const NAME_MAX: usize = 64;

/// TCP or UDP. Kept as an enum rather than a bool so log lines, JSON and the UI
/// all say "tcp"/"udp" without a stringly-typed conversion at each boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

impl std::fmt::Display for Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Proto {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" => Ok(Proto::Tcp),
            "udp" => Ok(Proto::Udp),
            other => bail!("`{other}`: expected tcp or udp"),
        }
    }
}

/// One offered local port on the serving side. `port` is the loopback port that
/// may be reached; `enabled` is how the UI parks a grant without losing its name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    pub proto: Proto,
    pub port: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

/// One allowlisted peer, plus the ports granted to that peer alone. An empty
/// `offers` list means the peer gets only what [`ServeConfig::shared`] grants,
/// which is how "one list for everyone" is expressed in a per-peer model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub id: EndpointId,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub offers: Vec<Offer>,
}

/// One local listener on the connecting side. `local` is bound on this machine's
/// loopback and forwarded to `remote` on the serving peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub proto: Proto,
    pub local: u16,
    pub remote: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

impl Binding {
    pub fn map(&self) -> PortMap {
        PortMap { local: self.local, remote: self.remote }
    }
}

fn yes() -> bool {
    true
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServeConfig {
    /// Ports every enabled peer may reach. Kept separate from per-peer offers so
    /// revoking one peer's extra grant cannot silently revoke the common ones.
    pub shared: Vec<Offer>,
    pub peers: Vec<Peer>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectConfig {
    pub bindings: Vec<Binding>,
}

/// The whole file. `serve` and `connect` sections coexist so one machine running
/// both roles keeps one config, and the admin UI shows whichever role is running.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub serve: ServeConfig,
    pub connect: ConnectConfig,
}

// ---------------------------------------------------------------- validation

fn check_name(name: &str) -> Result<()> {
    if name.chars().count() > NAME_MAX {
        bail!("name is longer than {NAME_MAX} characters");
    }
    // Control characters would corrupt a log line or the UI; a name is a label,
    // not a payload.
    if name.chars().any(char::is_control) {
        bail!("name must not contain control characters");
    }
    Ok(())
}

fn check_port(port: u16, which: &str) -> Result<()> {
    if port == 0 {
        bail!("{which} port must be 1-65535");
    }
    Ok(())
}

impl Offer {
    pub fn validate(&self) -> Result<()> {
        check_port(self.port, "offered")?;
        check_name(&self.name)
    }
}

impl Binding {
    pub fn validate(&self) -> Result<()> {
        check_port(self.local, "local")?;
        check_port(self.remote, "remote")?;
        check_name(&self.name)
    }
}

impl Peer {
    pub fn validate(&self) -> Result<()> {
        check_name(&self.name)?;
        for o in &self.offers {
            o.validate()?;
        }
        dedupe_offers(&self.offers).with_context(|| format!("peer {}", self.id.fmt_short()))
    }

    /// Every port this peer may reach, given the shared set. Disabled entries are
    /// dropped here rather than at the call site, so no caller can forget.
    pub fn granted(&self, shared: &[Offer], proto: Proto) -> Vec<u16> {
        let mut ports: Vec<u16> = shared
            .iter()
            .chain(&self.offers)
            .filter(|o| o.enabled && o.proto == proto)
            .map(|o| o.port)
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }
}

fn dedupe_offers(offers: &[Offer]) -> Result<()> {
    let mut seen = BTreeMap::new();
    for o in offers {
        if seen.insert((o.proto, o.port), ()).is_some() {
            bail!("{}/{} is listed twice", o.proto, o.port);
        }
    }
    Ok(())
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        for o in &self.serve.shared {
            o.validate()?;
        }
        dedupe_offers(&self.serve.shared).context("shared offers")?;

        let mut ids = BTreeMap::new();
        for p in &self.serve.peers {
            p.validate()?;
            if ids.insert(p.id, ()).is_some() {
                bail!("peer {} is listed twice", p.id.fmt_short());
            }
        }

        // Two listeners on one local port cannot both bind, so the config is
        // rejected rather than letting the second one fail at runtime.
        let mut locals = BTreeMap::new();
        for b in &self.connect.bindings {
            b.validate()?;
            if locals.insert((b.proto, b.local), ()).is_some() {
                bail!("local {}/{} is bound twice", b.proto, b.local);
            }
        }
        Ok(())
    }

    pub fn peer(&self, id: &EndpointId) -> Option<&Peer> {
        self.serve.peers.iter().find(|p| &p.id == id)
    }

    /// The admitted-peer test. Being listed is not enough — a parked entry is a
    /// remembered name, not a grant.
    pub fn admits(&self, id: &EndpointId) -> bool {
        self.peer(id).is_some_and(|p| p.enabled)
    }

    /// Ports `id` may reach. `None` when the peer is unknown or parked, which the
    /// caller must treat as "refuse", not as "no ports".
    pub fn granted(&self, id: &EndpointId, proto: Proto) -> Option<Vec<u16>> {
        let p = self.peer(id).filter(|p| p.enabled)?;
        Some(p.granted(&self.serve.shared, proto))
    }

    /// Listeners the connecting side should have bound right now.
    pub fn active_bindings(&self) -> Vec<Binding> {
        self.connect.bindings.iter().filter(|b| b.enabled).cloned().collect()
    }

    /// Applies `serve`/`connect` flags to a config that has no entries of that
    /// kind yet. Flags stay authoritative for the documented one-shot invocation
    /// while an existing config is never silently rewritten by them.
    pub fn seed_from_flags(
        &mut self,
        allow: &[EndpointId],
        tcp: &[u16],
        udp: &[u16],
    ) -> bool {
        let mut changed = false;
        for (proto, ports) in [(Proto::Tcp, tcp), (Proto::Udp, udp)] {
            for &port in ports {
                if !self.serve.shared.iter().any(|o| o.proto == proto && o.port == port) {
                    self.serve.shared.push(Offer {
                        proto,
                        port,
                        name: String::new(),
                        enabled: true,
                    });
                    changed = true;
                }
            }
        }
        for id in allow {
            if self.peer(id).is_none() {
                self.serve.peers.push(Peer {
                    id: *id,
                    name: String::new(),
                    enabled: true,
                    offers: Vec::new(),
                });
                changed = true;
            }
        }
        changed
    }

    pub fn seed_bindings(&mut self, tcp: &[PortMap], udp: &[PortMap]) -> bool {
        let mut changed = false;
        for (proto, maps) in [(Proto::Tcp, tcp), (Proto::Udp, udp)] {
            for m in maps {
                if !self
                    .connect
                    .bindings
                    .iter()
                    .any(|b| b.proto == proto && b.local == m.local)
                {
                    self.connect.bindings.push(Binding {
                        proto,
                        local: m.local,
                        remote: m.remote,
                        name: String::new(),
                        enabled: true,
                    });
                    changed = true;
                }
            }
        }
        changed
    }
}

// ---------------------------------------------------------------- persistence

pub fn config_path() -> Result<PathBuf> {
    Ok(crate::state_dir()?.join("config.toml"))
}

/// A missing file is an empty config, not an error: the first run of
/// `rtun serve --tcp 22 --allow ID` must work on a machine with no config at all.
pub fn load(path: &Path) -> Result<Config> {
    match fs::read_to_string(path) {
        Ok(s) => {
            let cfg: Config = toml::from_str(&s)
                .with_context(|| format!("parsing {}", path.display()))?;
            cfg.validate().with_context(|| format!("in {}", path.display()))?;
            Ok(cfg)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Written to a sibling temp file and renamed, so a crash mid-write cannot leave
/// a truncated allowlist — the old file stays intact until the new one is whole.
pub fn save(path: &Path, cfg: &Config) -> Result<()> {
    cfg.validate().context("refusing to write an invalid config")?;
    let dir = path.parent().context("config path has no parent directory")?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let body = format!(
        "# rtun configuration. Managed by the admin UI; safe to hand-edit while\n\
         # rtun is not running, and re-read on the next start.\n\n{}",
        toml::to_string_pretty(cfg).context("serialising config")?
    );
    let tmp = path.with_extension("toml.tmp");
    fs::write(&tmp, body).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------- admin token

/// The admin API's bearer token. Generated once and persisted `0600` next to the
/// secret key: a token that changed every start would invalidate an open browser
/// tab on every restart, and one derived from the endpoint key would leak it.
pub fn load_or_create_token() -> Result<String> {
    let dir = crate::state_dir()?;
    let path = dir.join("admin.token");
    // A present, non-empty token is reused; anything else is (re)minted. An
    // empty or truncated token file must not be able to brick `serve`.
    if let Ok(s) = fs::read_to_string(&path) {
        let s = s.trim();
        if !s.is_empty() {
            return Ok(s.to_owned());
        }
    }
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let t = mint_token();
    write_secret(&path, t.as_bytes())?;
    Ok(t)
}

fn mint_token() -> String {
    // 128 bits of CSPRNG output, hex-encoded: long enough that guessing it is
    // hopeless, short enough to paste into a URL by hand.
    let bytes: [u8; 16] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(unix)]
fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("creating {}", path.display()))
}

/// Constant-time comparison, so a token cannot be recovered a byte at a time by
/// timing the reject. Length is compared first because it is not a secret.
pub fn token_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The admin listener address. A bare port means loopback: exposing the panel is
/// a deliberate act that has to name an interface.
pub fn admin_addr(spec: &str) -> Result<SocketAddr> {
    if let Ok(port) = spec.parse::<u16>() {
        check_port(port, "admin")?;
        return Ok(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)));
    }
    let addr: SocketAddr = spec
        .parse()
        .with_context(|| format!("`{spec}`: expected PORT or IP:PORT, e.g. 7000"))?;
    check_port(addr.port(), "admin")?;
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn id(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn offer(proto: Proto, port: u16) -> Offer {
        Offer { proto, port, name: String::new(), enabled: true }
    }

    #[test]
    fn round_trips_through_toml() {
        let mut cfg = Config::default();
        cfg.serve.shared.push(Offer {
            proto: Proto::Tcp,
            port: 22,
            name: "ssh".into(),
            enabled: true,
        });
        cfg.serve.peers.push(Peer {
            id: id(1),
            name: "laptop".into(),
            enabled: true,
            offers: vec![offer(Proto::Udp, 51820)],
        });
        cfg.connect.bindings.push(Binding {
            proto: Proto::Tcp,
            local: 2222,
            remote: 22,
            name: "ssh".into(),
            enabled: true,
        });
        let text = toml::to_string_pretty(&cfg).unwrap();
        assert_eq!(toml::from_str::<Config>(&text).unwrap(), cfg);
        // ids must survive as the documented 64-char hex, not as a byte array
        assert!(text.contains(&id(1).to_string()));
    }

    #[test]
    fn granted_merges_shared_and_per_peer_and_honours_enabled() {
        let mut cfg = Config::default();
        cfg.serve.shared.push(offer(Proto::Tcp, 22));
        cfg.serve.shared.push(Offer { enabled: false, ..offer(Proto::Tcp, 80) });
        cfg.serve.peers.push(Peer {
            id: id(1),
            name: "laptop".into(),
            enabled: true,
            offers: vec![offer(Proto::Tcp, 8080), offer(Proto::Udp, 53)],
        });
        cfg.serve.peers.push(Peer {
            id: id(2),
            name: "parked".into(),
            enabled: false,
            offers: vec![offer(Proto::Tcp, 9999)],
        });

        assert_eq!(cfg.granted(&id(1), Proto::Tcp).unwrap(), vec![22, 8080]);
        assert_eq!(cfg.granted(&id(1), Proto::Udp).unwrap(), vec![53]);
        // a parked peer is refused outright, not granted an empty list
        assert!(cfg.granted(&id(2), Proto::Tcp).is_none());
        assert!(cfg.granted(&id(3), Proto::Tcp).is_none());
        assert!(cfg.admits(&id(1)) && !cfg.admits(&id(2)) && !cfg.admits(&id(3)));
    }

    #[test]
    fn validate_rejects_duplicates_and_bad_values() {
        let mut dup_peer = Config::default();
        dup_peer.serve.peers = vec![
            Peer { id: id(1), name: "a".into(), enabled: true, offers: vec![] },
            Peer { id: id(1), name: "b".into(), enabled: true, offers: vec![] },
        ];
        assert!(dup_peer.validate().is_err());

        let mut dup_offer = Config::default();
        dup_offer.serve.shared = vec![offer(Proto::Tcp, 22), offer(Proto::Tcp, 22)];
        assert!(dup_offer.validate().is_err());
        // the same port on the other protocol is a different grant
        let mut both = Config::default();
        both.serve.shared = vec![offer(Proto::Tcp, 22), offer(Proto::Udp, 22)];
        assert!(both.validate().is_ok());

        let mut zero = Config::default();
        zero.serve.shared = vec![offer(Proto::Tcp, 0)];
        assert!(zero.validate().is_err());

        let mut dup_local = Config::default();
        dup_local.connect.bindings = vec![
            Binding { proto: Proto::Tcp, local: 2222, remote: 22, name: String::new(), enabled: true },
            Binding { proto: Proto::Tcp, local: 2222, remote: 80, name: String::new(), enabled: true },
        ];
        assert!(dup_local.validate().is_err());

        let mut long = Config::default();
        long.serve.peers = vec![Peer {
            id: id(1),
            name: "x".repeat(NAME_MAX + 1),
            enabled: true,
            offers: vec![],
        }];
        assert!(long.validate().is_err());

        let mut ctrl = Config::default();
        ctrl.serve.peers = vec![Peer {
            id: id(1),
            name: "bad\nname".into(),
            enabled: true,
            offers: vec![],
        }];
        assert!(ctrl.validate().is_err());
    }

    #[test]
    fn seeding_is_idempotent_and_never_clobbers() {
        let mut cfg = Config::default();
        assert!(cfg.seed_from_flags(&[id(1)], &[22], &[53]));
        // a second identical seed changes nothing, so a restart with the same
        // flags does not grow the file
        assert!(!cfg.seed_from_flags(&[id(1)], &[22], &[53]));
        assert_eq!(cfg.serve.peers.len(), 1);
        assert_eq!(cfg.serve.shared.len(), 2);

        // a hand-parked entry survives a restart with the same flags
        cfg.serve.peers[0].enabled = false;
        cfg.serve.peers[0].name = "kept".into();
        assert!(!cfg.seed_from_flags(&[id(1)], &[22], &[53]));
        assert!(!cfg.serve.peers[0].enabled);
        assert_eq!(cfg.serve.peers[0].name, "kept");

        assert!(cfg.seed_bindings(&[PortMap { local: 2222, remote: 22 }], &[]));
        assert!(!cfg.seed_bindings(&[PortMap { local: 2222, remote: 22 }], &[]));
        assert_eq!(cfg.connect.bindings.len(), 1);
    }

    #[test]
    fn admin_addr_defaults_to_loopback() {
        assert_eq!(admin_addr("7000").unwrap(), "127.0.0.1:7000".parse().unwrap());
        assert_eq!(admin_addr("0.0.0.0:7000").unwrap(), "0.0.0.0:7000".parse().unwrap());
        for bad in ["0", "notaport", "127.0.0.1", "127.0.0.1:0", "99999"] {
            assert!(admin_addr(bad).is_err(), "{bad} should not parse");
        }
    }

    #[test]
    fn token_eq_matches_only_identical_tokens() {
        assert!(token_eq("abc", "abc"));
        assert!(!token_eq("abc", "abd"));
        assert!(!token_eq("abc", "ab"));
        assert!(!token_eq("", "a"));
        assert!(token_eq("", ""));
    }

    #[test]
    fn proto_parses_case_insensitively() {
        assert_eq!(Proto::from_str("tcp").unwrap(), Proto::Tcp);
        assert_eq!(Proto::from_str("UDP").unwrap(), Proto::Udp);
        assert!(Proto::from_str("sctp").is_err());
    }
}
