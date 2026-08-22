//! The live, shared view of the configuration, plus the runtime facts the admin
//! UI reports back.
//!
//! One writer path and many cheap readers: every mutation goes through
//! [`Shared::mutate`], which validates, persists, then publishes a new immutable
//! snapshot. Readers hold an `Arc<Config>` and never block a writer, which is what
//! lets a per-datagram allowlist check be free.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use iroh::EndpointId;
use serde::Serialize;
use tokio::sync::watch;

use crate::config::{Binding, Config, Proto};

/// Which role is running, so the UI shows the panel that matches the process and
/// refuses edits that could not take effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Serve,
    Connect,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Serve => "serve",
            Role::Connect => "connect",
        }
    }
}

/// Why a local listener is not carrying traffic. Reported verbatim to the UI, so
/// "address already in use" is visible without reading the log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum BindState {
    Listening,
    Failed { error: String },
}

/// One connected peer, as the serving side currently sees it.
#[derive(Clone, Debug, Serialize)]
pub struct PeerLive {
    pub id: String,
    pub short: String,
    /// "direct", "relayed" or "pending" — the single most useful diagnostic.
    pub path: String,
    pub addr: Option<String>,
    pub rtt_ms: Option<u64>,
    pub since_secs: u64,
}

#[derive(Default)]
struct Runtime {
    peers: BTreeMap<EndpointId, (std::time::Instant, PathInfo)>,
    binds: BTreeMap<(Proto, u16), BindState>,
}

#[derive(Clone, Default)]
struct PathInfo {
    path: String,
    addr: Option<String>,
    rtt_ms: Option<u64>,
}

/// Everything the admin surface and the data plane share. Cloneable by `Arc`.
pub struct Shared {
    path: PathBuf,
    role: Role,
    /// Serialises read-modify-write so two concurrent API calls cannot lose one
    /// another's edit. Held only around the in-memory swap and the file write.
    write: Mutex<()>,
    tx: watch::Sender<Arc<Config>>,
    runtime: Mutex<Runtime>,
    started: std::time::Instant,
}

impl Shared {
    pub fn new(cfg: Config, path: PathBuf, role: Role) -> Arc<Self> {
        let (tx, _) = watch::channel(Arc::new(cfg));
        Arc::new(Self {
            path,
            role,
            write: Mutex::new(()),
            tx,
            runtime: Mutex::new(Runtime::default()),
            started: std::time::Instant::now(),
        })
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn config_path(&self) -> &std::path::Path {
        &self.path
    }

    /// The current snapshot. Cheap: one `Arc` clone, no lock contention with
    /// writers.
    pub fn config(&self) -> Arc<Config> {
        self.tx.borrow().clone()
    }

    /// Notified on every committed change. The data plane watches this to bind or
    /// drop listeners and to re-check peers that are already connected.
    pub fn subscribe(&self) -> watch::Receiver<Arc<Config>> {
        self.tx.subscribe()
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// Applies `f` to a copy, validates it, writes it to disk, and only then
    /// publishes it. A rejected or unwritable edit leaves the running config
    /// exactly as it was — the UI reports the error and the tunnel is untouched.
    pub fn mutate<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Config) -> Result<T>,
    {
        let _guard = self.write.lock().unwrap();
        let mut next = (*self.config()).clone();
        let out = f(&mut next)?;
        next.validate()?;
        crate::config::save(&self.path, &next)
            .with_context(|| format!("persisting {}", self.path.display()))?;
        // Published after the write succeeds, so what is running is always what is
        // on disk. `send_replace`, not `send`: `send` reports an error *and drops
        // the value* when nobody is subscribed yet, which would silently discard
        // every edit made before the data plane starts watching.
        self.tx.send_replace(Arc::new(next));
        Ok(out)
    }

    // ------------------------------------------------------------ runtime facts

    pub fn peer_connected(&self, id: EndpointId) {
        let mut rt = self.runtime.lock().unwrap();
        rt.peers.entry(id).or_insert_with(|| (std::time::Instant::now(), PathInfo::default()));
    }

    pub fn peer_disconnected(&self, id: &EndpointId) {
        self.runtime.lock().unwrap().peers.remove(id);
    }

    pub fn peer_path(&self, id: EndpointId, path: &str, addr: Option<String>, rtt_ms: Option<u64>) {
        let mut rt = self.runtime.lock().unwrap();
        if let Some((_, info)) = rt.peers.get_mut(&id) {
            *info = PathInfo { path: path.to_owned(), addr, rtt_ms };
        }
    }

    pub fn live_peers(&self) -> Vec<PeerLive> {
        let rt = self.runtime.lock().unwrap();
        rt.peers
            .iter()
            .map(|(id, (since, info))| PeerLive {
                id: id.to_string(),
                short: id.fmt_short().to_string(),
                path: if info.path.is_empty() { "pending".into() } else { info.path.clone() },
                addr: info.addr.clone(),
                rtt_ms: info.rtt_ms,
                since_secs: since.elapsed().as_secs(),
            })
            .collect()
    }

    pub fn set_bind(&self, proto: Proto, local: u16, st: BindState) {
        self.runtime.lock().unwrap().binds.insert((proto, local), st);
    }

    pub fn clear_bind(&self, proto: Proto, local: u16) {
        self.runtime.lock().unwrap().binds.remove(&(proto, local));
    }

    pub fn bind_state(&self, b: &Binding) -> Option<BindState> {
        self.runtime.lock().unwrap().binds.get(&(b.proto, b.local)).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Offer, Peer};

    fn id(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn shared() -> (Arc<Shared>, tempdir::Dir) {
        let dir = tempdir::Dir::new();
        let path = dir.path().join("config.toml");
        (Shared::new(Config::default(), path, Role::Serve), dir)
    }

    #[test]
    fn mutation_persists_publishes_and_is_observable() {
        let (sh, _d) = shared();
        let mut rx = sh.subscribe();
        assert!(sh.config().serve.peers.is_empty());

        sh.mutate(|c| {
            c.serve.peers.push(Peer {
                id: id(1),
                name: "laptop".into(),
                enabled: true,
                offers: vec![],
            });
            Ok(())
        })
        .unwrap();

        // visible in memory
        assert!(sh.config().admits(&id(1)));
        // the watcher saw a change
        assert!(rx.has_changed().unwrap());
        assert!(rx.borrow_and_update().admits(&id(1)));
        // and it is on disk, so a restart keeps it
        let reloaded = crate::config::load(sh.config_path()).unwrap();
        assert!(reloaded.admits(&id(1)));
        assert_eq!(reloaded.serve.peers[0].name, "laptop");
    }

    /// Regression: `watch::Sender::send` fails *and discards the value* when no
    /// receiver exists, so an edit made before the data plane subscribes must not
    /// depend on there being a subscriber.
    #[test]
    fn mutation_applies_with_no_subscriber() {
        let (sh, _d) = shared();
        sh.mutate(|c| {
            c.serve.shared.push(Offer {
                proto: Proto::Tcp,
                port: 22,
                name: String::new(),
                enabled: true,
            });
            Ok(())
        })
        .unwrap();
        assert_eq!(sh.config().serve.shared.len(), 1, "edit lost with no subscriber");
        // a later subscriber sees the already-committed edit
        assert_eq!(sh.subscribe().borrow().serve.shared.len(), 1);
    }

    #[test]
    fn rejected_mutation_leaves_running_config_untouched() {
        let (sh, _d) = shared();
        sh.mutate(|c| {
            c.serve.shared.push(Offer {
                proto: Proto::Tcp,
                port: 22,
                name: String::new(),
                enabled: true,
            });
            Ok(())
        })
        .unwrap();
        let before = sh.config();

        // a duplicate port fails validation
        let err = sh.mutate(|c| {
            c.serve.shared.push(Offer {
                proto: Proto::Tcp,
                port: 22,
                name: String::new(),
                enabled: true,
            });
            Ok(())
        });
        assert!(err.is_err());
        assert_eq!(sh.config().serve.shared.len(), 1);
        assert!(Arc::ptr_eq(&before, &sh.config()), "snapshot must not be replaced");

        // an error raised by the closure itself also commits nothing
        assert!(sh.mutate(|_| -> Result<()> { anyhow::bail!("nope") }).is_err());
        assert_eq!(sh.config().serve.shared.len(), 1);
        // and disk still matches memory
        assert_eq!(crate::config::load(sh.config_path()).unwrap(), *sh.config());
    }

    #[test]
    fn runtime_tracks_peers_and_binds() {
        let (sh, _d) = shared();
        assert!(sh.live_peers().is_empty());

        sh.peer_connected(id(1));
        let live = sh.live_peers();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].path, "pending", "path is unknown until one is selected");

        sh.peer_path(id(1), "direct", Some("ip:1.2.3.4:5".into()), Some(12));
        let live = sh.live_peers();
        assert_eq!(live[0].path, "direct");
        assert_eq!(live[0].rtt_ms, Some(12));
        assert_eq!(live[0].id.len(), 64, "the UI shows the full pasteable id");

        // a path report for an unknown peer must not resurrect it
        sh.peer_disconnected(&id(1));
        sh.peer_path(id(1), "direct", None, None);
        assert!(sh.live_peers().is_empty());

        let b = Binding {
            proto: Proto::Tcp,
            local: 2222,
            remote: 22,
            name: String::new(),
            enabled: true,
        };
        assert_eq!(sh.bind_state(&b), None);
        sh.set_bind(Proto::Tcp, 2222, BindState::Listening);
        assert_eq!(sh.bind_state(&b), Some(BindState::Listening));
        sh.set_bind(Proto::Tcp, 2222, BindState::Failed { error: "in use".into() });
        assert!(matches!(sh.bind_state(&b), Some(BindState::Failed { .. })));
        sh.clear_bind(Proto::Tcp, 2222);
        assert_eq!(sh.bind_state(&b), None);
    }

    /// A self-cleaning temp directory, so the config tests never touch a real
    /// state dir.
    pub mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct Dir(PathBuf);

        impl Dir {
            pub fn new() -> Self {
                let mut p = std::env::temp_dir();
                p.push(format!("rtun-test-{}-{}", std::process::id(), rand::random::<u64>()));
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }

            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }
}
