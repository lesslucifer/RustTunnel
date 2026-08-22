//! The admin HTTP surface: a small JSON API plus one embedded page.
//!
//! This endpoint can grant a peer access to loopback services, so it is treated as
//! a credential-bearing surface, not a convenience: it binds loopback by default,
//! every request carries a bearer token compared in constant time, and mutations
//! must present the token in a header no cross-origin form can forge.

use std::{convert::Infallible, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Body as _;
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::{
    config::{self, Binding, Offer, Peer, Proto},
    state::{Role, Shared},
};

/// Request bodies are tiny; a cap keeps a stray large POST from being buffered.
const MAX_BODY: u64 = 64 * 1024;

/// The page itself. Embedded rather than read from disk so the binary stays the
/// only artifact that has to be deployed.
const INDEX_HTML: &str = include_str!("admin/index.html");

pub struct Admin {
    pub shared: Arc<Shared>,
    pub token: String,
    /// The endpoint id of this process, shown so a user can copy it to the peer.
    pub id: String,
}

/// Bound separately from [`serve`] so "port already in use" fails the command
/// instead of being logged by a background task after the tunnel is already up.
pub async fn bind(addr: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding the admin listener on {addr}"))
}

pub async fn serve(admin: Arc<Admin>, listener: TcpListener) -> Result<()> {
    let addr = listener.local_addr().context("reading the admin listener address")?;
    // Printed on stdout: this URL is the one thing a user must have, and it should
    // survive `2>/dev/null` like `rtun id` does.
    println!("admin ui http://{addr}/?t={}", admin.token);
    if !addr.ip().is_loopback() {
        warn!(%addr, "admin ui is not bound to loopback; anyone who can reach it and holds the token can change the allowlist");
    }
    info!(%addr, "admin ui listening");

    loop {
        let (stream, from) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("admin accept failed: {e:#}");
                continue;
            }
        };
        let admin = admin.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let admin = admin.clone();
                async move { Ok::<_, Infallible>(route(admin, req).await) }
            });
            if let Err(e) = http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await {
                // A browser closing a keep-alive connection is normal, so this is
                // debug-level noise rather than a warning.
                tracing::debug!(%from, "admin connection ended: {e}");
            }
        });
    }
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        // The panel is same-origin only and embeds no third-party content.
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("static response builds")
}

fn err(status: StatusCode, msg: impl std::fmt::Display) -> Response<Full<Bytes>> {
    json_response(status, json!({ "error": msg.to_string() }))
}

/// Token from either the `Authorization: Bearer` header or the `t` query
/// parameter. The query form exists so the printed URL works in a browser; the
/// page immediately swaps it for header auth.
fn presented_token(req: &Request<Incoming>) -> Option<String> {
    if let Some(v) = req.headers().get(header::AUTHORIZATION)
        && let Ok(s) = v.to_str()
        && let Some(rest) = s.strip_prefix("Bearer ")
    {
        return Some(rest.trim().to_owned());
    }
    req.uri().query().and_then(|q| {
        q.split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == "t")
            .map(|(_, v)| v.to_owned())
    })
}

async fn route(admin: Arc<Admin>, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_owned();
    let method = req.method().clone();

    // The page itself carries no secret, so it is served before the auth check and
    // asks for the token itself if the URL had none.
    if method == Method::GET && (path == "/" || path == "/index.html") {
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header("cache-control", "no-store")
            .header("x-content-type-options", "nosniff")
            .header("referrer-policy", "no-referrer")
            .body(Full::new(Bytes::from(INDEX_HTML)))
            .expect("static response builds");
    }

    let Some(tok) = presented_token(&req) else {
        return err(StatusCode::UNAUTHORIZED, "missing token");
    };
    if !config::token_eq(&tok, &admin.token) {
        warn!(%path, "admin request with a bad token");
        return err(StatusCode::UNAUTHORIZED, "bad token");
    }

    // Mutations require the header form. A cross-origin <form> can POST but cannot
    // set Authorization, so this is what stops a random page from editing the
    // allowlist even if it somehow learned the token.
    if method != Method::GET && !req.headers().contains_key(header::AUTHORIZATION) {
        return err(StatusCode::UNAUTHORIZED, "mutations require the Authorization header");
    }

    match (method, path.as_str()) {
        (Method::GET, "/api/state") => get_state(&admin),
        (Method::POST, "/api/peers") => with_body(req, |b| add_peer(&admin, b)).await,
        (Method::PATCH, "/api/peers") => with_body(req, |b| patch_peer(&admin, b)).await,
        (Method::DELETE, "/api/peers") => with_body(req, |b| del_peer(&admin, b)).await,
        (Method::POST, "/api/offers") => with_body(req, |b| add_offer(&admin, b)).await,
        (Method::PATCH, "/api/offers") => with_body(req, |b| patch_offer(&admin, b)).await,
        (Method::DELETE, "/api/offers") => with_body(req, |b| del_offer(&admin, b)).await,
        (Method::POST, "/api/bindings") => with_body(req, |b| add_binding(&admin, b)).await,
        (Method::PATCH, "/api/bindings") => with_body(req, |b| patch_binding(&admin, b)).await,
        (Method::DELETE, "/api/bindings") => with_body(req, |b| del_binding(&admin, b)).await,
        _ => err(StatusCode::NOT_FOUND, "no such endpoint"),
    }
}

/// Reads a capped body and hands it to a handler, so every mutating route shares
/// one limit and one set of error shapes.
async fn with_body<T, F>(req: Request<Incoming>, f: F) -> Response<Full<Bytes>>
where
    T: for<'de> Deserialize<'de>,
    F: FnOnce(T) -> Result<Response<Full<Bytes>>>,
{
    let upper = req.body().size_hint().upper().unwrap_or(u64::MAX);
    if upper > MAX_BODY {
        return err(StatusCode::PAYLOAD_TOO_LARGE, "body too large");
    }
    let bytes = match req.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("reading body: {e}")),
    };
    let parsed: T = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => return err(StatusCode::BAD_REQUEST, format!("invalid json: {e}")),
    };
    match f(parsed) {
        Ok(r) => r,
        // A rejected edit is the user's mistake far more often than a bug, so the
        // validation message is returned verbatim for the UI to show.
        Err(e) => err(StatusCode::UNPROCESSABLE_ENTITY, format!("{e:#}")),
    }
}

// ---------------------------------------------------------------- reads

#[derive(Serialize)]
struct OfferView<'a> {
    #[serde(flatten)]
    offer: &'a Offer,
}

fn get_state(admin: &Admin) -> Response<Full<Bytes>> {
    let cfg = admin.shared.config();
    let sh = &admin.shared;
    let bindings: Vec<_> = cfg
        .connect
        .bindings
        .iter()
        .map(|b| {
            json!({
                "proto": b.proto, "local": b.local, "remote": b.remote,
                "name": b.name, "enabled": b.enabled,
                "runtime": sh.bind_state(b),
            })
        })
        .collect();
    let peers: Vec<_> = cfg
        .serve
        .peers
        .iter()
        .map(|p| {
            json!({
                "id": p.id.to_string(),
                "short": p.id.fmt_short().to_string(),
                "name": p.name,
                "enabled": p.enabled,
                "offers": p.offers.iter().map(|o| OfferView { offer: o }).collect::<Vec<_>>(),
            })
        })
        .collect();

    json_response(
        StatusCode::OK,
        json!({
            "role": admin.shared.role(),
            "id": admin.id,
            "config_path": sh.config_path().display().to_string(),
            "uptime_secs": sh.uptime_secs(),
            "shared_offers": cfg.serve.shared,
            "peers": peers,
            "bindings": bindings,
            "live_peers": sh.live_peers(),
        }),
    )
}

fn ok() -> Result<Response<Full<Bytes>>> {
    Ok(json_response(StatusCode::OK, json!({ "ok": true })))
}

// ---------------------------------------------------------------- peers

#[derive(Deserialize)]
struct PeerAdd {
    id: String,
    #[serde(default)]
    name: String,
}

/// Parsed here rather than by serde so a mistyped key produces a message about the
/// key instead of a generic deserialisation error.
fn parse_id(s: &str) -> Result<EndpointId> {
    let s = s.trim();
    s.parse::<EndpointId>()
        .map_err(|e| anyhow::anyhow!("`{s}` is not a valid endpoint id: {e}"))
}

fn add_peer(admin: &Admin, b: PeerAdd) -> Result<Response<Full<Bytes>>> {
    let id = parse_id(&b.id)?;
    admin.shared.mutate(|c| {
        if c.peer(&id).is_some() {
            anyhow::bail!("peer {} is already on the list", id.fmt_short());
        }
        c.serve.peers.push(Peer { id, name: b.name.clone(), enabled: true, offers: vec![] });
        Ok(())
    })?;
    info!(peer = %id, name = %b.name, "peer added via admin ui");
    ok()
}

#[derive(Deserialize)]
struct PeerPatch {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

fn patch_peer(admin: &Admin, b: PeerPatch) -> Result<Response<Full<Bytes>>> {
    let id = parse_id(&b.id)?;
    admin.shared.mutate(|c| {
        let p = c
            .serve
            .peers
            .iter_mut()
            .find(|p| p.id == id)
            .with_context(|| format!("peer {} is not on the list", id.fmt_short()))?;
        if let Some(n) = &b.name {
            p.name = n.clone();
        }
        if let Some(e) = b.enabled {
            p.enabled = e;
        }
        Ok(())
    })?;
    info!(peer = %id, "peer updated via admin ui");
    ok()
}

#[derive(Deserialize)]
struct IdRef {
    id: String,
}

fn del_peer(admin: &Admin, b: IdRef) -> Result<Response<Full<Bytes>>> {
    let id = parse_id(&b.id)?;
    admin.shared.mutate(|c| {
        let before = c.serve.peers.len();
        c.serve.peers.retain(|p| p.id != id);
        if c.serve.peers.len() == before {
            anyhow::bail!("peer {} is not on the list", id.fmt_short());
        }
        Ok(())
    })?;
    // The live connection is closed by `serve`'s eviction watcher.
    info!(peer = %id, "peer removed via admin ui");
    ok()
}

// ---------------------------------------------------------------- offers

#[derive(Deserialize)]
struct OfferRef {
    /// Absent means the shared set; present scopes the offer to one peer.
    #[serde(default)]
    peer: Option<String>,
    proto: Proto,
    port: u16,
}

#[derive(Deserialize)]
struct OfferAdd {
    #[serde(default)]
    peer: Option<String>,
    proto: Proto,
    port: u16,
    #[serde(default)]
    name: String,
}

/// The shared list, or one peer's list. Both are edited by the same handlers, so
/// "add a port for everyone" and "add a port for this peer" cannot drift apart.
fn offers_of<'a>(
    c: &'a mut crate::config::Config,
    peer: &Option<String>,
) -> Result<&'a mut Vec<Offer>> {
    match peer {
        None => Ok(&mut c.serve.shared),
        Some(p) => {
            let id = parse_id(p)?;
            Ok(&mut c
                .serve
                .peers
                .iter_mut()
                .find(|x| x.id == id)
                .with_context(|| format!("peer {} is not on the list", id.fmt_short()))?
                .offers)
        }
    }
}

fn add_offer(admin: &Admin, b: OfferAdd) -> Result<Response<Full<Bytes>>> {
    admin.shared.mutate(|c| {
        let list = offers_of(c, &b.peer)?;
        if list.iter().any(|o| o.proto == b.proto && o.port == b.port) {
            anyhow::bail!("{}/{} is already offered", b.proto, b.port);
        }
        list.push(Offer { proto: b.proto, port: b.port, name: b.name.clone(), enabled: true });
        Ok(())
    })?;
    info!(proto = %b.proto, port = b.port, peer = ?b.peer, "port offered via admin ui");
    ok()
}

#[derive(Deserialize)]
struct OfferPatch {
    #[serde(default)]
    peer: Option<String>,
    proto: Proto,
    port: u16,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

fn patch_offer(admin: &Admin, b: OfferPatch) -> Result<Response<Full<Bytes>>> {
    admin.shared.mutate(|c| {
        let list = offers_of(c, &b.peer)?;
        let o = list
            .iter_mut()
            .find(|o| o.proto == b.proto && o.port == b.port)
            .with_context(|| format!("{}/{} is not offered", b.proto, b.port))?;
        if let Some(n) = &b.name {
            o.name = n.clone();
        }
        if let Some(e) = b.enabled {
            o.enabled = e;
        }
        Ok(())
    })?;
    info!(proto = %b.proto, port = b.port, peer = ?b.peer, "offer updated via admin ui");
    ok()
}

fn del_offer(admin: &Admin, b: OfferRef) -> Result<Response<Full<Bytes>>> {
    admin.shared.mutate(|c| {
        let list = offers_of(c, &b.peer)?;
        let before = list.len();
        list.retain(|o| !(o.proto == b.proto && o.port == b.port));
        if list.len() == before {
            anyhow::bail!("{}/{} is not offered", b.proto, b.port);
        }
        Ok(())
    })?;
    info!(proto = %b.proto, port = b.port, peer = ?b.peer, "offer withdrawn via admin ui");
    ok()
}

// ---------------------------------------------------------------- bindings

#[derive(Deserialize)]
struct BindingAdd {
    proto: Proto,
    local: u16,
    remote: u16,
    #[serde(default)]
    name: String,
}

fn add_binding(admin: &Admin, b: BindingAdd) -> Result<Response<Full<Bytes>>> {
    admin.shared.mutate(|c| {
        if c.connect.bindings.iter().any(|x| x.proto == b.proto && x.local == b.local) {
            anyhow::bail!("local {}/{} is already bound", b.proto, b.local);
        }
        c.connect.bindings.push(Binding {
            proto: b.proto,
            local: b.local,
            remote: b.remote,
            name: b.name.clone(),
            enabled: true,
        });
        Ok(())
    })?;
    info!(proto = %b.proto, local = b.local, remote = b.remote, "binding added via admin ui");
    ok()
}

#[derive(Deserialize)]
struct BindingPatch {
    proto: Proto,
    local: u16,
    #[serde(default)]
    remote: Option<u16>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

fn patch_binding(admin: &Admin, b: BindingPatch) -> Result<Response<Full<Bytes>>> {
    admin.shared.mutate(|c| {
        let x = c
            .connect
            .bindings
            .iter_mut()
            .find(|x| x.proto == b.proto && x.local == b.local)
            .with_context(|| format!("local {}/{} is not bound", b.proto, b.local))?;
        if let Some(r) = b.remote {
            x.remote = r;
        }
        if let Some(n) = &b.name {
            x.name = n.clone();
        }
        if let Some(e) = b.enabled {
            x.enabled = e;
        }
        Ok(())
    })?;
    info!(proto = %b.proto, local = b.local, "binding updated via admin ui");
    ok()
}

#[derive(Deserialize)]
struct BindingRef {
    proto: Proto,
    local: u16,
}

fn del_binding(admin: &Admin, b: BindingRef) -> Result<Response<Full<Bytes>>> {
    admin.shared.mutate(|c| {
        let before = c.connect.bindings.len();
        c.connect.bindings.retain(|x| !(x.proto == b.proto && x.local == b.local));
        if c.connect.bindings.len() == before {
            anyhow::bail!("local {}/{} is not bound", b.proto, b.local);
        }
        Ok(())
    })?;
    info!(proto = %b.proto, local = b.local, "binding removed via admin ui");
    ok()
}

/// Kept so the role is visible in the API for a UI that hides the other panel.
impl Role {
    pub fn is_serve(self) -> bool {
        matches!(self, Role::Serve)
    }
}
