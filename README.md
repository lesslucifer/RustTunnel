# rtun

Forward TCP and UDP ports between two machines you own, over a direct
hole-punched QUIC connection.

One static binary on each end. One side offers a list of local ports, the other
reaches them on its own `127.0.0.1`. Machines address each other by public key,
so neither needs a public IP, a port forward, a VPS, or an account.

```
# home box                                  # laptop, anywhere
rtun serve --tcp 22 --allow $ID_LAPTOP      rtun connect $ID_HOME --tcp 2222:22
                                            ssh -p 2222 127.0.0.1
```

- **Direct by default.** Both sides punch out through their NATs and talk to
  each other; a public relay is used only to introduce them, and only carries
  traffic when hole punching fails.
- **End-to-end encrypted.** The QUIC session is authenticated by the two
  endpoint keys. No third party terminates TLS or sees plaintext.
- **Two allowlists, no defaults.** Only named peers may connect, and only named
  ports may be reached. There is no "allow anyone" mode.
- **No root, no TUN device, no virtual IPs, no daemon required.**

**What it is not:** a public ingress. An unmodified peer running plain `ssh` or
a browser cannot reach you — only a machine running `rtun` can. That is the
trade that removes the relay from the data path. See
[docs/implementation-plan.html](docs/implementation-plan.html).

## Install

| Platform | Command |
| --- | --- |
| macOS, Linux | `curl -fsSL https://raw.githubusercontent.com/lesslucifer/RustTunnel/main/packaging/install.sh \| sh` |
| Windows (PowerShell) | `irm https://raw.githubusercontent.com/lesslucifer/RustTunnel/main/packaging/install.ps1 \| iex` |
| From source | `cargo build --release`, then put `target/release/rtun` on your `PATH` |

The installers verify a SHA-256 checksum, then drop the binary in
`~/.local/bin` (`%LOCALAPPDATA%\rtun\bin` on Windows) and warn if that directory
is not on your `PATH`. Prebuilt targets: `aarch64-apple-darwin`,
`x86_64-apple-darwin`, `x86_64-unknown-linux-musl`, `x86_64-pc-windows-msvc`.

## Quickstart

Both machines need `rtun`, and each needs the other's ID. That two-way exchange
is the whole of pairing; the long form is
[docs/pairing.html](docs/pairing.html).

**1. Print each machine's ID** — on *both* machines:

```sh
rtun id
# 3ef09bf26bfd29946ee8e3da2d18d56bbd5cb8a40a817084b9343950b6bed842
```

That 64-character string is the machine's public key and its permanent address.
It is generated on first run, persists across reboots, and is **not** a secret —
paste it into chat or read it over the phone. Call the two values `ID_HOME` and
`ID_LAPTOP`.

**2. On the serving machine**, offer port 22 to that one peer:

```sh
rtun serve --tcp 22 --allow $ID_LAPTOP
```

`--tcp 22` means *port 22 may be reached through the tunnel* — it does not start
SSH. To try the tunnel without touching system settings, run
`python3 -m http.server 8022 --bind 127.0.0.1` and offer `--tcp 8022` instead.

**3. On the connecting machine**, map that port onto a local one:

```sh
rtun connect $ID_HOME --tcp 2222:22
```

`2222:22` reads local-first: *this* machine's 2222 becomes *the far* machine's
22.

**4. Use it:**

```sh
ssh -p 2222 127.0.0.1
```

Within a few seconds both sides log the connection from their own end:

```
INFO rtun::serve: admitted peer=51d710cbd4…
INFO rtun: established peer=51d710cbd4 path=relayed addr=relay:… rtt=104ms
INFO rtun: path selected peer=51d710cbd4 path=direct addr=ip:192.168.1.8:61393
```

`path=relayed` first and `path=direct` a moment later is the normal, healthy
sequence — the two machines must talk through the relay before they can talk
directly.

## Commands

### `rtun id`

Prints this machine's endpoint ID on stdout and exits. Creates the key on first
run. Logs go to stderr, so `ID=$(rtun id)` captures a bare ID.

### `rtun serve`

Offers local ports to allowlisted peers.

| Flag | Meaning |
| --- | --- |
| `--allow <ENDPOINT_ID>` | Peer permitted to connect. **Required**, repeatable. |
| `--tcp <PORT>` | Local TCP port that may be reached. Repeatable. |
| `--udp <PORT>` | Local UDP port that may be reached. Repeatable. |
| `--relay-only` | Skip direct paths; force traffic through the relay. |

Connections are made to `127.0.0.1` on the serving machine — `rtun` reaches
loopback services, not other hosts on its LAN. A peer not in `--allow` is closed
immediately; a port not in `--tcp`/`--udp` is refused per stream or per
datagram, with a log line naming it.

### `rtun connect <PEER_ID>`

Binds local listeners and forwards them to the serving peer.

| Flag | Meaning |
| --- | --- |
| `--tcp <LOCAL:REMOTE>` | Map a local TCP port onto a remote one. Repeatable. |
| `--udp <LOCAL:REMOTE>` | Map a local UDP port onto a remote one. Repeatable. |
| `--relay-only` | Skip direct paths; force traffic through the relay. |

Listeners bind `127.0.0.1` only and are bound *before* dialing, so a port
already in use fails the command rather than failing later. They stay bound
across reconnects: if the link drops, `rtun` retries with a growing delay
(1s → 30s) and clients queue instead of finding nothing listening. Being refused
by the peer's allowlist is permanent, and exits rather than retrying forever.

### Environment

| Variable | Effect |
| --- | --- |
| `RTUN_STATE_DIR` | Where `secret.key` lives. Overrides everything below. |
| `STATE_DIRECTORY` | Honoured so systemd's `StateDirectory=rtun` just works. |
| `RTUN_LOG` | Log filter, `tracing` syntax. Default `rtun=info`; try `rtun=debug`. |

Default state directory: `~/.local/state/rtun` (`%APPDATA%\rtun` on Windows).

## Security model

The endpoint's identity *is* its keypair. The QUIC handshake cannot complete
against anything but the holder of that key, so dialing by ID is mutually
authenticated by construction — there is no separate token or fingerprint to
exchange.

- `secret.key` is created `0600` in an owner-only directory, and on Unix it is
  opened that way rather than chmod'ed afterwards, so it is never
  world-readable for even an instant. **Anyone who copies that file becomes that
  machine.** Deleting it mints a new identity and forces re-pairing.
- Endpoint IDs are public keys. Sharing one grants nothing on its own.
- `--allow` is the peer allowlist; `--tcp`/`--udp` are the port allowlist.
  Without the second, one allowlisted peer would reach every loopback port on
  the serving machine — a much larger grant than `--tcp 22` looks like.
- The public discovery service learns that two keys are looking for each other
  and their observed addresses. It never holds payload unless the path falls
  back to relayed, and even then the bytes are encrypted end to end.

## Running as a service

**Linux (systemd)** — [packaging/rtun.service](packaging/rtun.service):

```sh
sudo cp packaging/rtun.service /etc/systemd/system/
sudoedit /etc/systemd/system/rtun.service   # set --allow and the ports
sudo systemctl enable --now rtun
```

`DynamicUser=yes` plus `StateDirectory=rtun` keeps the endpoint identity across
restarts without a real user account owning it.

**macOS (LaunchAgent)** — [packaging/com.rtun.serve.plist](packaging/com.rtun.serve.plist):

```sh
sed -e "s|__RTUN__|$HOME/.local/bin/rtun|" -e "s|__PEER__|$PEER_ID|" \
    -e "s|__PORT__|22|" -e "s|__STATE__|$HOME/.local/state/rtun|" \
    -e "s|__HOME__|$HOME|" packaging/com.rtun.serve.plist \
    > ~/Library/LaunchAgents/com.rtun.serve.plist
launchctl bootstrap gui/$UID ~/Library/LaunchAgents/com.rtun.serve.plist
```

## Notes and limits

- **UDP datagrams are capped** at roughly 1200 bytes minus a 6-byte header —
  whatever the QUIC path can carry unfragmented. Oversize datagrams are dropped
  with a log line naming the cap, not silently truncated.
- **UDP sessions** are synthesised from the local source address and target
  port, and released after 60 seconds of silence in both directions.
- **Symmetric NAT on both ends** cannot be punched; those connections stay
  `relayed`. One symmetric NAT is usually survivable.
- Every held connection restates its path once a minute (`still up
  path=direct …`), so a log answers "was it still direct at 03:00" without
  inference.

## Development

```sh
cargo build --release
cargo test          # no network access required
RTUN_LOG=rtun=debug cargo run -- serve --tcp 8022 --allow $PEER
```

Two roles on one machine need separate identities — give each its own
`RTUN_STATE_DIR`.

Design and verification docs live in [docs/](docs/): the
[implementation plan](docs/implementation-plan.html), the
[work breakdown](docs/wbs.html), the [e2e test plan](docs/e2e-testing.html) and
the per-phase results. Captured runs are filed under [evidence/](evidence/) with
a ledger in [evidence/README.md](evidence/README.md).

**Status: v0.1.0.** TCP and UDP forwarding, identity, allowlists, relay
fallback, reconnect and packaging are implemented and verified. Cross-NAT
direct connection (evidence task 2.2) has not yet been confirmed on two
separate networks — the ledger tracks what is outstanding and why.
