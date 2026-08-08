# Evidence ledger — P0 through P6

Convention and definition of done live in [docs/wbs.html](../docs/wbs.html). A task is
done when the target is observably true, the check ran against real binaries, the
evidence is filed here, and `cargo test` still passes.

Runs with both roles on one machine are substitutes, not targets, and live on their own
shelf at `evidence/local/<task-id>/` — the procedure and what each substitution costs is
in [docs/e2e-testing.html](../docs/e2e-testing.html). Never file a local run as a
cross-machine task's evidence.

All captured runs are from `MacBook-Pro-3.local`, macOS 14.0, arm64, Wi-Fi `192.168.1.8`,
against the public n0 relay `aps1-1.relay.n0.iroh.link`.

| Task | State | Evidence |
| --- | --- | --- |
| 0.1 Repo skeleton and toolchain | **done** | `0.1/session.txt` |
| 0.2 Three-platform CI | **blocked — needs a git remote** | see below |
| 1.1 Persistent identity and `rtun id` | **done** | `1.1/session.txt` |
| 1.2 Dial by endpoint ID | **partial — one machine only** | `1.2/`, `local/1.2/` |
| 1.3 Peer allowlist | **done** | `1.3/session.txt` |
| 2.1 Path reporting | **done** | `2.1/session.txt` |
| 2.2 Cross-NAT direct connection | **not run — needs a second network** | see below |
| 2.3 Relay fallback works | **done** | `2.3/` |
| 3.1 One connection end to end | **partial — one machine only** | `local/3.1/` |
| 3.2 Port allowlist on the serving side | **done** | `local/3.2/`, `local/3.2-udp/` |
| 3.3 Concurrency and clean close | **done** | `local/3.3/` |
| 3.4 Re-verify on the relayed path | **done** | `local/3.4/` |
| 4.1 DNS round trip | **done** | `local/4.1/` |
| 4.2 WireGuard handshake | **not run — substitute only** | `local/4.2-substitute/` |
| 4.3 Session reaping | **done** | `local/4.3/` |
| 4.4 Oversize datagram behaviour | **done** | `local/4.4/` |
| 5.1 Reconnect with backoff | **done** | `local/5.1/` |
| 5.2 Survives a network change | **partial — symmetric flap only** | `local/5.2/` |
| 5.3 24-hour soak | **partial — one hour** | `local/5.3/` |
| 6.1 Release artifacts | **blocked — needs a git remote** | `local/6.1/` |
| 6.2 Install on a clean machine | **partial — macOS only** | `local/6.2/` |
| 6.3 Runs as a service, survives reboot | **partial — no reboot** | `local/6.3/` |
| 6.4 Pairing walkthrough | **partial — no second person** | `local/6.4/` |

Everything from P3 on was run with both roles on one machine, so it is all filed under
`local/` per the [filing rules](../docs/e2e-testing.html) — including the checks the
coverage matrix marks full fidelity, where the substitution costs nothing and the local
run *is* the check. `local/harness/` holds the scripts, so any of it can be re-run
verbatim: `bash local/harness/run-all.sh` for P3–P4, `p51.sh`/`p52.sh`/`p53.sh` for P5,
`p61.sh` … `p64.sh` for P6 (6.1 first — 6.2 and 6.4 install what it builds).

Results and the findings each phase produced:
[P0–P2](../docs/p0-p2-results.html) · [P3–P4](../docs/p3-p4-results.html) ·
[P5–P6 and the final report](../docs/p5-p6-results.html).

## What is left, by cause

**No second machine** — 1.2, 3.1, 5.2's asymmetric case, 6.3's far-side observer, and
2.2 below. One kernel, one hostname, one clock; `hostname` cannot distinguish the ends
and a Wi-Fi flap takes both roles down together.

**No git remote** — 0.2 and 6.1. `.github/workflows/ci.yml` builds and tests on
`ubuntu-latest`, `macos-latest` and `windows-latest`; `release.yml` turns a `v*` tag into
four archives with checksums. Both parse; neither has ever run.

```
git remote add origin git@github.com:<you>/RustTunnel.git
git push -u origin main          # 0.2 — file 0.2/ci-run.png and the run URL
git tag v0.1.0 && git push --tags # 6.1 — file 6.1/release.png and the artifact list
```

Nothing in the test suite touches the network — the allowlist test binds `127.0.0.1:0`
with `presets::Minimal`, no relay and no discovery — so the runners need no egress.

**No admin** — 6.2 on a fresh user account, 5.2's `pfctl` path-failure rule, and the
`--tcp 22` examples (Remote Login is off and turning it on needs an administrator).
Fresh `HOME`s with stripped `PATH`s stand in for fresh accounts.

**Needs time or a human** — 5.3 wants 24 hours (`p53.sh` with no arguments does exactly
that; the filed run is one hour), 6.3 wants a real reboot, 6.4 wants a person who did
not write the walkthrough.

## 2.2 — the risk gate, still open

This is the one task that can invalidate the design, and it cannot be faked locally:
loopback has nothing to traverse. It needs the home box on the home ISP and the laptop
tethered to a phone on cellular.

```
# home box
rtun id                                  # -> ID_HOME
rtun serve --tcp 22 --allow $ID_LAPTOP 2>&1 | tee serve.log

# laptop, on cellular tethering — NOT the home Wi-Fi
rtun id                                  # -> ID_LAPTOP
rtun connect $ID_HOME --tcp 2222:22 2>&1 | tee connect.log
```

Pass condition: **both** logs independently reach `path=direct`. Note that establishment
is `path=relayed` and the upgrade follows — that is the design, not a failure; wait for
the `path selected ... path=direct` line. File both logs plus a first line in
`2.2/session.txt` naming both networks and both carriers.

If it stays `relayed` on both sides, stop. Try a third network first — one symmetric NAT
is survivable, two are not. If a third network also fails, the premise of v2 is
unavailable on the networks you have; see the gate condition in the WBS.

## 3.1 and 4.2 — what is left

3.1's evidence line wants "the local hostname before connecting and the remote hostname
inside the session". One machine has one hostname. The token check filed instead is
stronger about the byte path and silent about reaching another host.

4.2 wants `wg show` reporting a recent handshake and a ping crossing the interface. Two
`utun`s on one host compete for routes to the same address space, so a failure would be
as likely to be macOS routing as rtun. The substitute covers what 4.2 adds over 4.1 —
sustained bidirectional flow from a fixed source port near the size cap — and nothing
more. Two Linux containers with `NET_ADMIN` are the cheap way to close it.
