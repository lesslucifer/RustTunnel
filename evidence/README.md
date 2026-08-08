# Evidence ledger — P0, P1, P2

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
| 1.2 Dial by endpoint ID | **partial — one machine only** | `1.2/{session.txt,serve.log,connect.log}` |
| 1.3 Peer allowlist | **done** | `1.3/session.txt` |
| 2.1 Path reporting | **done** | `2.1/session.txt` |
| 2.2 Cross-NAT direct connection | **not run — needs a second network** | see below |
| 2.3 Relay fallback works | **done** | `2.3/{session.txt,serve.log,connect.log}` |

## 0.2 — what is left

`.github/workflows/ci.yml` builds and tests on `ubuntu-latest`, `macos-latest` and
`windows-latest`. The check is a green run on all three, which needs a push:

```
git remote add origin git@github.com:<you>/RustTunnel.git
git push -u origin main
```

Then file `0.2/ci-run.png` and the run URL in `0.2/session.txt`. Nothing in the test
suite touches the network — the allowlist test binds `127.0.0.1:0` with
`presets::Minimal`, no relay and no discovery — so the runners need no egress.

## 1.2 — what is left

The captured run has both roles on one machine with separate `RTUN_STATE_DIR`s. The
target says the connecting side must be a **different machine**. Copy the binary to the
second box and repeat; the log lines to look for are unchanged.

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
unavailable on the networks you have; see the gate condition in the WBS. Do not start P3
on a relayed-only result.
