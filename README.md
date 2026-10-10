# Watch — LatticeAGI

[![LatticeAG zone](https://img.shields.io/badge/LatticeAG-Watch-111111)](https://github.com/LatticeAG)
[![Status](https://img.shields.io/badge/status-UNWRITTEN%E2%80%94GATED%20BEHIND%20COVENANT%20v1-amber)](https://github.com/LatticeAG)
[![Protocol](https://img.shields.io/badge/protocol-watch%2F1-111111)](https://github.com/LatticeAG)
[![License](https://img.shields.io/badge/license-MIT-111111)](LICENSE)
[![CI](https://img.shields.io/badge/ci-conformance%20suite-111111)](.github/workflows/ci.yml)

> **Watches run beside the work, not inside it.**
> Watchers, detectors, and audit math observe the run. Chain of thought is a signal, never a proof.

**Status: UNWRITTEN — GATED BEHIND COVENANT v1.** This repository is the open-source
core of the Watch zone: deterministic blocking/trailing monitors, drift detection,
audit arithmetic, the human remainder queue, signed evidence, and the offline
bundle verifier. It is not a release, a hosted service, or a safety certification.

## What Watch is

Watch is a sidecar. An untrusted agent's runtime publishes signed, hash-chained
observations; a runtime guard blocks each protected dispatch while Watch
evaluates pinned deterministic monitors:

| Surface | What it does |
|---|---|
| `watchd` | Single-writer daemon. AF_UNIX `control.sock` with `SO_PEERCRED` role auth, WAL SQLite authority, signed audit chain, monitor workers. |
| `watchctl` | Operator/runtime/reviewer/auditor CLI. Same commands online and offline; strict exit-code contract. |
| `sdk/` | Zero-dependency TypeScript client + Ed25519/JCS helpers for integrators. |
| `watch-harness` | Conformance runner for the `TV-W-*` vector set. |

* Blocking `CLEAR` means only *no Watch veto at this bound cut* — never authorization.
* Trailing monitors review closed windows after durable ingestion; they never
  delay an authorized operation and never claim to prevent past effects.
* Ambiguous remainder goes to humans on one coherent card with exact basis,
  bounded acceptance, and attributable resolution. There is no fail-open.
* Export produces `watch-proof/1` bundles; the offline verifier reports
  `FULL_REPLAY` / `INTEGRITY_ONLY` / `INCOMPLETE` / `INVALID` with
  `facts_verified: false` — always.

## Layout

```
crates/watch   Rust workspace crate: protocol, reducers, store, daemon, CLI
sdk/           TypeScript SDK (Node >= 20, zero dependencies)
```

## Build

```sh
cargo build --release          # watchd, watchctl, watch-harness
cargo test                     # conformance suite (72 vectors + lifecycle)
```

## Lab quickstart (inert fixture profile `fixture/1`)

The lab adapter exposes two inert tools, `record.read` and `record.write`.
It cannot contact Stripe or any external provider.

The `lab/` files the commands below reference are **generated**, not shipped:
`cargo run --example mk_smoke` materializes a complete lab deployment under
`/tmp/watch-smoke` — `config.json`, `trust.json`, an **unsigned** policy body
(`policy.json`), monitor artifacts, key material, a signed `observation.json`,
and a ready-made `check.json` for a guarded `record.read` dispatch.

```sh
# 1. Build, then generate the fixture deployment -> /tmp/watch-smoke
cargo build --release
cargo run --example mk_smoke
export PATH="$PWD/target/release:$PATH"
```

`doctor` on the fresh fixture reports `SCHEMA_INVALID` on the `permissions`
check: `mk_smoke` writes the key files group/world-readable, and the check
requires owner-only key material. Tighten the mode and re-run:

```sh
chmod 600 /tmp/watch-smoke/test-key.bin /tmp/watch-smoke/object-key.bin
watchctl doctor --config /tmp/watch-smoke/config.json --trust /tmp/watch-smoke/trust.json --json
# -> {"ready":true,...}
```

Serve the daemon. `--lab` is required (and refused) for anything but a
`deployment: "lab"` config:

```sh
watchd --config /tmp/watch-smoke/config.json --lab &
```

Caller identity comes from `SO_PEERCRED` — the OS uid of the connecting
process maps to a configured `principals[]` entry; there is no flag or request
field for it. The fixture pins synthetic uids (`runtime1`=1002,
`operator1`=1003, `reviewer1`=1004, `auditor1`=1005) that need not exist as
OS users. On a single-user dev box, drive each role by setting the uid of the
CLI process, e.g. `sudo setpriv --reuid <uid> --clear-groups watchctl ...` —
which is what each role-gated step below uses.

```sh
# 2. Sign the policy body offline (any uid — it must be able to read the
#    key file, so run as the fixture's owner), then activate it (operator,
#    uid 1003). `activate` requires the signed envelope, not the body.
watchctl policy sign \
  --file /tmp/watch-smoke/policy.json --key /tmp/watch-smoke/test-key.bin \
  --key-id test_key --key-epoch 1 --out /tmp/policy.signed.json
chmod 644 /tmp/policy.signed.json   # --out files are written mode 0600
sudo setpriv --reuid 1003 --clear-groups \
  watchctl --socket /tmp/watch-smoke/control.sock policy activate \
  --file /tmp/policy.signed.json --expected-generation 0 --json
# -> {"digest":"<policy digest>","generation":"1","id":"wtp_1"}

# 3. Open a GUARDED run as the source's runtime principal (uid 1002).
#    runs.open fields: id, source, source_epoch, guard_epoch, boot, mode,
#    profile, policy — `policy` is the activated digest from step 2 and
#    `boot` is this machine's boot id (/proc/sys/kernel/random/boot_id).
BOOT=$(cat /proc/sys/kernel/random/boot_id)
POL=<digest printed by policy activate>
printf '{"id":"wtr_smoke1","source":"source1","source_epoch":"1","guard_epoch":"1","boot":"%s","mode":"GUARDED","profile":"fixture/1","policy":"%s"}' \
  "$BOOT" "$POL" > /tmp/watch-smoke/run.json
sudo setpriv --reuid 1002 --clear-groups \
  watchctl --socket /tmp/watch-smoke/control.sock run open \
  --file /tmp/watch-smoke/run.json --json
# -> {"id":"wtr_smoke1","revision":"1","state":"OPEN"}

# 4. Append the signed observation and evaluate a guarded dispatch (runtime).
sudo setpriv --reuid 1002 --clear-groups \
  watchctl --socket /tmp/watch-smoke/control.sock observe \
  --file /tmp/watch-smoke/observation.json --json
sudo setpriv --reuid 1002 --clear-groups \
  watchctl --socket /tmp/watch-smoke/control.sock check \
  --file /tmp/watch-smoke/check.json --wait --json
# -> ... "state":"CLEAR" plus the signed clearance envelope
# If the observation trips SOURCE_STALE (its cut is older than the policy's
# 120 s freshness window), regenerate it at the live clock:
#   cargo run --example mk_smoke -- obs 1

# 5. Export a watch-proof/1 bundle (auditor, uid 1005) and verify it offline.
#    `through` bounds the export at a chain head {seq,hash} — take it from
#    the last `events` line (body.seq + top-level digest).
sudo setpriv --reuid 1005 --clear-groups \
  watchctl --socket /tmp/watch-smoke/control.sock events --after 0 --limit 128 \
  | tail -n1 \
  | python3 -c 'import json,sys; e=json.load(sys.stdin); print(json.dumps({"seq":e["body"]["seq"],"hash":e["digest"]}))' \
  > /tmp/watch-smoke/through.json
sudo setpriv --reuid 1005 --clear-groups \
  watchctl --socket /tmp/watch-smoke/control.sock export \
  --through-file /tmp/watch-smoke/through.json --disclosure FULL \
  --recipient auditor1 --out /tmp/watch-bundle.json --json
watchctl verify --bundle /tmp/watch-bundle.json \
  --trust /tmp/watch-smoke/trust.json --json
# -> {"status":"FULL_REPLAY","facts_verified":false,...}
```

Notes on identity and file modes:

- `policy sign --out` writes the signed envelope mode `0600` owned by the
  signing uid — the activating principal must be able to read it (`chmod`
  the file, as above, or sign under the operator uid).
- All caller-role examples assume each `watchctl` step runs with the uid of
  the required role: `policy.activate` needs `operator`; `runs.open`,
  `observations.append`, `checks.create` need the run's `runtime` principal;
  `bundle.export` needs `auditor`. A caller whose uid maps to no configured
  principal gets `UNAUTHENTICATED`; the wrong role gets `FORBIDDEN`.
- `--socket` must point at the config's `socket` path — `watchctl` does not
  read the config file itself (offline commands like `doctor`, `policy sign`,
  `policy validate`, and `verify` reject `--socket`).

Every guarded dispatch additionally requires the runtime's own authorization,
budget reservation, target freshness, and consume-once record — a Watch
clearance is an observation certificate, not a capability.

## Product status

`product_status` is `UNWRITTEN_GATED` everywhere, including `system.status`.
Nothing here satisfies the Covenant v1 gate, changes product labels, or claims
a sibling integration. Proof/Weather adapters are documented stub interfaces
that fail closed with `GATED`, not fake working code.
