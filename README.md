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

```sh
watchctl doctor --config lab/config.json --trust lab/trust.json --json
watchctl serve --config lab/config.json --lab &
watchctl policy activate --file lab/policy.json --expected-generation 0 --request r1 --json
watchctl run open --file lab/run.json --request r2 --json
watchctl observe --file lab/observation.json --request r3 --json
watchctl check --file lab/check.json --request r4 --wait --json
watchctl verify --bundle bundle.json --trust lab/trust.json --json
```

Every guarded dispatch additionally requires the runtime's own authorization,
budget reservation, target freshness, and consume-once record — a Watch
clearance is an observation certificate, not a capability.

## Product status

`product_status` is `UNWRITTEN_GATED` everywhere, including `system.status`.
Nothing here satisfies the Covenant v1 gate, changes product labels, or claims
a sibling integration. Proof/Weather adapters are documented stub interfaces
that fail closed with `GATED`, not fake working code.
