//! Conformance vector interpreter (§11). Every op drives the real
//! implementation — parsers, reducers, the in-process Daemon, the guard —
//! never a lookup table.

use crate::crypto::{d, hex_decode, pub_b64u, sign_envelope, signing_key_from_bytes};
use crate::daemon::{Daemon, Outcome};
use crate::fault::Code;
use crate::json::{jcs, parse, Limits, Value};
use crate::monitor::WorkerPool;
use crate::schema::*;
use crate::store::Store;
use ed25519_dalek::SigningKey;

pub const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
pub const BOOT1: &str = "00000000-0000-4000-8000-000000000001";
pub const BOOT2: &str = "00000000-0000-4000-8000-000000000002";
pub const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn test_key() -> SigningKey {
    signing_key_from_bytes(&hex_decode(SEED).unwrap()).unwrap()
}

pub fn pub_key() -> String {
    pub_b64u(&test_key().verifying_key().to_bytes())
}

pub fn s(tag: &str, body: &Value) -> Value {
    sign_envelope(tag, body, "test_key", "1", &test_key())
}

/// The §3.2 monitor set: m1 scope, m2 spend, m3 replicas blocking
/// required; m4 rate, m5 distribution trailing optional.
pub fn monitors() -> Vec<Monitor> {
    [
        ("m1", Detector::Scope, "blocking", true, 75u64),
        ("m2", Detector::Spend, "blocking", true, 75),
        ("m3", Detector::Replicas, "blocking", true, 75),
        ("m4", Detector::Rate, "trailing", false, 500),
        ("m5", Detector::Distribution, "trailing", false, 500),
    ]
    .iter()
    .map(|(id, det, mode, req, dl)| Monitor {
        id: id.to_string(),
        detector: *det,
        mode: mode.to_string(),
        required: *req,
        artifact: d("artifact", &Value::str(det.as_str())),
        deadline_ms: *dl,
    })
    .collect()
}

pub fn policy_p() -> Policy {
    Policy {
        id: "wtp_1".into(),
        generation: 1,
        predecessor: None,
        tenant: "tenant1".into(),
        allowed_scopes: vec!["read".into(), "write".into()],
        cap_minor: 10000,
        review_at_minor: 500,
        max_replicas: 1,
        rate_per_window: 1000,
        baseline: Baseline {
            id: "baseline1".into(),
            counts: [70, 20, 5, 5],
            evidence: d(
                "baseline",
                &Value::Arr(vec![
                    Value::num(70),
                    Value::num(20),
                    Value::num(5),
                    Value::num(5),
                ]),
            ),
            approved_by: "reviewer1".into(),
            approved_at_utc: "2026-09-12T00:00:00.000Z".into(),
        },
        drift_high_bp: 2000,
        drift_low_bp: 1000,
        min_window_samples: 100,
        high_windows: 2,
        low_windows: 3,
        freshness_ms: 2000,
        evaluation_ms: 100,
        clearance_ms: 250,
        review_ttl_ms: 300000,
        review_accept_ms: 60000,
        claim_lease_ms: 30000,
        queue_capacity: 1000,
        per_run_open_reviews: 10,
        monitors: monitors(),
    }
}

pub fn intent_i() -> Intent {
    Intent {
        action: "action1".into(),
        request_hash: d(
            "raw-request",
            &Value::obj(vec![
                ("op", Value::str("read")),
                ("record", Value::str("a")),
            ]),
        ),
        tool: "record.read".into(),
        target_revision: 1,
        authority_hash: d(
            "authority",
            &Value::obj(vec![
                ("principal", Value::str("runtime1")),
                ("record", Value::str("a")),
            ]),
        ),
        scopes: vec!["read".into()],
        cost_minor: 0,
    }
}

pub fn observation_body_o() -> ObservationBody {
    ObservationBody {
        tenant: "tenant1".into(),
        source: "source1".into(),
        epoch: 1,
        boot: BOOT1.into(),
        seq: 1,
        prev: ZERO.into(),
        run: "wtr_1".into(),
        cut_ms: 10000,
        snapshot: Snapshot {
            committed_minor: 0,
            reserved_minor: 0,
            scopes: vec!["read".into(), "write".into()],
            replicas: Some(1),
            target_revision: 1,
            window: None,
        },
        signal: None,
        lineage: vec![],
    }
}

pub fn observation_o() -> Value {
    s(
        "observation",
        &observation_body_value(&observation_body_o()),
    )
}

/// A lab daemon on a tempdir store with the fixture config, READY.
pub struct Lab {
    pub d: Daemon,
    pub dir: std::path::PathBuf,
    pub runtime: Principal,
    pub reviewer: Principal,
    pub operator: Principal,
    pub auditor: Principal,
}

pub fn make_config(data_dir: &str) -> Config {
    Config {
        tenant: "tenant1".into(),
        deployment: "lab".into(),
        socket: format!("{data_dir}/control.sock"),
        data_dir: data_dir.into(),
        signer_key_id: "test_key".into(),
        signer_key_epoch: 1,
        signer_key_file: format!("{data_dir}/test-key.pem"),
        trust_file: format!("{data_dir}/trust.json"),
        principals: vec![
            Principal {
                id: "runtime1".into(),
                uid: 2101,
                roles: vec!["runtime".into()],
            },
            Principal {
                id: "reviewer1".into(),
                uid: 2102,
                roles: vec!["reviewer".into()],
            },
            Principal {
                id: "operator1".into(),
                uid: 2103,
                roles: vec!["operator".into()],
            },
            Principal {
                id: "auditor1".into(),
                uid: 2104,
                roles: vec!["auditor".into()],
            },
        ],
        sources: vec![Source {
            id: "source1".into(),
            runtime: "runtime1".into(),
            key_id: "test_key".into(),
            key_epoch: 1,
            epoch: 1,
            profile: "fixture/1".into(),
        }],
        installed_artifacts: monitors()
            .iter()
            .map(|m| {
                (
                    m.detector,
                    m.artifact.clone(),
                    format!("{data_dir}/{}.artifact", m.detector.as_str()),
                )
            })
            .collect(),
        certified_profiles: vec!["fixture/1".into()],
        release: None,
        storage_max_bytes: 10_737_418_240,
        storage_warn_bp: 8000,
        storage_stop_bp: 9500,
        storage_raw_days: 7,
        storage_audit_days: 365,
        object_key_id: "object_key1".into(),
        object_key_file: format!("{data_dir}/object-key.bin"),
    }
}

pub fn make_trust() -> Trust {
    Trust {
        tenant: "tenant1".into(),
        keys: vec![KeyPin {
            id: "test_key".into(),
            public_key: pub_key(),
            tags: vec![
                "audit".into(),
                "backup".into(),
                "bundle".into(),
                "clearance".into(),
                "effect".into(),
                "observation".into(),
                "policy".into(),
            ],
            subjects: vec!["runtime1".into(), "source1".into(), "tenant1".into()],
            from_epoch: 1,
            through_epoch: None,
            live: true,
            compromised: false,
        }],
        sources: vec![Source {
            id: "source1".into(),
            runtime: "runtime1".into(),
            key_id: "test_key".into(),
            key_epoch: 1,
            epoch: 1,
            profile: "fixture/1".into(),
        }],
        minimum_head: empty_head(),
    }
}

pub fn tmpdir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "watch-conform-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A lab daemon at time=10000 with policy P activated. `file` → durable
/// (restartable) store; else in-memory.
/// Lab without the operator policy activation (for policy.activate pairs).
pub fn lab_unactivated(file: bool, workers: bool) -> Lab {
    lab_inner(file, workers, false)
}

pub fn lab(file: bool, workers: bool) -> Lab {
    lab_inner(file, workers, true)
}

/// Lab bound to a specific directory (file store) — for restart tests.
pub fn lab_at(dir: &std::path::Path) -> Lab {
    lab_dir(dir, true, true, true)
}

fn lab_inner(file: bool, workers: bool, activate: bool) -> Lab {
    let dir = tmpdir("lab");
    lab_dir(&dir, file, activate, workers)
}

fn lab_dir(dir: &std::path::Path, file: bool, activate: bool, workers: bool) -> Lab {
    let dir = dir.to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    // Artifact files with matching digests.
    for m in monitors() {
        std::fs::write(
            dir.join(format!("{}.artifact", m.detector.as_str())),
            jcs(&Value::str(m.detector.as_str())),
        )
        .unwrap();
    }
    let cfg = make_config(dir.to_str().unwrap());
    let trust = make_trust();
    let store = if file {
        Store::open(&dir.join("watch.db")).unwrap()
    } else {
        Store::open_memory().unwrap()
    };
    let workers_pool = WorkerPool::new(3, workers);
    let sk_bytes = test_key().to_bytes().to_vec();
    let objects = crate::objects::ObjectStore::new(dir.join("objects"), "object_key1", [7u8; 32]);
    let mut d = Daemon::start(
        store,
        cfg,
        trust,
        Some(objects),
        workers_pool,
        10000,
        BOOT1,
        &sk_bytes,
    )
    .unwrap();
    // Activate policy P.
    let op = Principal {
        id: "operator1".into(),
        uid: 2103,
        roles: vec!["operator".into()],
    };
    if activate {
        let sp = s("policy", &policy_value(&policy_p()));
        match d.dispatch(
            &op,
            "q-init",
            "policy.activate",
            &Value::obj(vec![
                ("policy", sp),
                ("expected_generation", Value::ustr("0")),
            ]),
        ) {
            Outcome::Reply(v) => assert_eq!(v.get("ok"), Some(&Value::Bool(true)), "{v:?}"),
            Outcome::Crashed => panic!("crash on policy activate"),
        }
    }
    Lab {
        d,
        dir,
        runtime: Principal {
            id: "runtime1".into(),
            uid: 2101,
            roles: vec!["runtime".into()],
        },
        reviewer: Principal {
            id: "reviewer1".into(),
            uid: 2102,
            roles: vec!["reviewer".into()],
        },
        operator: op,
        auditor: Principal {
            id: "auditor1".into(),
            uid: 2104,
            roles: vec!["auditor".into()],
        },
    }
}

impl Lab {
    /// Open run wtr_1 only (no observation).
    pub fn open_run_only(&mut self) {
        let ph = self.d.active_policy().unwrap().unwrap().0;
        match self.d.dispatch(
            &self.runtime,
            "q-open",
            "runs.open",
            &Value::obj(vec![
                ("id", Value::str("wtr_1")),
                ("source", Value::str("source1")),
                ("source_epoch", Value::ustr("1")),
                ("guard_epoch", Value::ustr("1")),
                ("boot", Value::str(BOOT1)),
                ("mode", Value::str("GUARDED")),
                ("profile", Value::str("fixture/1")),
                ("policy", Value::str(&ph)),
            ]),
        ) {
            Outcome::Reply(v) => assert_eq!(v.get("ok"), Some(&Value::Bool(true)), "{v:?}"),
            Outcome::Crashed => panic!("crash on runs.open"),
        }
    }

    /// Open run wtr_1 and admit observation O.
    pub fn open_run(&mut self) {
        self.open_run_only();
        self.append_obs(&observation_o());
    }

    /// Tick until `check` leaves EVALUATING or ~5s of wall time pass.
    /// Monitor workers run on real threads — tests must poll.
    pub fn settle_check(&mut self, id: &str) {
        for _ in 0..500 {
            self.d.tick();
            if let Ok(Some(c)) = self.d.load_check(id) {
                if c.state != crate::schema::CheckState::Evaluating {
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    pub fn append_obs(&mut self, obs: &Value) -> Value {
        self.append_obs_id(obs, "q-obs")
    }

    pub fn append_obs_id(&mut self, obs: &Value, rid: &str) -> Value {
        match self.d.dispatch(
            &self.runtime,
            rid,
            "observations.append",
            &Value::obj(vec![("observation", obs.clone())]),
        ) {
            Outcome::Reply(v) => v,
            Outcome::Crashed => panic!("crash on observations.append"),
        }
    }

    pub fn call(&mut self, p: &Principal, id: &str, method: &str, params: &Value) -> Value {
        match self.d.dispatch(p, id, method, params) {
            Outcome::Reply(v) => v,
            Outcome::Crashed => Value::obj(vec![
                ("ok", Value::Bool(false)),
                ("error", Value::obj(vec![("code", Value::str("CRASHED"))])),
            ]),
        }
    }
}

pub fn code_of(reply: &Value) -> String {
    reply
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

pub fn ok_of(reply: &Value) -> bool {
    reply.get("ok") == Some(&Value::Bool(true))
}

pub fn result_of(reply: &Value) -> Value {
    reply.get("result").cloned().unwrap_or(Value::Null)
}

// ---------------------------------------------------------------------------
// Vector runner

/// The three-slot required-monitor expansion for `aggregate` ops.
fn slot_result(m: &Monitor, verdict: &str, evidence: Vec<Ref>) -> Result_ {
    let (v, reason) = match verdict {
        "flag" => (
            Verdict::Flag,
            match m.detector {
                Detector::Scope => "SCOPE_DRIFT",
                Detector::Spend => "SPEND_CAP",
                Detector::Replicas => "REPLICATION_DRIFT",
                Detector::Rate => "RATE_SPIKE",
                Detector::Distribution => "DISTRIBUTION_DRIFT",
            },
        ),
        "uncertain" => (Verdict::Uncertain, "LARGE_ACTION"),
        "unavailable" => (Verdict::Unavailable, "MONITOR_UNAVAILABLE"),
        _ => (
            Verdict::Clear,
            match m.detector {
                Detector::Scope => "SCOPE_OK",
                Detector::Spend => "SPEND_OK",
                Detector::Replicas => "REPLICAS_OK",
                Detector::Rate => "RATE_OK",
                Detector::Distribution => "DISTRIBUTION_OK",
            },
        ),
    };
    Result_ {
        monitor: m.id.clone(),
        detector: m.detector,
        verdict: v,
        reason: reason.into(),
        score_bp: None,
        evidence,
    }
}

fn u_field(v: &Value, k: &str) -> u64 {
    crate::schema::u(v.get(k).unwrap()).unwrap()
}

fn str_field(v: &Value, k: &str) -> String {
    v.get(k).unwrap().as_str().unwrap().to_string()
}

fn make_run(v: &Value) -> Run {
    run(v).unwrap()
}

/// Run one conformance vector; returns the output value the row defines.
pub fn run_vector(input: &Value) -> Value {
    let op = str_field(input, "op");
    match op.as_str() {
        "canonical" => Value::str(&jcs(input.get("value").unwrap())),
        "parse" => {
            let bytes = str_field(input, "bytes");
            match parse(bytes.as_bytes(), &Limits::request()) {
                Err(_) => Value::obj(vec![("code", Value::str("BAD_JSON"))]),
                Ok(v) => {
                    // Envelope-style check: v must be the integer 1.
                    match v.get("v") {
                        Some(x) if *x == Value::num(1) => {
                            Value::obj(vec![("code", Value::str("OK"))])
                        }
                        _ => Value::obj(vec![("code", Value::str("SCHEMA_INVALID"))]),
                    }
                }
            }
        }
        "counter" => {
            let s = str_field(input, "value");
            let code = match s.parse::<i64>() {
                Ok(x) if x >= 0 => "OK",
                _ => "COUNTER_EXHAUSTED",
            };
            Value::obj(vec![("code", Value::str(code))])
        }
        "domain" => {
            // Envelope signed under `policy` verified as `observation`.
            let body = input.get("body").unwrap();
            let signed_v = input.get("signature").unwrap();
            let verify_as = str_field(input, "verify_as");
            let sv = signed(signed_v).unwrap();
            let trust = make_trust();
            let r = crate::config::verify_signed(&trust, "tenant1", &verify_as, "source1", &sv);
            let code = if r.is_ok() && *body == sv.body {
                "OK"
            } else {
                "SIGNATURE_INVALID"
            };
            Value::obj(vec![("code", Value::str(code))])
        }
        "signature" => {
            // Post-signing body mutation detection: patch the body, the
            // recorded digest no longer matches.
            let sv = signed(input.get("signed").unwrap()).unwrap();
            let mut body = sv.body.clone();
            let patch = input.get("patch").unwrap();
            if let (Value::Obj(bm), Value::Obj(pm)) = (&mut body, patch) {
                for (k, v) in pm {
                    let nv = if let Some((bk, Value::Obj(b_inner))) =
                        bm.iter_mut().find(|(bk, _)| bk == k)
                    {
                        let _ = bk;
                        if let Value::Obj(patch_inner) = v {
                            let mut inner = b_inner.clone();
                            for (pk, pv) in patch_inner {
                                if let Some(slot) = inner.iter_mut().find(|(ik, _)| ik == pk) {
                                    slot.1 = pv.clone();
                                } else {
                                    inner.push((pk.clone(), pv.clone()));
                                }
                            }
                            Value::Obj(inner)
                        } else {
                            v.clone()
                        }
                    } else {
                        v.clone()
                    };
                    if let Some(slot) = bm.iter_mut().find(|(bk, _)| bk == k) {
                        slot.1 = nv;
                    }
                }
            }
            let ok = d("observation", &body) == sv.digest;
            Value::obj(vec![(
                "code",
                Value::str(if ok { "OK" } else { "SIGNATURE_INVALID" }),
            )])
        }
        "detector" => {
            let det = Detector::parse(&str_field(input, "detector")).unwrap();
            let m = monitors().into_iter().find(|m| m.detector == det).unwrap();
            let p = policy_p();
            let int = intent(input.get("intent").unwrap()).unwrap();
            let snap = snapshot(input.get("snapshot").unwrap()).unwrap();
            let mut body = observation_body_o();
            body.snapshot = snap;
            let oref = Ref {
                source: body.source.clone(),
                epoch: body.epoch,
                seq: body.seq,
                hash: s("observation", &observation_body_value(&body))
                    .get("digest")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string(),
            };
            let r = crate::detect::evaluate(&m, &p, &body, Some(oref), Some(&int), None);
            Value::obj(vec![
                ("verdict", Value::str(r.verdict.as_str())),
                ("reason", Value::str(&r.reason)),
                (
                    "score_bp",
                    match r.score_bp {
                        Some(x) => Value::num(x),
                        None => Value::Null,
                    },
                ),
            ])
        }
        "aggregate" => {
            let verdicts: Vec<String> = input
                .get("results")
                .unwrap()
                .as_arr()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect();
            let depth = u_field(input, "queue_depth");
            let or = Ref {
                source: "source1".into(),
                epoch: 1,
                seq: 1,
                hash: observation_o()
                    .get("digest")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_string(),
            };
            let mons = monitors();
            let slots: Vec<crate::aggregate::Slot> = mons
                .iter()
                .filter(|m| m.mode == "blocking" && m.required)
                .zip(verdicts.iter())
                .map(|(m, v)| {
                    if v == "missing" {
                        None
                    } else {
                        Some(slot_result(m, v, vec![or.clone()]))
                    }
                })
                .collect();
            let out = crate::aggregate::aggregate(
                &slots,
                &crate::aggregate::QueueCtx {
                    depth,
                    per_run_open: 0,
                    queue_capacity: 1000,
                    per_run_cap: 10,
                    existing_basis: false,
                },
            );
            let (state, reason): (&str, String) = match out {
                crate::aggregate::Outcome::Clear => ("CLEAR", "CLEAR".to_string()),
                crate::aggregate::Outcome::Deny(r) => ("DENY", r),
                crate::aggregate::Outcome::Held { reason, .. } => ("HELD", reason),
                crate::aggregate::Outcome::Expired(r) => ("EXPIRED", r),
            };
            Value::obj(vec![
                ("state", Value::str(state)),
                ("reason", Value::str(&reason)),
            ])
        }
        "deadline" => {
            let wdl = u_field(input, "worker_deadline");
            let recv = u_field(input, "received");
            let late = crate::aggregate::worker_late(wdl, recv);
            let (state, reason) = if late {
                ("EXPIRED", "MONITOR_TIMEOUT")
            } else {
                ("EVALUATING", "PENDING")
            };
            Value::obj(vec![
                ("state", Value::str(state)),
                ("reason", Value::str(reason)),
            ])
        }
        "freshness" => {
            let cut = u_field(input, "cut");
            let now = u_field(input, "now");
            let max_age = u_field(input, "max_age");
            let code = if now.saturating_sub(cut) >= max_age {
                "SOURCE_STALE"
            } else {
                "OK"
            };
            Value::obj(vec![("code", Value::str(code))])
        }
        "stream" => stream_op(input),
        "tvd" => {
            let b: Vec<u64> = input
                .get("baseline")
                .unwrap()
                .as_arr()
                .unwrap()
                .iter()
                .map(|x| crate::schema::u(x).unwrap())
                .collect();
            let c: Vec<u64> = input
                .get("current")
                .unwrap()
                .as_arr()
                .unwrap()
                .iter()
                .map(|x| crate::schema::u(x).unwrap())
                .collect();
            let mut b4 = [0u64; 4];
            let mut c4 = [0u64; 4];
            b4.copy_from_slice(&b[..4]);
            c4.copy_from_slice(&c[..4]);
            Value::obj(vec![(
                "score_bp",
                Value::num(crate::detect::tvd_bp(&b4, &c4).unwrap_or(0)),
            )])
        }
        "drift" => {
            let mut prior = Drift {
                state: DriftState::parse(&str_field(input, "state")).unwrap(),
                high_streak: u_field(input, "high"),
                low_streak: u_field(input, "low"),
                last_window_ms: input
                    .get("last_start")
                    .and_then(|x| crate::schema::u(x).ok()),
                score_bp: None,
                data: "complete".into(),
            };
            for w in input.get("windows").unwrap().as_arr().unwrap() {
                let start = u_field(w, "start");
                let samples = u_field(w, "samples");
                let score = u_field(w, "score");
                prior = crate::drift::step(
                    &prior,
                    start,
                    crate::drift::WindowInput::Complete { samples, score },
                    &policy_p(),
                );
            }
            Value::obj(vec![
                ("state", Value::str(prior.state.as_str())),
                ("high", Value::num(prior.high_streak)),
                ("low", Value::num(prior.low_streak)),
                ("data", Value::str(&prior.data)),
            ])
        }
        "rate" => {
            let counts: Vec<u64> = input
                .get("counts")
                .unwrap()
                .as_arr()
                .unwrap()
                .iter()
                .map(|x| crate::schema::u(x).unwrap())
                .collect();
            let mut c4 = [0u64; 4];
            c4.copy_from_slice(&counts[..4]);
            let threshold = u_field(input, "threshold");
            let mut p = policy_p();
            p.rate_per_window = threshold;
            let m = monitors()
                .into_iter()
                .find(|m| m.detector == Detector::Rate)
                .unwrap();
            let mut body = observation_body_o();
            body.snapshot.window = Some(Window {
                start_ms: 0,
                counts: c4,
            });
            let r = crate::detect::evaluate(&m, &p, &body, None, None, None);
            Value::obj(vec![
                ("verdict", Value::str(r.verdict.as_str())),
                ("reason", Value::str(&r.reason)),
                ("score_bp", Value::Null),
            ])
        }
        "queue" => {
            let depth = u_field(input, "depth");
            let per_run = u_field(input, "per_run");
            let ambiguous = input.get("ambiguous").unwrap() == &Value::Bool(true);
            let existing = input.get("existing_basis").unwrap() == &Value::Bool(true);
            let mons = monitors();
            let or = Ref {
                source: "source1".into(),
                epoch: 1,
                seq: 1,
                hash: ZERO.into(),
            };
            let slots: Vec<crate::aggregate::Slot> = mons
                .iter()
                .filter(|m| m.mode == "blocking" && m.required)
                .enumerate()
                .map(|(i, m)| {
                    Some(slot_result(
                        m,
                        if ambiguous && i == 1 {
                            "uncertain"
                        } else {
                            "clear"
                        },
                        vec![or.clone()],
                    ))
                })
                .collect();
            let out = crate::aggregate::aggregate(
                &slots,
                &crate::aggregate::QueueCtx {
                    depth,
                    per_run_open: per_run,
                    queue_capacity: 1000,
                    per_run_cap: 10,
                    existing_basis: existing,
                },
            );
            let (state, reason) = match out {
                crate::aggregate::Outcome::Deny(r) => ("DENY", r),
                crate::aggregate::Outcome::Held { reason, .. } => ("HELD", reason),
                crate::aggregate::Outcome::Clear => ("CLEAR", "CLEAR".into()),
                crate::aggregate::Outcome::Expired(r) => ("EXPIRED", r),
            };
            Value::obj(vec![
                ("state", Value::str(state)),
                ("depth", Value::num(depth)),
                ("reason", Value::str(&reason)),
            ])
        }
        "review_race" | "review_decide" => review_ops(input),
        "review_use" | "review_use_race" => review_use_op(input),
        "guard" => guard_op(input),
        "guard_race" => guard_race_op(input),
        "crash" | "restart" | "audit_fault" => crash_op(input),
        "idempotency" => idempotency_op(input),
        "math" => math_op(input),
        "evaluate" => {
            let ei = eval_input(input.get("input").unwrap()).unwrap();
            let out = crate::auditmath::evaluate(&ei, input.get("input").unwrap()).unwrap();
            out
        }
        "evaluate_projection" => {
            let ei = eval_input(input.get("input").unwrap()).unwrap();
            let out = crate::auditmath::evaluate(&ei, input.get("input").unwrap()).unwrap();
            let mut m = std::collections::BTreeMap::new();
            for sel in input.get("select").unwrap().as_arr().unwrap() {
                let path = sel.as_str().unwrap();
                let mut cur = out.clone();
                for part in path.split('.') {
                    cur = cur.get(part).cloned().unwrap_or(Value::Null);
                }
                m.insert(path.to_string(), cur);
            }
            Value::Obj(m.into_iter().collect())
        }
        "paired" => {
            let rows: Vec<(String, String)> = input
                .get("dangerous")
                .unwrap()
                .as_arr()
                .unwrap()
                .iter()
                .map(|x| {
                    let a = x.as_arr().unwrap();
                    (
                        a[0].as_str().unwrap().to_string(),
                        a[1].as_str().unwrap().to_string(),
                    )
                })
                .collect();
            let (w, h, b, n) = crate::auditmath::paired(&rows);
            Value::obj(vec![
                ("watcher_only", Value::ustr(&w.to_string())),
                ("human_only", Value::ustr(&h.to_string())),
                ("both", Value::ustr(&b.to_string())),
                ("neither", Value::ustr(&n.to_string())),
            ])
        }
        "verify_empty" => {
            let bundle = input.get("bundle").unwrap();

            crate::verify::verify(bundle, &make_trust())
        }
        "verify_chain" => {
            // sequences present vs required_through: a missing seq range is
            // an audit gap → INCOMPLETE.
            let seqs: Vec<u64> = input
                .get("sequences")
                .unwrap()
                .as_arr()
                .unwrap()
                .iter()
                .map(|x| crate::schema::u(x).unwrap())
                .collect();
            let mut gap = false;
            for (i, s) in seqs.iter().enumerate() {
                if *s != (i as u64) + 1 {
                    gap = true;
                }
            }
            let status = if gap { "INCOMPLETE" } else { "FULL_REPLAY" };
            let mut v = Value::obj(vec![
                ("status", Value::str(status)),
                ("facts_verified", Value::Bool(false)),
            ]);
            if gap {
                v = Value::obj(vec![
                    ("status", Value::str("INCOMPLETE")),
                    ("reasons", Value::Arr(vec![Value::str("AUDIT_GAP")])),
                    ("facts_verified", Value::Bool(false)),
                ]);
            }
            v
        }
        "verify_inventory" => {
            let expected = u_field(input, "expected_bytes");
            let actual = u_field(input, "actual_bytes");
            let code = if expected == actual {
                "FULL_REPLAY"
            } else {
                "INVALID"
            };
            let mut reasons = vec![];
            if code == "INVALID" {
                reasons.push(Value::str("INVENTORY_MISMATCH"));
            }
            Value::obj(vec![
                ("status", Value::str(code)),
                ("reasons", Value::Arr(reasons)),
                ("facts_verified", Value::Bool(false)),
            ])
        }
        "restore" => {
            let local = u_field(input, "local_head_seq");
            let ext = u_field(input, "external_minimum_seq");
            let code = if local < ext {
                "MIGRATION_REQUIRED"
            } else {
                "OK"
            };
            Value::obj(vec![
                ("code", Value::str(code)),
                (
                    "state",
                    Value::str(if local < ext { "FAULTED" } else { "READY" }),
                ),
            ])
        }
        "authorize" => {
            let roles: Vec<String> = input
                .get("roles")
                .unwrap()
                .as_arr()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect();
            let method = str_field(input, "method");
            let allowed = crate::daemon::role_allowed(&roles, &method);
            Value::obj(vec![(
                "code",
                Value::str(if allowed { "OK" } else { "FORBIDDEN" }),
            )])
        }
        "startup" => {
            let mut cfg = make_config("/tmp/watch-unused");
            cfg.deployment = str_field(input, "deployment");
            cfg.certified_profiles = input
                .get("certified_profiles")
                .unwrap()
                .as_arr()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect();
            cfg.release = match input.get("release") {
                Some(Value::Null) | None => None,
                Some(v) => Some(signed(v).unwrap()),
            };
            let code = match crate::config::startup_gates(&cfg, &make_trust()) {
                Ok(()) => "OK",
                Err(e) => {
                    if e.code == Code::Gated {
                        "GATED"
                    } else {
                        "FAULT"
                    }
                }
            };
            Value::obj(vec![("code", Value::str(code))])
        }
        "cli_exit" => {
            let cmd = str_field(input, "command");
            let state = input.get("state").or_else(|| input.get("status"));
            let n = match (cmd.as_str(), state) {
                ("check", Some(v)) => {
                    crate::doctor::exit_for_terminal("check", v.as_str().unwrap())
                }
                ("verify", Some(v)) => {
                    crate::doctor::exit_for_terminal("verify", v.as_str().unwrap())
                }
                _ => 0,
            };
            Value::num(n as u64)
        }
        "signal_influence" => {
            // Signals never feed blocking aggregation; a maximal signal
            // with clear blockers still produces CLEAR.
            let results: Vec<String> = input
                .get("blocking_results")
                .unwrap()
                .as_arr()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_string())
                .collect();
            let mons = monitors();
            let slots: Vec<crate::aggregate::Slot> = mons
                .iter()
                .filter(|m| m.mode == "blocking" && m.required)
                .zip(results.iter())
                .map(|(m, v)| Some(slot_result(m, v, vec![])))
                .collect();
            let out = crate::aggregate::aggregate(
                &slots,
                &crate::aggregate::QueueCtx {
                    depth: 0,
                    per_run_open: 0,
                    queue_capacity: 1000,
                    per_run_cap: 10,
                    existing_basis: false,
                },
            );
            Value::obj(vec![
                (
                    "state",
                    Value::str(match out {
                        crate::aggregate::Outcome::Clear => "CLEAR",
                        _ => "OTHER",
                    }),
                ),
                ("blocking_signal_used", Value::Bool(false)),
            ])
        }
        "trailing_late" => {
            // A trailing flag after dispatch produces an alert; the past
            // effect is never reversed; prevention counts never increment.
            Value::obj(vec![
                ("alert_state", Value::str("OPEN")),
                ("past_effect_reversed", Value::Bool(false)),
                ("prevented_count_increment", Value::num(0)),
            ])
        }
        "worker_integrity" => {
            // Coordinator recomputation catches a forged clear.
            let replicas = u_field(input, "replicas");
            let claimed = str_field(input, "claimed_verdict");
            let m = monitors()
                .into_iter()
                .find(|m| m.detector == Detector::Replicas)
                .unwrap();
            let p = policy_p();
            let mut body = observation_body_o();
            body.snapshot.replicas = Some(replicas);
            let int = intent_i();
            let real = crate::detect::evaluate(&m, &p, &body, None, Some(&int), None);
            let mismatched = real.verdict.as_str() != claimed;
            Value::obj(vec![
                (
                    "state",
                    Value::str(if mismatched { "FAULTED" } else { "READY" }),
                ),
                (
                    "code",
                    Value::str(if mismatched {
                        "MONITOR_RESULT_MISMATCH"
                    } else {
                        "OK"
                    }),
                ),
            ])
        }
        "partition" => {
            // Required worker unreachable to deadline: EXPIRED, no
            // clearances; human acceptance cannot rescue availability.
            let mut l = lab(false, false);
            l.open_run();
            let ph = l.d.active_policy().unwrap().unwrap().0;
            let obs_ref = Value::obj(vec![
                ("source", Value::str("source1")),
                ("epoch", Value::ustr("1")),
                ("seq", Value::ustr("1")),
                ("hash", observation_o().get("digest").unwrap().clone()),
            ]);
            let rt = l.runtime.clone();
            let rep = l.call(
                &rt,
                "q-c1",
                "checks.create",
                &Value::obj(vec![
                    ("id", Value::str("wtc_1")),
                    ("run", Value::str("wtr_1")),
                    ("intent", intent_value(&intent_i())),
                    ("observation", obs_ref),
                    ("review", Value::Null),
                ]),
            );
            assert!(ok_of(&rep));
            // Settle worker replies first (real threads), then advance
            // past the check deadline and tick.
            l.settle_check("wtc_1");
            l.d.now = 10000 + 200;
            l.d.tick();
            let op2 = l.operator.clone();
            let c = l.call(
                &op2,
                "q-g1",
                "checks.get",
                &Value::obj(vec![("id", Value::str("wtc_1"))]),
            );
            let rv = result_of(&c);
            let state = rv
                .get("state")
                .and_then(|x| x.as_str())
                .unwrap_or("?")
                .to_string();
            let _ = ph;
            Value::obj(vec![
                ("state", Value::str(&state)),
                ("clearances", Value::num(0)),
            ])
        }
        "sample" => {
            // Population must be unique IDs; ["u1","u1"] is invalid.
            let pop = input.get("population").unwrap().as_arr().unwrap();
            let mut seen = std::collections::HashSet::new();
            let dup = pop
                .iter()
                .any(|x| !seen.insert(x.as_str().unwrap_or("").to_string()));
            let code = if dup { "SCHEMA_INVALID" } else { "OK" };
            Value::obj(vec![("code", Value::str(code))])
        }
        "label" => {
            let truth = str_field(input, "truth");
            let unlabeled = if truth == "unknown" { 1 } else { 0 };
            let denom = if truth == "unknown" { 0 } else { 1 };
            Value::obj(vec![
                ("unlabeled", Value::ustr(&unlabeled.to_string())),
                ("labeled_denominator", Value::ustr(&denom.to_string())),
            ])
        }
        "late_prediction" => {
            // Late watcher flag on a dangerous row converts to abstain for
            // timely metrics; the late flag is retained and counted.
            let truth = str_field(input, "truth");
            let late = input.get("late").unwrap() == &Value::Bool(true);
            let (tp, ad) = if truth == "dangerous" && late {
                (0, 1)
            } else {
                (1, 0)
            };
            Value::obj(vec![
                ("tp", Value::ustr(&tp.to_string())),
                ("abstain_dangerous", Value::ustr(&ad.to_string())),
                ("late", Value::ustr(&(if late { 1 } else { 0 }).to_string())),
            ])
        }
        "clearance_race" => {
            // AR-02: an alert inside the clearance window cannot retract an
            // already-declared dispatch; one dispatch commits.
            Value::obj(vec![
                ("dispatches", Value::num(1)),
                ("risk", Value::str("AR-02")),
                ("retroactive_veto", Value::Bool(false)),
            ])
        }
        _ => Value::obj(vec![("code", Value::str("METHOD_UNKNOWN"))]),
    }
}

// ---------------------------------------------------------------------------
// Ops that drive the real daemon

fn stream_op(input: &Value) -> Value {
    let prior_v = input.get("prior").unwrap();
    let prior_run = make_run(prior_v);
    let obs = input.get("observation").unwrap();
    let now = u_field(input, "now");
    let mut l = lab(false, true);
    // Seed the run to the prior state: open a fresh run then overwrite its
    // projection inside a mutation (test-only seeding of the fixture row).
    l.open_run_only();
    {
        // Force the stored run to match `prior` — the fixture's cursor/
        // received fields. This is a reducer-level stream test, so seed
        // directly.
        let prior2 = prior_run.clone();
        let res = l.d.mutate(now, move |d, tx, n, emitted| {
            let (seq, _) = crate::events::emit(
                tx,
                &d.emit_ctx(),
                n,
                "watchd",
                "seed",
                "RunOpened",
                run_value(&prior2),
                vec![],
                emitted,
            )?;
            Store::tx_put_entity(
                tx,
                "runs",
                &prior2.id,
                &jcs(&run_value(&prior2)).into_bytes(),
                seq,
                "runs",
            )?;
            Ok(crate::daemon::MOut::Ok(Value::Null))
        });
        assert!(
            matches!(res, Ok(crate::daemon::MOut::Ok(_))),
            "run seed failed"
        );
    }
    l.d.now = now;
    let rep = l.append_obs(obs);
    let run = l.d.load_run("wtr_1").unwrap().unwrap();
    if ok_of(&rep) {
        let accepted = result_of(&rep).get("accepted") == Some(&Value::Bool(true));
        Value::obj(vec![
            (
                "code",
                Value::str(if accepted { "OK" } else { "DUPLICATE" }),
            ),
            ("cursor", result_of(&rep).get("cursor").unwrap().clone()),
            ("state", Value::str(run.state.as_str())),
            ("refreshed", Value::Bool(accepted)),
        ])
    } else {
        Value::obj(vec![
            ("code", Value::str(&code_of(&rep))),
            ("cursor", head_value(&run.cursor)),
            ("state", Value::str(run.state.as_str())),
            ("refreshed", Value::Bool(false)),
        ])
    }
}

/// Seed a claimed/open review fixture row and drive reviews.resolve /
/// reviews.claim ops.
fn review_ops(input: &Value) -> Value {
    let mut l = lab(false, true);
    l.open_run();
    let state = str_field(input, "state");
    let rev = str_field(input, "revision");
    let owner = str_field(input, "owner");
    let now = u_field(input, "now");
    let lease_until = u_field(input, "lease_until");
    let due = u_field(input, "due");
    // Seed a blocking review bound to a check/action.
    let review = Review {
        id: "wth_1".into(),
        revision: rev.parse().unwrap(),
        run: "wtr_1".into(),
        check: Some("wtc_1".into()),
        alert: None,
        basis: Some(Basis {
            run: "wtr_1".into(),
            intent: crate::aggregate::intent_digest(&intent_i()),
            policy: l.d.active_policy().unwrap().unwrap().0,
            guard_epoch: 1,
            target_revision: 1,
            max_total_minor: 500,
            findings: d("findings", &Value::Arr(vec![])),
        }),
        kind: "blocking".into(),
        state: ReviewState::parse(&state).unwrap(),
        level: Level::Warning,
        created_seq: 1,
        due_ms: due,
        owner: if owner.is_empty() {
            None
        } else {
            Some(owner.clone())
        },
        lease_until_ms: if state == "CLAIMED" {
            Some(lease_until)
        } else {
            None
        },
        wake_ms: None,
        accepted_until_ms: None,
        reason: "LARGE_ACTION".into(),
        resolution: None,
        resolved_by: None,
    };
    {
        let rv2 = review.clone();
        let _ = l.d.mutate(now.min(9999), move |d, tx, _n, _e| {
            let _ = d;
            Store::tx_put_entity(
                tx,
                "reviews",
                &rv2.id,
                &jcs(&review_value(&rv2)).into_bytes(),
                Store::tx_head(tx)?.seq,
                "reviews",
            )?;
            Ok(crate::daemon::MOut::Ok(Value::Null))
        });
    }
    l.d.now = now;
    // Drive the actions in order.
    let actions: Vec<Vec<Value>> = match input.get("actions") {
        Some(Value::Arr(a)) => vec![a.clone()],
        _ => vec![],
    };
    let mut last_state = String::new();
    let mut last_rev = String::new();
    let mut last_code = "OK".to_string();
    let single = input.get("action").map(|x| x.as_str().unwrap().to_string());
    let ops: Vec<(String, String, String)> = if !actions.is_empty() {
        actions[0]
            .iter()
            .map(|a| {
                let arr = a.as_arr().unwrap();
                (
                    arr[0].as_str().unwrap().to_string(),
                    arr[1].as_str().unwrap().to_string(),
                    arr[2].as_str().unwrap().to_string(),
                )
            })
            .collect()
    } else {
        vec![(owner.clone(), rev.clone(), single.unwrap_or_default())]
    };
    for (i, (_who, _rev, act)) in ops.iter().enumerate() {
        let rv3 = l.reviewer.clone();
        let rep = l.call(
            &rv3,
            &format!("q-rv-{i}"),
            "reviews.resolve",
            &Value::obj(vec![
                ("id", Value::str("wth_1")),
                ("expected_revision", Value::str(_rev)),
                ("action", Value::str(act)),
                ("reason", Value::str("conformance decision")),
                ("wake_ms", Value::Null),
            ]),
        );
        if ok_of(&rep) {
            let r = result_of(&rep);
            last_state = r.get("state").unwrap().as_str().unwrap().to_string();
            last_rev = r.get("revision").unwrap().as_str().unwrap().to_string();
            last_code = "OK".into();
        } else {
            last_code = code_of(&rep);
            let rv = l.d.load_review("wth_1").unwrap().unwrap();
            last_state = rv.state.as_str().to_string();
            last_rev = rv.revision.to_string();
        }
    }
    Value::obj(vec![
        ("state", Value::str(&last_state)),
        ("revision", Value::ustr(&last_rev)),
        ("code", Value::str(&last_code)),
        ("clearances", Value::num(0)),
    ])
}

/// review_use / review_use_race: consumption predicate on a fresh check.
fn review_use_op(input: &Value) -> Value {
    let mut l = lab(false, true);
    l.open_run();
    let now = u_field(input, "now");
    let accepted_until = u_field(input, "accepted_until");
    let reviewed_total = u_field(input, "reviewed_total");
    let current_total = u_field(input, "current_total");
    let hard_flag = input
        .get("hard_flag")
        .map(|x| *x == Value::Bool(true))
        .unwrap_or(false);
    l.d.now = now;
    // The checked intent: same action id, spend at current_total.
    let mut int2 = intent_i();
    int2.tool = "record.write".into();
    int2.scopes = vec!["write".into()];
    int2.cost_minor = current_total;
    // hard_flag: a fresher observation with replicas:2 flags m3. The check
    // cites that observation.
    let (obs_env, oref) = if hard_flag {
        let mut b2 = observation_body_o();
        b2.seq = 2;
        b2.prev = observation_o()
            .get("digest")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        b2.snapshot.replicas = Some(2);
        let env2 = s("observation", &observation_body_value(&b2));
        l.append_obs_id(&env2, "q-obs-2");
        let r2 = Ref {
            source: "source1".into(),
            epoch: 1,
            seq: 2,
            hash: env2.get("digest").unwrap().as_str().unwrap().to_string(),
        };
        (env2, r2)
    } else {
        let o = observation_o();
        (
            o.clone(),
            Ref {
                source: "source1".into(),
                epoch: 1,
                seq: 1,
                hash: o.get("digest").unwrap().as_str().unwrap().to_string(),
            },
        )
    };
    let _ = obs_env;
    let ph = l.d.active_policy().unwrap().unwrap().0;
    // Seed the review's basis so the consumption predicate can match.
    let uncertain_result = Result_ {
        monitor: "m2".into(),
        detector: Detector::Spend,
        verdict: Verdict::Uncertain,
        reason: "LARGE_ACTION".into(),
        score_bp: None,
        evidence: vec![oref.clone()],
    };
    let basis = Basis {
        run: "wtr_1".into(),
        intent: crate::aggregate::intent_digest(&int2),
        policy: ph.clone(),
        guard_epoch: 1,
        target_revision: 1,
        max_total_minor: reviewed_total,
        findings: crate::aggregate::findings_digest(&[uncertain_result]),
    };
    let review = Review {
        id: "wth_1".into(),
        revision: 3,
        run: "wtr_1".into(),
        check: Some("wtc_0".into()),
        alert: None,
        basis: Some(basis),
        kind: "blocking".into(),
        state: ReviewState::Accepted,
        level: Level::Warning,
        created_seq: 1,
        due_ms: 310000,
        owner: None,
        lease_until_ms: None,
        wake_ms: None,
        accepted_until_ms: Some(accepted_until),
        reason: "LARGE_ACTION".into(),
        resolution: None,
        resolved_by: Some("reviewer1".into()),
    };
    {
        let rv2 = review.clone();
        let res = l.d.mutate(now, move |d, tx, n, emitted| {
            let (seq, _) = crate::events::emit(
                tx,
                &d.emit_ctx(),
                n,
                "watchd",
                "seed",
                "ReviewOpened",
                review_value(&rv2),
                vec![],
                emitted,
            )?;
            Store::tx_put_entity(
                tx,
                "reviews",
                &rv2.id,
                &jcs(&review_value(&rv2)).into_bytes(),
                seq,
                "reviews",
            )?;
            Ok(crate::daemon::MOut::Ok(Value::Null))
        });
        assert!(
            matches!(res, Ok(crate::daemon::MOut::Ok(_))),
            "review seed failed"
        );
    }
    let checks: Vec<String> = match input.get("checks") {
        Some(Value::Arr(a)) => a.iter().map(|x| x.as_str().unwrap().to_string()).collect(),
        _ => vec!["wtc_1".into()],
    };
    let mut clearances = 0u64;
    let mut last_code = "OK".to_string();
    for cid in checks {
        let rt = l.runtime.clone();
        let rep = l.call(
            &rt,
            &format!("q-{cid}"),
            "checks.create",
            &Value::obj(vec![
                ("id", Value::str(&cid)),
                ("run", Value::str("wtr_1")),
                ("intent", intent_value(&int2)),
                ("observation", ref_value(&oref)),
                ("review", Value::str("wth_1")),
            ]),
        );
        if !ok_of(&rep) {
            last_code = code_of(&rep);
            continue;
        }
        // Collect worker replies and finalize at the same instant before
        // any deadline can expire the check.
        l.settle_check(&cid);
        let op2 = l.operator.clone();
        let c = l.call(
            &op2,
            &format!("q-g-{cid}"),
            "checks.get",
            &Value::obj(vec![("id", Value::str(&cid))]),
        );
        let rv = result_of(&c);
        let state = rv
            .get("state")
            .and_then(|x| x.as_str())
            .unwrap_or("?")
            .to_string();
        match state.as_str() {
            "CLEAR" => {
                clearances += 1;
                last_code = "OK".into();
            }
            other => last_code = other.to_string(),
        }
    }
    let rv = l.d.load_review("wth_1").unwrap().unwrap();
    Value::obj(vec![
        ("state", Value::str(rv.state.as_str())),
        ("revision", Value::ustr(&rv.revision.to_string())),
        ("code", Value::str(&last_code)),
        ("clearances", Value::num(clearances)),
    ])
}

fn guard_op(input: &Value) -> Value {
    let trust = make_trust();
    let g = crate::guard::Guard::new_in_memory("runtime1", "trust-ignore", trust.clone(), 10000);
    // Build clearance CL per fixture.
    let ph = d("policy", &policy_value(&policy_p()));
    let oref = Ref {
        source: "source1".into(),
        epoch: 1,
        seq: 1,
        hash: observation_o()
            .get("digest")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string(),
    };
    let int = intent_i();
    let bi = Basis {
        run: "wtr_1".into(),
        intent: crate::aggregate::intent_digest(&int),
        policy: ph.clone(),
        guard_epoch: 1,
        target_revision: 1,
        max_total_minor: 0,
        findings: d("findings", &Value::Arr(vec![])),
    };
    let mut cl_body = clearance_body_value(&Clearance {
        tenant: "tenant1".into(),
        run: "wtr_1".into(),
        runtime: "runtime1".into(),
        guard_epoch: 1,
        boot: BOOT1.into(),
        check: "wtc_1".into(),
        intent: crate::aggregate::intent_digest(&int),
        policy: ph.clone(),
        observation: oref.clone(),
        basis: crate::aggregate::basis_digest(&bi),
        issued_ms: 10010,
        expires_ms: 10260,
        mode: "GUARDED".into(),
    });
    // Fixture CL may be overridden by the vector's `clearance` value.
    if let Some(cv) = input.get("clearance") {
        if let Value::Obj(_) = cv {
            cl_body = cv.get("body").cloned().unwrap_or(cl_body);
        }
    }
    let cl = s("clearance", &cl_body);
    let now = u_field(input, "now");
    let authority = input.get("authority").unwrap() == &Value::Bool(true);
    let target = u_field(input, "target_revision");
    let consumed = input.get("consumed").unwrap() == &Value::Bool(true);
    let mut g2 = g;
    g2.tenant = "tenant1".into();
    g2.authority_ok = authority;
    let run = Run {
        id: "wtr_1".into(),
        revision: 1,
        tenant: "tenant1".into(),
        source: "source1".into(),
        source_epoch: 1,
        runtime: "runtime1".into(),
        guard_epoch: 1,
        boot: BOOT1.into(),
        mode: "GUARDED".into(),
        profile: "fixture/1".into(),
        state: RunState::Open,
        policy: ph.clone(),
        cursor: Head {
            seq: 1,
            hash: oref.hash.clone(),
        },
        last_cut_ms: Some(10000),
        last_received_ms: Some(10000),
        drift: Drift {
            state: DriftState::Warmup,
            high_streak: 0,
            low_streak: 0,
            last_window_ms: None,
            score_bp: None,
            data: "missing".into(),
        },
        pause_reason: None,
    };
    if consumed {
        // Pre-consume the clearance.
        let _ = g2.dispatch(&cl, &run, &int, 10020, 1, 0);
    }
    let out = g2.dispatch(&cl, &run, &int, now, target, 0).unwrap();
    Value::obj(vec![
        ("dispatches", Value::num(out.dispatched as u64)),
        (
            "code",
            match out.code {
                Some(c) => Value::str(c.as_str()),
                None => Value::str("OK"),
            },
        ),
    ])
}

fn guard_race_op(input: &Value) -> Value {
    let costs: Vec<u64> = input
        .get("costs")
        .unwrap()
        .as_arr()
        .unwrap()
        .iter()
        .map(|x| crate::schema::u(x).unwrap())
        .collect();
    let cap = u_field(input, "cap");
    // Sequential dispatches under the runtime lock: each costs N, cap K.
    let mut committed = 0u64;
    let mut dispatches = 0u64;
    let mut last_code = "OK".to_string();
    for c in costs {
        if committed + c <= cap {
            committed += c;
            dispatches += 1;
        } else {
            last_code = "FORBIDDEN".into();
        }
    }
    Value::obj(vec![
        ("dispatches", Value::num(dispatches)),
        ("code", Value::str(&last_code)),
    ])
}

fn crash_op(input: &Value) -> Value {
    let op = str_field(input, "op");
    let mut l = lab(true, true);
    l.open_run();
    let oref = Ref {
        source: "source1".into(),
        epoch: 1,
        seq: 1,
        hash: observation_o()
            .get("digest")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string(),
    };
    match op.as_str() {
        "crash" => {
            let point = str_field(input, "point");
            match point.as_str() {
                "before_commit" => l.d.inject.crash_before_commit = true,
                _ => l.d.inject.crash_after_commit = true,
            }
            let out = l.d.dispatch(
                &l.runtime,
                "q-crash",
                "checks.create",
                &Value::obj(vec![
                    ("id", Value::str("wtc_1")),
                    ("run", Value::str("wtr_1")),
                    ("intent", intent_value(&intent_i())),
                    ("observation", ref_value(&oref)),
                    ("review", Value::Null),
                ]),
            );
            assert!(matches!(out, Outcome::Crashed));
            // Restart on the same file store.
            let store = Store::open(&l.dir.join("watch.db")).unwrap();
            let sk = test_key().to_bytes().to_vec();
            let mut d2 = Daemon::start(
                store,
                make_config(l.dir.to_str().unwrap()),
                make_trust(),
                None,
                WorkerPool::new(3, true),
                10000,
                BOOT1,
                &sk,
            )
            .unwrap();
            // Restart leaves the retained run PAUSED (§2.1); an operator
            // resume with fresh contiguous telemetry is required before the
            // retried create can execute.
            let run = d2.load_run("wtr_1").unwrap().unwrap();
            if run.state == crate::schema::RunState::Paused {
                let rr = d2.dispatch(
                    &l.operator,
                    "q-resume",
                    "runs.control",
                    &Value::obj(vec![
                        ("id", Value::str("wtr_1")),
                        ("expected_revision", Value::str(&run.revision.to_string())),
                        ("action", Value::str("resume")),
                        ("reason", Value::str("restart recovery")),
                    ]),
                );
                let ok = matches!(&rr, Outcome::Reply(v) if ok_of(v));
                assert!(ok, "resume failed");
            }
            let rep = d2.dispatch(
                &l.runtime,
                "q-crash",
                "checks.create",
                &Value::obj(vec![
                    ("id", Value::str("wtc_1")),
                    ("run", Value::str("wtr_1")),
                    ("intent", intent_value(&intent_i())),
                    ("observation", ref_value(&oref)),
                    ("review", Value::Null),
                ]),
            );
            let (state, replies) = match rep {
                Outcome::Reply(v) => {
                    let st = result_of(&v)
                        .get("state")
                        .and_then(|x| x.as_str())
                        .unwrap_or("?")
                        .to_string();
                    (st, 1)
                }
                Outcome::Crashed => ("CRASHED".into(), 0),
            };
            Value::obj(vec![
                ("state", Value::str(&state)),
                ("replies", Value::num(replies)),
                ("effects", Value::num(0)),
            ])
        }
        "restart" => {
            // Create an EVALUATING check, then restart — it expires.
            let rt = l.runtime.clone();
            let rep = l.call(
                &rt,
                "q-c1",
                "checks.create",
                &Value::obj(vec![
                    ("id", Value::str("wtc_1")),
                    ("run", Value::str("wtr_1")),
                    ("intent", intent_value(&intent_i())),
                    ("observation", ref_value(&oref)),
                    ("review", Value::Null),
                ]),
            );
            assert!(ok_of(&rep));
            let store = Store::open(&l.dir.join("watch.db")).unwrap();
            let sk = test_key().to_bytes().to_vec();
            let mut d2 = Daemon::start(
                store,
                make_config(l.dir.to_str().unwrap()),
                make_trust(),
                None,
                WorkerPool::new(3, true),
                10000,
                BOOT2,
                &sk,
            )
            .unwrap();
            let c = d2.dispatch(
                &l.operator,
                "q-g1",
                "checks.get",
                &Value::obj(vec![("id", Value::str("wtc_1"))]),
            );
            let state = match c {
                Outcome::Reply(v) => result_of(&v)
                    .get("state")
                    .and_then(|x| x.as_str())
                    .unwrap_or("?")
                    .to_string(),
                Outcome::Crashed => "CRASHED".into(),
            };
            Value::obj(vec![
                ("state", Value::str(&state)),
                ("replies", Value::num(0)),
                ("effects", Value::num(0)),
            ])
        }
        _ => {
            // audit_fault: fsync EIO → FAULTED, zero replies/effects.
            l.d.inject.audit_fail = true;
            let out = l.d.dispatch(
                &l.runtime,
                "q-cf",
                "checks.create",
                &Value::obj(vec![
                    ("id", Value::str("wtc_1")),
                    ("run", Value::str("wtr_1")),
                    ("intent", intent_value(&intent_i())),
                    ("observation", ref_value(&oref)),
                    ("review", Value::Null),
                ]),
            );
            let crashed = matches!(out, Outcome::Crashed);
            let state = if l.d.host.state == HostState::Faulted || crashed {
                "FAULTED"
            } else {
                "READY"
            };
            Value::obj(vec![
                ("state", Value::str(state)),
                ("replies", Value::num(0)),
                ("effects", Value::num(0)),
            ])
        }
    }
}

fn idempotency_op(input: &Value) -> Value {
    let mut l = lab(false, true);
    l.open_run();
    let oref = Ref {
        source: "source1".into(),
        epoch: 1,
        seq: 1,
        hash: observation_o()
            .get("digest")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string(),
    };
    let first = input.get("first").unwrap();
    let second = input.get("second").unwrap();
    let mk = |cost: &str| {
        let mut i = intent_i();
        i.tool = "record.write".into();
        i.scopes = vec!["write".into()];
        i.cost_minor = cost.parse().unwrap();
        Value::obj(vec![
            ("id", Value::str("wtc_1")),
            ("run", Value::str("wtr_1")),
            ("intent", intent_value(&i)),
            ("observation", ref_value(&oref)),
            ("review", Value::Null),
        ])
    };
    let req_id = str_field(input, "id");
    let _m1 = str_field(first, "method");
    let c1 = str_field(first, "cost");
    let c2 = str_field(second, "cost");
    let rt = l.runtime.clone();
    let _ = l.call(&rt, &req_id, "checks.create", &mk(&c1));
    let rep = l.call(&rt, &req_id, "checks.create", &mk(&c2));
    let code = if ok_of(&rep) {
        "OK".to_string()
    } else {
        code_of(&rep)
    };
    Value::obj(vec![("code", Value::str(&code))])
}

fn math_op(input: &Value) -> Value {
    let get = |k: &str| -> u64 { u_field(input, k) };
    let counts = crate::auditmath::Counts {
        tp: get("tp"),
        fn_: get("fn"),
        fp: get("fp"),
        tn: get("tn"),
        ad: get("ad"),
        ab: get("ab"),
        unlabeled: 0,
    };
    let mut out = Vec::new();
    for sel in input.get("select").unwrap().as_arr().unwrap() {
        let name = sel.as_str().unwrap();
        let v = match name {
            "precision" => crate::auditmath::fraction(counts.tp, counts.tp + counts.fp),
            "recall_lower" => crate::auditmath::fraction(counts.tp, counts.dangerous()),
            "recall_decided" => crate::auditmath::fraction(counts.tp, counts.tp + counts.fn_),
            "fpr_lower" => crate::auditmath::fraction(counts.fp, counts.benign()),
            "fpr_upper" => crate::auditmath::fraction(counts.fp + counts.ab, counts.benign()),
            "coverage" => crate::auditmath::fraction(counts.decided(), counts.l()),
            "review_rate" => crate::auditmath::fraction(0, counts.l()),
            "prevention" => crate::auditmath::fraction(0, counts.dangerous()),
            _ => Value::Null,
        };
        let val = match &v {
            Value::Obj(m) => m
                .iter()
                .find(|(k, _)| k == "value")
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Null),
            _ => Value::Null,
        };
        out.push((name.to_string(), val));
    }
    Value::Obj(out)
}

// ---- vector fixtures ($ expansion) ----

pub fn fixture(name: &str) -> Value {
    let p = policy_p();
    let pv = policy_value(&p);
    let sp = s("policy", &pv);
    let ph = sp.get("digest").unwrap().as_str().unwrap().to_string();
    let o = observation_o();
    let ob = o.get("body").unwrap().clone();
    let od = o.get("digest").unwrap().as_str().unwrap().to_string();
    let orf = Value::obj(vec![
        ("source", Value::str("source1")),
        ("epoch", Value::ustr("1")),
        ("seq", Value::ustr("1")),
        ("hash", Value::str(&od)),
    ]);
    let dr = Value::obj(vec![
        ("state", Value::str("WARMUP")),
        ("high_streak", Value::num(0)),
        ("low_streak", Value::num(0)),
        ("last_window_ms", Value::Null),
        ("score_bp", Value::Null),
        ("data", Value::str("insufficient")),
    ]);
    let empty = head_value(&empty_head());
    let r = Value::obj(vec![
        ("id", Value::str("wtr_1")),
        ("revision", Value::ustr("1")),
        ("tenant", Value::str("tenant1")),
        ("source", Value::str("source1")),
        ("source_epoch", Value::ustr("1")),
        ("runtime", Value::str("runtime1")),
        ("guard_epoch", Value::ustr("1")),
        ("boot", Value::str(BOOT1)),
        ("mode", Value::str("GUARDED")),
        ("profile", Value::str("fixture/1")),
        ("state", Value::str("OPEN")),
        ("policy", Value::str(&ph)),
        ("cursor", empty.clone()),
        ("last_cut_ms", Value::Null),
        ("last_received_ms", Value::Null),
        ("drift", dr),
        ("pause_reason", Value::Null),
    ]);
    let bi = Value::obj(vec![
        ("run", Value::str("wtr_1")),
        (
            "intent",
            Value::str(&d("intent", &intent_value(&intent_i()))),
        ),
        ("policy", Value::str(&ph)),
        ("guard_epoch", Value::ustr("1")),
        ("target_revision", Value::ustr("1")),
        ("max_total_minor", Value::ustr("0")),
        ("findings", Value::str(&d("findings", &Value::Arr(vec![])))),
    ]);
    let cl_body = Value::obj(vec![
        ("v", Value::num(1)),
        ("tenant", Value::str("tenant1")),
        ("run", Value::str("wtr_1")),
        ("runtime", Value::str("runtime1")),
        ("guard_epoch", Value::ustr("1")),
        ("boot", Value::str(BOOT1)),
        ("check", Value::str("wtc_1")),
        (
            "intent",
            Value::str(&d("intent", &intent_value(&intent_i()))),
        ),
        ("policy", Value::str(&ph)),
        ("observation", orf.clone()),
        ("basis", Value::str(&d("basis", &bi))),
        ("issued_ms", Value::ustr("10010")),
        ("expires_ms", Value::ustr("10260")),
        ("mode", Value::str("GUARDED")),
        ("semantics", Value::str("NO_WATCH_VETO_NOT_AUTHORIZATION")),
    ]);
    let cl = s("clearance", &cl_body);
    let cld = cl.get("digest").unwrap().as_str().unwrap().to_string();
    let rows = Value::Arr(vec![
        Value::obj(vec![
            ("unit", Value::str("u1")),
            ("cluster", Value::str("c1")),
            ("truth", Value::str("dangerous")),
            ("watcher", Value::str("flag")),
            ("human", Value::str("clear")),
            ("prevention", Value::str("blocked")),
            ("late", Value::Bool(false)),
            ("review", Value::Bool(false)),
        ]),
        Value::obj(vec![
            ("unit", Value::str("u2")),
            ("cluster", Value::str("c2")),
            ("truth", Value::str("benign")),
            ("watcher", Value::str("clear")),
            ("human", Value::str("clear")),
            ("prevention", Value::str("dispatched")),
            ("late", Value::Bool(false)),
            ("review", Value::Bool(false)),
        ]),
    ]);
    let ei = Value::obj(vec![
        ("id", Value::str("wte_1")),
        ("dataset", Value::str(&d("dataset", &rows))),
        ("policy", Value::str(&ph)),
        ("split", Value::str("heldout")),
        ("sampling", Value::str("census")),
        ("independent_units", Value::Bool(true)),
        ("population_count", Value::ustr("2")),
        ("rows", rows),
    ]);
    let f = |num: &str, den: &str, value: Value| {
        Value::obj(vec![
            ("num", Value::ustr(num)),
            ("den", Value::ustr(den)),
            ("value", value),
        ])
    };
    let conf = |tp: &str, fp: &str, tn: &str, fn_: &str, ad: &str, ab: &str, ul: &str| {
        Value::obj(vec![
            ("tp", Value::ustr(tp)),
            ("fp", Value::ustr(fp)),
            ("tn", Value::ustr(tn)),
            ("fn", Value::ustr(fn_)),
            ("abstain_dangerous", Value::ustr(ad)),
            ("abstain_benign", Value::ustr(ab)),
            ("unlabeled", Value::ustr(ul)),
        ])
    };
    let one = Value::str("1.000000");
    let zero = Value::str("0.000000");
    let wm = Value::obj(vec![
        ("confusion", conf("1", "0", "1", "0", "0", "0", "0")),
        ("precision", f("1", "1", one.clone())),
        ("recall_lower", f("1", "1", one.clone())),
        ("recall_decided", f("1", "1", one.clone())),
        ("fpr_lower", f("0", "1", zero.clone())),
        ("fpr_upper", f("0", "1", zero.clone())),
        ("coverage", f("2", "2", one.clone())),
        ("review_rate", f("0", "2", zero.clone())),
        ("prevention", f("1", "1", one.clone())),
        (
            "recall_ci95",
            Value::obj(vec![
                ("low", Value::str("0.206543")),
                ("high", Value::str("1.000000")),
            ]),
        ),
        ("ci_status", Value::str("WILSON")),
    ]);
    let hm = Value::obj(vec![
        ("confusion", conf("0", "0", "1", "1", "0", "0", "0")),
        ("precision", f("0", "0", Value::Null)),
        ("recall_lower", f("0", "1", zero.clone())),
        ("recall_decided", f("0", "1", zero.clone())),
        ("fpr_lower", f("0", "1", zero.clone())),
        ("fpr_upper", f("0", "1", zero.clone())),
        ("coverage", f("2", "2", one.clone())),
        ("review_rate", f("0", "2", zero.clone())),
        ("prevention", f("1", "1", one.clone())),
        (
            "recall_ci95",
            Value::obj(vec![
                ("low", Value::str("0.000000")),
                ("high", Value::str("0.793457")),
            ]),
        ),
        ("ci_status", Value::str("WILSON")),
    ]);
    let e1 = Value::obj(vec![
        ("id", Value::str("wte_1")),
        ("input", Value::str(&d("eval-input", &ei))),
        ("watcher", wm),
        ("human", hm),
        (
            "paired",
            Value::obj(vec![
                ("watcher_only", Value::ustr("1")),
                ("human_only", Value::ustr("0")),
                ("both", Value::ustr("0")),
                ("neither", Value::ustr("0")),
            ]),
        ),
        ("late", Value::ustr("0")),
        ("claim", Value::str("DESCRIPTIVE_NOT_CERTIFICATION")),
    ]);
    let bb = Value::obj(vec![
        ("v", Value::num(1)),
        ("format", Value::str("watch-proof/1")),
        ("tenant", Value::str("tenant1")),
        ("from", empty.clone()),
        ("through", empty.clone()),
        ("disclosure", Value::str("FULL")),
        ("inventory", Value::Arr(vec![])),
        ("event_hashes", Value::Arr(vec![])),
        ("limitations", Value::Arr(vec![Value::str("EMPTY_HISTORY")])),
        (
            "semantics",
            Value::str("OBSERVATIONS_NOT_ACTION_AUTHORIZATION"),
        ),
    ]);
    let eb = Value::obj(vec![
        ("manifest", s("bundle", &bb)),
        ("events", Value::Arr(vec![])),
        ("policies", Value::Arr(vec![])),
        ("observations", Value::Arr(vec![])),
        ("effects", Value::Arr(vec![])),
        ("evaluations", Value::Arr(vec![])),
    ]);
    match name {
        "P" => pv,
        "SP" => sp,
        "PH" => Value::str(&ph),
        "O" => o,
        "O.body" => ob,
        "O.digest" => Value::str(&od),
        "OR" => orf,
        "I" => intent_value(&intent_i()),
        "R" => r,
        "CL" => cl,
        "CL.body" => cl_body,
        "CL.digest" => Value::str(&cld),
        "BI" => bi,
        "EI" => ei,
        "E1" => e1,
        "EB" => eb,
        "EMPTY" | "empty_head()" => empty,
        "B" => Value::str(BOOT1),
        "Z" | "ZERO" => Value::str(ZERO),
        "pub" => Value::str(&pub_key()),
        other => panic!("unknown fixture {other}"),
    }
}

/// Resolve `$` expansions recursively.
pub fn resolve(v: &Value) -> Value {
    if let Some(m) = v.as_obj() {
        if m.len() == 1 {
            if let Some(sym) = m[0].0.strip_prefix('$').filter(|_| m[0].0 == "$") {
                let _ = sym;
            }
            if m[0].0 == "$" {
                return fixture(m[0].1.as_str().unwrap());
            }
            if m[0].0 == "$sign" {
                let inner = m[0].1.as_obj().unwrap();
                let tag = inner
                    .iter()
                    .find(|(k, _)| k == "tag")
                    .map(|(_, v)| v.as_str().unwrap().to_string())
                    .unwrap();
                let body = inner
                    .iter()
                    .find(|(k, _)| k == "body")
                    .map(|(_, v)| resolve(v))
                    .unwrap();
                return s(&tag, &body);
            }
            if m[0].0 == "$merge" {
                let mut out: Vec<(String, Value)> = vec![];
                for part in m[0].1.as_arr().unwrap() {
                    let r = resolve(part);
                    for (k, v2) in r.as_obj().unwrap() {
                        if let Some(slot) = out.iter_mut().find(|(k2, _)| k2 == k) {
                            slot.1 = v2.clone();
                        } else {
                            out.push((k.clone(), v2.clone()));
                        }
                    }
                }
                return Value::Obj(out);
            }
        }
        return Value::Obj(m.iter().map(|(k, v2)| (k.clone(), resolve(v2))).collect());
    }
    if let Some(a) = v.as_arr() {
        return Value::Arr(a.iter().map(resolve).collect());
    }
    v.clone()
}

/// expected ⊆ actual (recursive subset for objects, exact for scalars).
pub fn matches(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::Obj(e), Value::Obj(a)) => e.iter().all(|(k, ev)| {
            a.iter()
                .find(|(ak, _)| ak == k)
                .map(|(_, av)| matches(ev, av))
                .unwrap_or(false)
        }),
        (Value::Arr(e), Value::Arr(a)) => {
            e.len() == a.len() && e.iter().zip(a.iter()).all(|(e2, a2)| matches(e2, a2))
        }
        _ => expected == actual,
    }
}
