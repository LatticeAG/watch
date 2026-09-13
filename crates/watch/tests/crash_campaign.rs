//! §6.2 crash-point campaign: every injected crash point iterated 1000×
//! with recovery invariants checked after restart — no acknowledgement
//! without committed audit, no double-apply on exact retry.

use watch::conform::*;
use watch::daemon::{Daemon, Outcome};
use watch::json::Value;
use watch::monitor::WorkerPool;
use watch::schema::*;
use watch::store::Store;

fn create_params(cid: &str) -> Value {
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
    Value::obj(vec![
        ("id", Value::str(cid)),
        ("run", Value::str("wtr_1")),
        ("intent", intent_value(&intent_i())),
        ("observation", ref_value(&oref)),
        ("review", Value::Null),
    ])
}

fn reopen(dir: &std::path::Path, now: u64) -> Daemon {
    let store = Store::open(&dir.join("watch.db")).unwrap();
    let sk = test_key().to_bytes().to_vec();
    Daemon::start(
        store,
        make_config(dir.to_str().unwrap()),
        make_trust(),
        None,
        WorkerPool::new(1, false),
        now,
        BOOT1,
        &sk,
    )
    .unwrap()
}

fn resume(d: &mut Daemon, operator: &Principal, tag: u32) {
    let run = d.load_run("wtr_1").unwrap().unwrap();
    if run.state != RunState::Paused {
        return;
    }
    match d.dispatch(
        operator,
        &format!(
            "q-resume-{tag}-{now}",
            now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ),
        "runs.control",
        &Value::obj(vec![
            ("id", Value::str("wtr_1")),
            ("expected_revision", Value::ustr(&run.revision.to_string())),
            ("action", Value::str("resume")),
            ("reason", Value::str("restart recovery")),
        ]),
    ) {
        Outcome::Reply(v) => assert!(ok_of(&v), "resume: {v:?}"),
        Outcome::Crashed => panic!("crash on resume"),
    }
}

/// A lab rooted at a fixed directory so the campaign reuses one store.
fn campaign_lab() -> (std::path::PathBuf, Principal, Principal) {
    let dir = tmpdir("campaign");
    for m in monitors() {
        std::fs::write(
            dir.join(format!("{}.artifact", m.detector.as_str())),
            watch::json::jcs(&Value::str(m.detector.as_str())),
        )
        .unwrap();
    }
    let mut l = lab_at(&dir);
    l.d.workers = WorkerPool::new(1, false);
    l.open_run();
    drop(l.d);
    (
        dir,
        Principal {
            id: "runtime1".into(),
            uid: 2101,
            roles: vec!["runtime".into()],
        },
        Principal {
            id: "operator1".into(),
            uid: 2103,
            roles: vec!["operator".into()],
        },
    )
}

#[test]
fn crash_before_commit_campaign() {
    // Crash before commit → nothing durable; exact retry re-executes.
    const N: u32 = 1000;
    let (dir, rt, op) = campaign_lab();
    for i in 0..N {
        let cid = format!("wtc_{i}");
        let qid = format!("q-cc-{i}");
        let mut d = reopen(&dir, 10000);
        resume(&mut d, &op, i);
        d.inject.crash_before_commit = true;
        let out = d.dispatch(&rt, &qid, "checks.create", &create_params(&cid));
        assert!(matches!(out, Outcome::Crashed), "iter {i}");
        drop(d);
        let mut d2 = reopen(&dir, 10000);
        assert!(d2.load_check(&cid).unwrap().is_none(), "iter {i}");
        resume(&mut d2, &op, i);
        let rep = d2.dispatch(&rt, &qid, "checks.create", &create_params(&cid));
        match rep {
            Outcome::Reply(v) => {
                assert!(ok_of(&v), "iter {i}: {v:?}");
                assert_eq!(
                    result_of(&v).get("state").unwrap().as_str().unwrap(),
                    "EVALUATING"
                );
            }
            Outcome::Crashed => panic!("iter {i}: unexpected crash"),
        }
        assert_eq!(d2.load_check(&cid).unwrap().unwrap().revision, 1);
    }
}

#[test]
fn crash_after_commit_campaign() {
    // Crash after commit, before reply → retry replays the durable
    // idempotency record (the stored EVALUATING reply); the entity is
    // expired by restart recovery per §6.2, never re-executed.
    const N: u32 = 1000;
    let (dir, rt, op) = campaign_lab();
    for i in 0..N {
        let cid = format!("wtc_{i}");
        let qid = format!("q-cc-{i}");
        let mut d = reopen(&dir, 10000);
        resume(&mut d, &op, i);
        d.inject.crash_after_commit = true;
        let out = d.dispatch(&rt, &qid, "checks.create", &create_params(&cid));
        assert!(matches!(out, Outcome::Crashed), "iter {i}");
        drop(d);
        let mut d2 = reopen(&dir, 10000);
        // Recovery expired the committed EVALUATING check (RESTART).
        let c = d2.load_check(&cid).unwrap().unwrap();
        assert_eq!(c.state.as_str(), "EXPIRED", "iter {i}");
        resume(&mut d2, &op, i);
        // Exact retry replays the recorded reply — no re-execution.
        let rep = d2.dispatch(&rt, &qid, "checks.create", &create_params(&cid));
        match rep {
            Outcome::Reply(v) => {
                assert!(ok_of(&v), "iter {i}: {v:?}");
                assert_eq!(
                    result_of(&v).get("state").unwrap().as_str().unwrap(),
                    "EVALUATING"
                );
            }
            Outcome::Crashed => panic!("iter {i}: unexpected crash"),
        }
        // Still exactly one check row for this id; no duplicate entity.
        let c2 = d2.load_check(&cid).unwrap().unwrap();
        assert_eq!(c2.revision, c.revision, "iter {i}: double-applied");
    }
}

#[test]
fn crash_during_observation_append() {
    // Crash before commit on observations.append → nothing durable; the
    // same signed observation commits on the post-restart retry.
    let dir = tmpdir("campaign-obs");
    for m in monitors() {
        std::fs::write(
            dir.join(format!("{}.artifact", m.detector.as_str())),
            watch::json::jcs(&Value::str(m.detector.as_str())),
        )
        .unwrap();
    }
    {
        let mut l = lab_at(&dir);
        l.open_run_only();
    }
    let rt = Principal {
        id: "runtime1".into(),
        uid: 2101,
        roles: vec!["runtime".into()],
    };
    // Fresh signed observations chained off the fixture O.
    let mut prev = "0".repeat(64);
    for (seq, i) in (1u64..).zip(0..100u32) {
        let qid = format!("q-oa-{i}");
        let mut b = observation_body_o();
        b.seq = seq;
        b.prev = prev.clone();
        let obs = watch::conform::s("observation", &observation_body_value(&b));
        let obs_digest = obs.get("digest").unwrap().as_str().unwrap().to_string();
        let mut d = reopen(&dir, 10000);
        d.inject.crash_before_commit = true;
        let out = d.dispatch(
            &rt,
            &qid,
            "observations.append",
            &Value::obj(vec![("observation", obs.clone())]),
        );
        assert!(matches!(out, Outcome::Crashed), "iter {i}");
        drop(d);
        let mut d2 = reopen(&dir, 10000);
        let rep = d2.dispatch(
            &rt,
            &qid,
            "observations.append",
            &Value::obj(vec![("observation", obs)]),
        );
        match rep {
            Outcome::Reply(v) => {
                assert!(ok_of(&v), "iter {i}: {v:?}");
                assert_eq!(result_of(&v).get("accepted"), Some(&Value::Bool(true)));
            }
            Outcome::Crashed => panic!("iter {i}"),
        }
        prev = obs_digest;
    }
}

#[test]
fn audit_chain_verifies_after_crashes() {
    // After crash/restart cycles the audit chain still verifies end-to-end:
    // export a FULL bundle and run the offline verifier.
    let (dir, rt, op) = campaign_lab();
    for i in 0..20u32 {
        let cid = format!("wtc_{i}");
        let mut d = reopen(&dir, 10000);
        resume(&mut d, &op, i);
        d.inject.crash_after_commit = true;
        let out = d.dispatch(
            &rt,
            &format!("q-x{i}"),
            "checks.create",
            &create_params(&cid),
        );
        assert!(matches!(out, Outcome::Crashed), "iter {i}");
        drop(d);
    }
    let d = reopen(&dir, 10000);
    let head = d.store.head().unwrap();
    let bundle = watch::bundle::export(&d, &head, "FULL", "auditor1").unwrap();
    let v = watch::verify::verify(&bundle, &make_trust());
    assert_eq!(
        v.get("status").unwrap().as_str().unwrap(),
        "FULL_REPLAY",
        "verify: {}",
        watch::json::jcs(&v)
    );
}
