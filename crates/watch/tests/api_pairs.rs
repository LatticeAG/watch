//! §3.3 API example pairs — each request executed against a real daemon
//! with the §3.2 fixture environment.

use watch::conform::*;
use watch::crypto::d;
use watch::daemon::{Daemon, Outcome};
use watch::json::Value;
use watch::monitor::WorkerPool;
use watch::schema::*;
use watch::store::Store;

fn q(l: &mut Lab, p: &watch::schema::Principal, id: &str, m: &str, params: &Value) -> Value {
    match l.d.dispatch(p, id, m, params) {
        Outcome::Reply(v) => v,
        Outcome::Crashed => panic!("crash on {m}"),
    }
}

#[test]
fn system_status_pair() {
    let mut l = lab(false, true);
    let rt0 = l.runtime.clone();
    let rep = q(&mut l, &rt0, "q1", "system.status", &Value::obj(vec![]));
    assert!(ok_of(&rep));
    let r = result_of(&rep);
    assert_eq!(
        r.get("host")
            .unwrap()
            .get("state")
            .unwrap()
            .as_str()
            .unwrap(),
        "READY"
    );
    assert_eq!(
        r.get("host")
            .unwrap()
            .get("epoch")
            .unwrap()
            .as_str()
            .unwrap(),
        "1"
    );
    assert_eq!(
        r.get("host")
            .unwrap()
            .get("boot")
            .unwrap()
            .as_str()
            .unwrap(),
        BOOT1
    );
    assert_eq!(
        r.get("product_status").unwrap().as_str().unwrap(),
        "UNWRITTEN_GATED"
    );
    assert_eq!(r.get("profile").unwrap().as_str().unwrap(), "lab/1");
    let ph = watch::conform::s("policy", &policy_value(&policy_p()));
    assert_eq!(
        r.get("active_policy").unwrap().as_str().unwrap(),
        ph.get("digest").unwrap().as_str().unwrap()
    );
}

#[test]
fn policy_activate_pair() {
    let mut l = lab_unactivated(false, true);
    let sp = watch::conform::s("policy", &policy_value(&policy_p()));
    let op0 = l.operator.clone();
    let rep = q(
        &mut l,
        &op0,
        "q1",
        "policy.activate",
        &Value::obj(vec![
            ("policy", sp.clone()),
            ("expected_generation", Value::ustr("0")),
        ]),
    );
    assert!(ok_of(&rep), "{:?}", rep);
    let r = result_of(&rep);
    assert_eq!(r.get("id").unwrap().as_str().unwrap(), "wtp_1");
    assert_eq!(r.get("generation").unwrap().as_str().unwrap(), "1");
    assert_eq!(
        r.get("digest").unwrap().as_str().unwrap(),
        sp.get("digest").unwrap().as_str().unwrap()
    );
}

#[test]
fn run_lifecycle_pairs() {
    let mut l = lab(false, true);
    l.open_run_only();
    let rt = l.runtime.clone();
    let rep = q(
        &mut l,
        &rt,
        "q2",
        "runs.get",
        &Value::obj(vec![("id", Value::str("wtr_1"))]),
    );
    assert!(ok_of(&rep));
    assert_eq!(
        result_of(&rep).get("state").unwrap().as_str().unwrap(),
        "OPEN"
    );

    // pause (operator)
    let op = l.operator.clone();
    let rep = q(
        &mut l,
        &op,
        "q3",
        "runs.control",
        &Value::obj(vec![
            ("id", Value::str("wtr_1")),
            ("expected_revision", Value::ustr("1")),
            ("action", Value::str("pause")),
            ("reason", Value::str("operator inspection")),
        ]),
    );
    assert!(ok_of(&rep), "{:?}", rep);
    let r = result_of(&rep);
    assert_eq!(r.get("state").unwrap().as_str().unwrap(), "PAUSED");
    assert_eq!(r.get("revision").unwrap().as_str().unwrap(), "2");

    // resume requires fresh contiguous telemetry (§2.1).
    let app = l.append_obs(&observation_o());
    assert!(ok_of(&app), "{:?}", app);
    let run = l.d.load_run("wtr_1").unwrap().unwrap();
    let rep = q(
        &mut l,
        &op,
        "q4",
        "runs.control",
        &Value::obj(vec![
            ("id", Value::str("wtr_1")),
            ("expected_revision", Value::ustr(&run.revision.to_string())),
            ("action", Value::str("resume")),
            ("reason", Value::str("contiguous source verified")),
        ]),
    );
    assert!(ok_of(&rep), "{:?}", rep);
    assert_eq!(
        result_of(&rep).get("state").unwrap().as_str().unwrap(),
        "OPEN"
    );

    // close
    let run = l.d.load_run("wtr_1").unwrap().unwrap();
    let rep = q(
        &mut l,
        &op,
        "q5",
        "runs.control",
        &Value::obj(vec![
            ("id", Value::str("wtr_1")),
            ("expected_revision", Value::ustr(&run.revision.to_string())),
            ("action", Value::str("close")),
            ("reason", Value::str("task finished")),
        ]),
    );
    assert!(ok_of(&rep));
    assert_eq!(
        result_of(&rep).get("state").unwrap().as_str().unwrap(),
        "CLOSED"
    );
}

#[test]
fn observation_append_pair() {
    let mut l = lab(false, true);
    l.open_run_only();
    let rep = l.append_obs(&observation_o());
    assert!(ok_of(&rep));
    let r = result_of(&rep);
    assert_eq!(r.get("accepted"), Some(&Value::Bool(true)));
    assert_eq!(
        r.get("cursor")
            .unwrap()
            .get("seq")
            .unwrap()
            .as_str()
            .unwrap(),
        "1"
    );
    assert_eq!(
        r.get("cursor")
            .unwrap()
            .get("hash")
            .unwrap()
            .as_str()
            .unwrap(),
        observation_o().get("digest").unwrap().as_str().unwrap()
    );
    // Exact duplicate: accepted=false, no refresh, no new audit event.
    let head_before = l.d.store.head().unwrap().seq;
    let rep2 = l.append_obs_id(&observation_o(), "q-obs-dup");
    assert!(ok_of(&rep2));
    let r2 = result_of(&rep2);
    assert_eq!(r2.get("accepted"), Some(&Value::Bool(false)));
    assert_eq!(l.d.store.head().unwrap().seq, head_before);
}

#[test]
fn check_lifecycle_pairs() {
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
    let rt = l.runtime.clone();
    let rep = q(
        &mut l,
        &rt,
        "q6",
        "checks.create",
        &Value::obj(vec![
            ("id", Value::str("wtc_1")),
            ("run", Value::str("wtr_1")),
            ("intent", intent_value(&intent_i())),
            ("observation", ref_value(&oref)),
            ("review", Value::Null),
        ]),
    );
    assert!(ok_of(&rep), "{:?}", rep);
    let r = result_of(&rep);
    assert_eq!(r.get("state").unwrap().as_str().unwrap(), "EVALUATING");
    assert_eq!(r.get("revision").unwrap().as_str().unwrap(), "1");

    // checks.get returns the card.
    let op = l.operator.clone();
    let rep = q(
        &mut l,
        &op,
        "q7",
        "checks.get",
        &Value::obj(vec![("id", Value::str("wtc_1"))]),
    );
    assert!(ok_of(&rep));

    // cancel
    let rep = q(
        &mut l,
        &rt,
        "q8",
        "checks.cancel",
        &Value::obj(vec![
            ("id", Value::str("wtc_1")),
            ("expected_revision", Value::ustr("1")),
        ]),
    );
    assert!(ok_of(&rep), "{:?}", rep);
    assert_eq!(
        result_of(&rep).get("state").unwrap().as_str().unwrap(),
        "CANCELLED"
    );
}

#[test]
fn effects_record_pair() {
    // Full flow: run + O + check → CLEAR clearance → signed effect.
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
    let rt = l.runtime.clone();
    let rep = q(
        &mut l,
        &rt,
        "q9",
        "checks.create",
        &Value::obj(vec![
            ("id", Value::str("wtc_1")),
            ("run", Value::str("wtr_1")),
            ("intent", intent_value(&intent_i())),
            ("observation", ref_value(&oref)),
            ("review", Value::Null),
        ]),
    );
    assert!(ok_of(&rep), "{:?}", rep);
    l.settle_check("wtc_1");
    let c = l.d.load_check("wtc_1").unwrap().unwrap();
    assert_eq!(c.state.as_str(), "CLEAR", "check did not clear");
    let cl = c.clearance.as_ref().unwrap().clone();
    let eb = EffectBody {
        tenant: "tenant1".into(),
        run: "wtr_1".into(),
        check: "wtc_1".into(),
        action: c.intent.action.clone(),
        intent: watch::aggregate::intent_digest(&c.intent),
        clearance: cl.digest.clone(),
        runtime: "runtime1".into(),
        guard_epoch: 1,
        boot: BOOT1.into(),
        state: EffectState::Declared,
        at_ms: 10000,
        provider_receipt: None,
        predecessor: None,
    };
    let fx = watch::conform::s("effect", &effect_body_value(&eb));
    let rep = q(
        &mut l,
        &rt,
        "q10",
        "effects.record",
        &Value::obj(vec![("effect", fx.clone())]),
    );
    assert!(ok_of(&rep), "{:?}", rep);
    let r = result_of(&rep);
    assert_eq!(r.get("state").unwrap().as_str().unwrap(), "DECLARED");
    assert_eq!(
        r.get("digest").unwrap().as_str().unwrap(),
        fx.get("digest").unwrap().as_str().unwrap()
    );
}

#[test]
fn review_alert_list_pairs() {
    let mut l = lab(false, true);
    l.open_run();
    let rv = l.reviewer.clone();
    let rep = q(
        &mut l,
        &rv,
        "q11",
        "reviews.list",
        &Value::obj(vec![
            ("run", Value::Null),
            ("after", Value::ustr("0")),
            ("through", Value::Null),
            ("limit", Value::num(20)),
        ]),
    );
    assert!(ok_of(&rep));
    let r = result_of(&rep);
    assert_eq!(r.get("items").unwrap().as_arr().unwrap().len(), 0);

    let rep = q(
        &mut l,
        &rv,
        "q12",
        "alerts.list",
        &Value::obj(vec![
            ("run", Value::Null),
            ("after", Value::ustr("0")),
            ("through", Value::Null),
            ("limit", Value::num(20)),
        ]),
    );
    assert!(ok_of(&rep));
    assert_eq!(
        result_of(&rep)
            .get("items")
            .unwrap()
            .as_arr()
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn review_claim_resolve_pairs() {
    let mut l = lab(false, true);
    l.open_run();
    // Seed review wth_1 OPEN (trailing kind, linked alert wta_1).
    let ph = l.d.active_policy().unwrap().unwrap().0;
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
    let review = Review {
        id: "wth_1".into(),
        revision: 1,
        run: "wtr_1".into(),
        check: None,
        alert: Some("wta_1".into()),
        basis: None,
        kind: "trailing".into(),
        state: ReviewState::Open,
        level: Level::Warning,
        created_seq: 1,
        due_ms: 310000,
        owner: None,
        lease_until_ms: None,
        wake_ms: None,
        accepted_until_ms: None,
        reason: "RATE_SPIKE".into(),
        resolution: None,
        resolved_by: None,
    };
    let alert = Alert {
        id: "wta_1".into(),
        revision: 1,
        run: "wtr_1".into(),
        monitor: "m4".into(),
        baseline: "baseline1".into(),
        state: AlertState::Open,
        level: Level::Warning,
        first: oref.clone(),
        last: oref.clone(),
        occurrences: 1,
        review: Some("wth_1".into()),
        reason: "RATE_SPIKE".into(),
        resolved_by: None,
    };
    let _ = ph;
    let rv2 = review.clone();
    let al2 = alert.clone();
    let res = l.d.mutate(10000, move |d, tx, n, emitted| {
        let (s1, _) = watch::events::emit(
            tx,
            &d.emit_ctx(),
            n,
            "watchd",
            "seed",
            "AlertOpened",
            alert_value(&al2),
            vec![],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "alerts",
            &al2.id,
            &watch::json::jcs(&alert_value(&al2)).into_bytes(),
            s1,
            "alerts",
        )?;
        let (s2, _) = watch::events::emit(
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
            &watch::json::jcs(&review_value(&rv2)).into_bytes(),
            s2,
            "reviews",
        )?;
        Ok(watch::daemon::MOut::Ok(Value::Null))
    });
    assert!(matches!(res, Ok(watch::daemon::MOut::Ok(_))), "seed failed");

    let rvp = l.reviewer.clone();
    // reviews.claim with id:null picks the eligible OPEN item.
    let rep = q(
        &mut l,
        &rvp,
        "q13",
        "reviews.claim",
        &Value::obj(vec![
            ("id", Value::Null),
            ("expected_revision", Value::Null),
        ]),
    );
    assert!(ok_of(&rep), "{:?}", rep);
    let r = result_of(&rep);
    assert_eq!(r.get("id").unwrap().as_str().unwrap(), "wth_1");
    assert_eq!(r.get("state").unwrap().as_str().unwrap(), "CLAIMED");
    assert_eq!(r.get("revision").unwrap().as_str().unwrap(), "2");

    // reviews.get returns the card with linked alert.
    let rep = q(
        &mut l,
        &rvp,
        "q14",
        "reviews.get",
        &Value::obj(vec![("id", Value::str("wth_1"))]),
    );
    assert!(ok_of(&rep));
    let r = result_of(&rep);
    assert_eq!(
        r.get("review")
            .unwrap()
            .get("id")
            .unwrap()
            .as_str()
            .unwrap(),
        "wth_1"
    );
    assert_eq!(
        r.get("alert").unwrap().get("id").unwrap().as_str().unwrap(),
        "wta_1"
    );

    // resolve annotate → CLOSED.
    let rep = q(
        &mut l,
        &rvp,
        "q15",
        "reviews.resolve",
        &Value::obj(vec![
            ("id", Value::str("wth_1")),
            ("expected_revision", Value::ustr("2")),
            ("action", Value::str("annotate")),
            (
                "reason",
                Value::str("reviewed burst against approved batch"),
            ),
            ("wake_ms", Value::Null),
        ]),
    );
    assert!(ok_of(&rep), "{:?}", rep);
    assert_eq!(
        result_of(&rep).get("state").unwrap().as_str().unwrap(),
        "CLOSED"
    );

    // alerts.resolve on the OPEN alert → ACKNOWLEDGED.
    let rep = q(
        &mut l,
        &rvp,
        "q16",
        "alerts.resolve",
        &Value::obj(vec![
            ("id", Value::str("wta_1")),
            ("expected_revision", Value::ustr("1")),
            ("action", Value::str("acknowledge")),
            ("reason", Value::str("investigating batch schedule")),
        ]),
    );
    assert!(ok_of(&rep), "{:?}", rep);
    assert_eq!(
        result_of(&rep).get("state").unwrap().as_str().unwrap(),
        "ACKNOWLEDGED"
    );
}

#[test]
fn audit_evaluate_pair() {
    let mut l = lab(false, true);
    l.open_run();
    let ei = fixture("EI");
    let e1 = fixture("E1");
    let au = l.auditor.clone();
    let rep = q(
        &mut l,
        &au,
        "q17",
        "audit.evaluate",
        &Value::obj(vec![("input", ei)]),
    );
    assert!(ok_of(&rep), "{:?}", rep);
    assert!(
        matches(&e1, &result_of(&rep)),
        "E1 mismatch: {:?}",
        result_of(&rep)
    );
}

#[test]
fn audit_sample_pair() {
    let mut l = lab(false, true);
    l.open_run();
    let au = l.auditor.clone();
    let pop = Value::Arr(vec![Value::str("u1")]);
    let pd = d("population", &pop);
    let seed = d("seed", &Value::str("audit1"));
    let rep = q(
        &mut l,
        &au,
        "q18",
        "audit.sample",
        &Value::obj(vec![
            ("population", pop),
            ("population_digest", Value::str(&pd)),
            ("seed", Value::str(&seed)),
            ("k", Value::num(1)),
        ]),
    );
    assert!(ok_of(&rep), "{:?}", rep);
    let r = result_of(&rep);
    assert_eq!(
        r.get("selected").unwrap().as_arr().unwrap()[0]
            .as_str()
            .unwrap(),
        "u1"
    );
    let expected_commit = d(
        "sample-commit",
        &Value::obj(vec![
            ("population", Value::str(&pd)),
            ("seed", Value::str(&seed)),
            ("k", Value::num(1)),
        ]),
    );
    assert_eq!(
        r.get("commitment").unwrap().as_str().unwrap(),
        expected_commit
    );
}

#[test]
fn events_read_and_metrics_pairs() {
    let mut l = lab(false, true);
    let op = l.operator.clone();
    let rep = q(
        &mut l,
        &op,
        "q19",
        "events.read",
        &Value::obj(vec![
            ("after", Value::ustr("0")),
            ("through", Value::Null),
            ("limit", Value::num(100)),
        ]),
    );
    assert!(ok_of(&rep));
    let r = result_of(&rep);
    assert!(r.get("items").unwrap().as_arr().unwrap().len() >= 2); // HostStarted/HostReady etc.

    let au = l.auditor.clone();
    let rep = q(&mut l, &au, "q20", "metrics.get", &Value::obj(vec![]));
    assert!(ok_of(&rep), "{:?}", rep);
}

#[test]
fn bundle_export_pair() {
    let mut l = lab(false, true);
    let au = l.auditor.clone();
    let rep = q(
        &mut l,
        &au,
        "q21",
        "bundle.export",
        &Value::obj(vec![
            ("through", fixture("EMPTY")),
            ("disclosure", Value::str("FULL")),
            ("recipient", Value::str("auditor1")),
        ]),
    );
    assert!(ok_of(&rep), "{:?}", rep);
    let r = result_of(&rep);
    if !matches(&fixture("EB"), &r) {
        panic!(
            "bundle mismatch:
 got {}",
            watch::json::jcs(&r)
        );
    }
}

#[test]
fn drain_pair() {
    let mut l = lab(false, true);
    let op = l.operator.clone();
    let rep = q(&mut l, &op, "q22", "system.drain", &Value::obj(vec![]));
    assert!(ok_of(&rep), "{:?}", rep);
    assert_eq!(
        result_of(&rep).get("state").unwrap().as_str().unwrap(),
        "DRAINING"
    );
}

#[test]
fn restart_persists_state() {
    // Same-boot daemon restart: run retained PAUSED, review expired,
    // then operator resume works.
    let dir = tmpdir("restart");
    for m in monitors() {
        std::fs::write(
            dir.join(format!("{}.artifact", m.detector.as_str())),
            watch::json::jcs(&Value::str(m.detector.as_str())),
        )
        .unwrap();
    }
    let sk = test_key().to_bytes().to_vec();
    {
        let mut l = lab_at(&dir);
        l.open_run();
    }
    let store = Store::open(&dir.join("watch.db")).unwrap();
    let d2 = Daemon::start(
        store,
        make_config(dir.to_str().unwrap()),
        make_trust(),
        None,
        WorkerPool::new(3, true),
        10000,
        BOOT1,
        &sk,
    )
    .unwrap();
    let run = d2.load_run("wtr_1").unwrap().unwrap();
    assert_eq!(run.state.as_str(), "PAUSED");
}
