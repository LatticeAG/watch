//! Public method handlers (§3.1/§7.1). Every handler runs inside the
//! admission order: schema → role → idempotency → readiness (dispatch in
//! daemon.rs) → run binding → source/policy/freshness → review/action
//! binding → capacity → durable event.

use crate::aggregate;
use crate::crypto::d;
use crate::daemon::{Daemon, HErr, MOut};
use crate::events::emit;
use crate::fault::{Code, Fault};
use crate::json::{jcs, Value};
use crate::schema::*;
use crate::store::Store;

type R<T> = Result<T, Fault>;

fn f(code: Code, msg: &str) -> Fault {
    Fault::new(code, msg)
}

/// §3.1 params schemas — closed objects per method.
pub fn validate_params(method: &str, params: &Value) -> R<()> {
    let m = match params {
        Value::Obj(m) => m,
        _ => return Err(f(Code::SchemaInvalid, "params must be an object")),
    };
    let closed = |allowed: &[&str]| -> R<()> { crate::schema::closed(m, allowed) };
    let req = |k: &str| -> R<&Value> { crate::schema::field(m, k) };
    match method {
        "system.status" | "system.drain" | "metrics.get" => closed(&[]),
        "policy.activate" => {
            closed(&["policy", "expected_generation"])?;
            signed(req("policy")?)?;
            u(req("expected_generation")?)?;
            Ok(())
        }
        "runs.open" => {
            closed(&[
                "id",
                "source",
                "source_epoch",
                "guard_epoch",
                "boot",
                "mode",
                "profile",
                "policy",
            ])?;
            id(req("id")?)?;
            id(req("source")?)?;
            u(req("source_epoch")?)?;
            u(req("guard_epoch")?)?;
            boot(req("boot")?)?;
            let mode = s(req("mode")?)?;
            if mode != "GUARDED" && mode != "SHADOW" {
                return Err(f(Code::SchemaInvalid, "bad mode"));
            }
            let prof = s(req("profile")?)?;
            if prof != "fixture/1" && prof != "runtime-guard/1" {
                return Err(f(Code::SchemaInvalid, "bad profile"));
            }
            hash(req("policy")?)?;
            Ok(())
        }
        "runs.get" | "checks.get" | "reviews.get" => {
            closed(&["id"])?;
            id(req("id")?)?;
            Ok(())
        }
        "runs.control" => {
            closed(&["id", "expected_revision", "action", "reason"])?;
            id(req("id")?)?;
            u(req("expected_revision")?)?;
            let a = s(req("action")?)?;
            if !["pause", "resume", "close"].contains(&a) {
                return Err(f(Code::SchemaInvalid, "bad action"));
            }
            text(req("reason")?)?;
            Ok(())
        }
        "observations.append" => {
            closed(&["observation"])?;
            signed(req("observation")?)?;
            Ok(())
        }
        "checks.create" => {
            closed(&["id", "run", "intent", "observation", "review"])?;
            id(req("id")?)?;
            id(req("run")?)?;
            intent(req("intent")?)?;
            ref_(req("observation")?)?;
            let rv = req("review")?;
            if *rv != Value::Null {
                id(rv)?;
            }
            Ok(())
        }
        "checks.cancel" => {
            closed(&["id", "expected_revision"])?;
            id(req("id")?)?;
            u(req("expected_revision")?)?;
            Ok(())
        }
        "effects.record" => {
            closed(&["effect"])?;
            signed(req("effect")?)?;
            Ok(())
        }
        "reviews.list" | "alerts.list" => {
            closed(&["run", "after", "through", "limit"])?;
            let r = req("run")?;
            if *r != Value::Null {
                id(r)?;
            }
            u(req("after")?)?;
            let t = req("through")?;
            if *t != Value::Null {
                head(t)?;
            }
            let limit = n(req("limit")?)?;
            if !(1..=crate::PAGE_MAX as u64).contains(&limit) {
                return Err(f(Code::SchemaInvalid, "limit out of range"));
            }
            Ok(())
        }
        "reviews.claim" => {
            closed(&["id", "expected_revision"])?;
            let idv = req("id")?;
            let rev = req("expected_revision")?;
            match (*idv == Value::Null, *rev == Value::Null) {
                (true, true) => Ok(()),
                (false, false) => {
                    id(idv)?;
                    u(rev)?;
                    Ok(())
                }
                _ => Err(f(Code::SchemaInvalid, "id and expected_revision pair")),
            }
        }
        "reviews.resolve" => {
            closed(&["id", "expected_revision", "action", "reason", "wake_ms"])?;
            id(req("id")?)?;
            u(req("expected_revision")?)?;
            let a = s(req("action")?)?;
            if !["accept_risk", "reject", "annotate", "release", "defer"].contains(&a) {
                return Err(f(Code::SchemaInvalid, "bad action"));
            }
            text(req("reason")?)?;
            let w = req("wake_ms")?;
            if *w != Value::Null {
                u(w)?;
            }
            if a != "defer" && *w != Value::Null {
                return Err(f(Code::SchemaInvalid, "wake_ms only for defer"));
            }
            Ok(())
        }
        "alerts.resolve" => {
            closed(&["id", "expected_revision", "action", "reason"])?;
            id(req("id")?)?;
            u(req("expected_revision")?)?;
            let a = s(req("action")?)?;
            if !["acknowledge", "resolve"].contains(&a) {
                return Err(f(Code::SchemaInvalid, "bad action"));
            }
            text(req("reason")?)?;
            Ok(())
        }
        "audit.evaluate" => {
            closed(&["input"])?;
            eval_input(req("input")?)?;
            Ok(())
        }
        "audit.sample" => {
            closed(&["population", "population_digest", "seed", "k"])?;
            let pop = arr(req("population")?)?;
            for x in pop {
                id(x)?;
            }
            let mut uniq: Vec<String> = pop
                .iter()
                .map(|x| x.as_str().unwrap_or("").to_string())
                .collect();
            uniq.sort();
            uniq.dedup();
            if uniq.len() != pop.len() {
                return Err(f(Code::SchemaInvalid, "duplicate population member"));
            }
            hash(req("population_digest")?)?;
            hash(req("seed")?)?;
            let k = n(req("k")?)?;
            if k > pop.len() as u64 {
                return Err(f(Code::SchemaInvalid, "k exceeds population"));
            }
            Ok(())
        }
        "events.read" => {
            closed(&["after", "through", "limit"])?;
            u(req("after")?)?;
            let t = req("through")?;
            if *t != Value::Null {
                head(t)?;
            }
            let limit = n(req("limit")?)?;
            if !(1..=crate::PAGE_MAX as u64).contains(&limit) {
                return Err(f(Code::SchemaInvalid, "limit out of range"));
            }
            Ok(())
        }
        "bundle.export" => {
            closed(&["through", "disclosure", "recipient"])?;
            head(req("through")?)?;
            let dd = s(req("disclosure")?)?;
            if dd != "FULL" && dd != "COMMITMENTS" {
                return Err(f(Code::SchemaInvalid, "bad disclosure"));
            }
            id(req("recipient")?)?;
            Ok(())
        }
        _ => Err(f(Code::MethodUnknown, "unknown method")),
    }
}

// ---------------------------------------------------------------------------

pub fn execute(
    d: &mut Daemon,
    p: &Principal,
    req_id: &str,
    method: &str,
    params: &Value,
) -> Result<MOut, HErr> {
    match method {
        "system.status" => Ok(MOut::Ok(system_status(d))),
        "system.drain" => system_drain(d, p, req_id),
        "policy.activate" => policy_activate(d, p, req_id, params),
        "runs.open" => runs_open(d, p, req_id, params),
        "runs.get" => Ok(MOut::Ok(run_get(d, p, params)?)),
        "runs.control" => runs_control(d, p, req_id, params),
        "observations.append" => observations_append(d, p, req_id, params),
        "checks.create" => checks_create(d, p, req_id, params),
        "checks.get" => Ok(MOut::Ok(check_get(d, p, params)?)),
        "checks.cancel" => checks_cancel(d, p, req_id, params),
        "effects.record" => effects_record(d, p, req_id, params),
        "reviews.list" => Ok(MOut::Ok(list_page(d, "reviews", params)?)),
        "reviews.get" => Ok(MOut::Ok(review_card(d, p, params)?)),
        "reviews.claim" => reviews_claim(d, p, req_id, params),
        "reviews.resolve" => reviews_resolve(d, p, req_id, params),
        "alerts.list" => Ok(MOut::Ok(list_page(d, "alerts", params)?)),
        "alerts.resolve" => alerts_resolve(d, p, req_id, params),
        "audit.evaluate" => audit_evaluate(d, p, req_id, params),
        "audit.sample" => Ok(MOut::Ok(audit_sample(params)?)),
        "events.read" => Ok(MOut::Ok(events_read(d, params)?)),
        "bundle.export" => bundle_export(d, p, req_id, params),
        "metrics.get" => Ok(MOut::Ok(crate::metrics::get(d)?)),
        _ => Ok(MOut::Rejected(f(Code::MethodUnknown, "unknown method"))),
    }
}

// ---------------------------------------------------------------------------

fn system_status(d: &Daemon) -> Value {
    let active = d
        .active_policy()
        .ok()
        .flatten()
        .map(|(dg, _, _)| Value::str(&dg))
        .unwrap_or(Value::Null);
    Value::obj(vec![
        ("host", host_value(&d.host)),
        ("active_policy", active),
        ("product_status", Value::str(crate::PRODUCT_STATUS)),
        ("profile", Value::str(crate::PROFILE)),
    ])
}

fn system_drain(d: &mut Daemon, p: &Principal, req_id: &str) -> Result<MOut, HErr> {
    if d.host.state == HostState::Draining {
        return Ok(MOut::Ok(Value::obj(vec![(
            "state",
            Value::str("DRAINING"),
        )])));
    }
    let now = d.now;
    let pid = p.id.clone();
    d.mutate_h(now, |d, tx, now, emitted| {
        d.host.state = HostState::Draining;
        emit(
            tx,
            &d.emit_ctx(),
            now,
            &pid,
            req_id,
            "HostDraining",
            host_value(&d.host),
            vec![],
            emitted,
        )?;
        // EVALUATING checks expire DRAIN.
        let ids = {
            let mut st = tx
                .prepare("SELECT id FROM checks WHERE state='EVALUATING' ORDER BY id")
                .map_err(|e| f(Code::AuditUnavailable, &e.to_string()))?;
            let rows = st
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(|e| f(Code::AuditUnavailable, &e.to_string()))?;
            let mut v = Vec::new();
            for r in rows {
                v.push(r.map_err(|e| f(Code::AuditUnavailable, &e.to_string()))?);
            }
            v
        };
        for cid in ids {
            let mut c = d.load_check_tx(tx, &cid)?.unwrap();
            c.state = CheckState::Expired;
            c.reason = "DRAIN".into();
            c.revision += 1;
            let (seq, _) = emit(
                tx,
                &d.emit_ctx(),
                now,
                "watchd",
                "watchd",
                "CheckFinalized",
                check_value(&c),
                vec![c.observation.hash.clone(), c.policy.clone()],
                emitted,
            )?;
            Store::tx_put_entity(
                tx,
                "checks",
                &cid,
                &jcs(&check_value(&c)).into_bytes(),
                seq,
                "checks",
            )?;
            d.bump(tx, "watch_checks_total", "", "EXPIRED", 1)?;
        }
        Ok(MOut::Ok(Value::obj(vec![(
            "state",
            Value::str("DRAINING"),
        )])))
    })
}

fn policy_activate(
    d: &mut Daemon,
    p: &Principal,
    req_id: &str,
    params: &Value,
) -> Result<MOut, HErr> {
    let sv = signed(params.get("policy").unwrap())?;
    let expected = u(params.get("expected_generation").unwrap())?;
    let pol = policy(&sv.body).map_err(|e| f(Code::PolicyInvalid, &e.message))?;
    policy_constraints(&pol).map_err(|e| f(Code::PolicyInvalid, &e.message))?;
    // Signature admission: live pinned key for tag "policy" on this tenant.
    crate::config::verify_signed(&d.trust, &d.cfg.tenant, "policy", &d.cfg.tenant, &sv)
        .map_err(|e| f(Code::PolicyInvalid, &e.message))?;
    if pol.tenant != d.cfg.tenant {
        return Ok(MOut::Rejected(f(Code::PolicyInvalid, "tenant mismatch")));
    }
    // Monitor artifacts must match installed pinned digests.
    for m in &pol.monitors {
        let ok = d
            .cfg
            .installed_artifacts
            .iter()
            .any(|(det, dg, _)| *det == m.detector && *dg == m.artifact);
        if !ok {
            return Ok(MOut::Rejected(f(
                Code::PolicyInvalid,
                "monitor artifact not installed",
            )));
        }
    }
    // Generation/predecessor CAS against the active policy.
    let active = d.active_policy()?;
    match &active {
        None => {
            if expected != 0 || pol.generation != 1 || pol.predecessor.is_some() {
                return Ok(MOut::Rejected(f(
                    Code::PolicyStale,
                    "first policy must be generation 1",
                )));
            }
        }
        Some((dg, cur, _)) => {
            if expected != cur.generation
                || pol.generation != cur.generation + 1
                || pol.predecessor.as_deref() != Some(dg.as_str())
            {
                return Ok(MOut::Rejected(f(
                    Code::PolicyStale,
                    "generation/predecessor mismatch",
                )));
            }
        }
    }
    let now = d.now;
    let pid = p.id.clone();
    let req = req_id.to_string();
    let env_bytes = jcs(params.get("policy").unwrap()).into_bytes();
    let digest = sv.digest.clone();
    let pol_id = pol.id.clone();
    let pol_gen = pol.generation;
    d.mutate_h(now, move |d, tx, now, emitted| {
        // Store the signed envelope, then pause all OPEN runs and expire
        // their unconsumed reviews (policy replacement §2.1/§10).
        Store::tx_policy_put(tx, &digest, pol_gen, &env_bytes)?;
        Store::tx_meta_set(tx, "active_policy", &digest)?;
        let (seq, _) = emit(
            tx,
            &d.emit_ctx(),
            now,
            &pid,
            &req,
            "PolicyActivated",
            signed(params.get("policy").unwrap()).map(|s| signed_value(&s))?,
            vec![],
            emitted,
        )?;
        let _ = seq;
        let run_ids = Daemon::entity_ids_by_state(tx, "runs", &["OPEN"])?;
        for rid in &run_ids {
            let mut run = d.load_run_tx(tx, rid)?.unwrap();
            run.state = RunState::Paused;
            run.pause_reason = Some("POLICY_REPLACED".into());
            run.revision += 1;
            let (s, _) = emit(
                tx,
                &d.emit_ctx(),
                now,
                "watchd",
                "watchd",
                "RunPaused",
                run_value(&run),
                vec![],
                emitted,
            )?;
            Store::tx_put_entity(
                tx,
                "runs",
                rid,
                &jcs(&run_value(&run)).into_bytes(),
                s,
                "runs",
            )?;
            d.expire_run_checks(tx, now, emitted, rid)?;
            d.expire_run_reviews(tx, now, emitted, rid)?;
        }
        Ok(MOut::Ok(Value::obj(vec![
            ("id", Value::str(&pol_id)),
            ("generation", Value::ustr(&pol_gen.to_string())),
            ("digest", Value::str(&digest)),
        ])))
    })
}

fn runs_open(d: &mut Daemon, p: &Principal, req_id: &str, params: &Value) -> Result<MOut, HErr> {
    let run_id = id(params.get("id").unwrap())?;
    let source_id = id(params.get("source").unwrap())?;
    let source_epoch = u(params.get("source_epoch").unwrap())?;
    let guard_epoch = u(params.get("guard_epoch").unwrap())?;
    let boot_s = boot(params.get("boot").unwrap())?;
    let mode = s(params.get("mode").unwrap())?.to_string();
    let profile = s(params.get("profile").unwrap())?.to_string();
    let policy_hash = hash(params.get("policy").unwrap())?;

    // Entity-ID reuse.
    if d.load_run(&run_id)?.is_some() {
        return Ok(MOut::Rejected(f(Code::StateConflict, "entity id reuse")));
    }
    // Configured source; caller must equal the source's runtime principal.
    let Some(src) = d.cfg.sources.iter().find(|x| x.id == source_id) else {
        return Ok(MOut::Rejected(f(Code::NotFound, "unknown source")));
    };
    if src.runtime != p.id {
        return Ok(MOut::Rejected(f(Code::Forbidden, "not the source runtime")));
    }
    if src.epoch != source_epoch || src.profile != profile {
        return Ok(MOut::Rejected(f(
            Code::StateConflict,
            "source epoch/profile mismatch",
        )));
    }
    // Profile must be certified; adapter artifact must exist.
    if !d.cfg.certified_profiles.contains(&profile) {
        return Ok(MOut::Rejected(f(
            Code::AdapterUnavailable,
            "profile not certified",
        )));
    }
    if mode == "GUARDED" && profile == "runtime-guard/1" && d.cfg.deployment == "lab" {
        // runtime-guard profile requires a certified adapter install; the
        // lab deployment ships the inert fixture only.
        return Ok(MOut::Rejected(f(
            Code::AdapterUnavailable,
            "guard adapter unavailable",
        )));
    }
    // Policy must be the active one.
    let Some((dg, _pol, _env)) = d.active_policy()? else {
        return Ok(MOut::Rejected(f(Code::PolicyStale, "no active policy")));
    };
    if dg != policy_hash {
        return Ok(MOut::Rejected(f(
            Code::PolicyStale,
            "not the active policy",
        )));
    }
    // Run capacity.
    let n_runs: i64 = d
        .store
        .conn
        .query_row(
            "SELECT COUNT(*) FROM runs WHERE state IN ('OPEN','PAUSED')",
            [],
            |r| r.get(0),
        )
        .map_err(|e| f(Code::AuditUnavailable, &e.to_string()))?;
    if (n_runs as u64) >= crate::RUN_TOTAL as u64 {
        return Ok(MOut::Rejected(f(Code::Capacity, "run cap")));
    }
    let now = d.now;
    let pid = p.id.clone();
    let req = req_id.to_string();
    let run = Run {
        id: run_id.clone(),
        revision: 1,
        tenant: d.cfg.tenant.clone(),
        source: source_id,
        source_epoch,
        runtime: p.id.clone(),
        guard_epoch,
        boot: boot_s,
        mode,
        profile,
        state: RunState::Open,
        policy: policy_hash,
        cursor: empty_head(),
        last_cut_ms: None,
        last_received_ms: None,
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
    d.mutate_h(now, move |d, tx, now, emitted| {
        let (seq, _) = emit(
            tx,
            &d.emit_ctx(),
            now,
            &pid,
            &req,
            "RunOpened",
            run_value(&run),
            vec![],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "runs",
            &run_id,
            &jcs(&run_value(&run)).into_bytes(),
            seq,
            "runs",
        )?;
        d.bump(tx, "watch_candidate_actions_total", &run.mode, "", 0)?;
        Ok(MOut::Ok(Value::obj(vec![
            ("id", Value::str(&run.id)),
            ("revision", Value::str("1")),
            ("state", Value::str("OPEN")),
        ])))
    })
}

fn run_get(d: &Daemon, p: &Principal, params: &Value) -> R<Value> {
    let rid = id(params.get("id").unwrap())?;
    match d.load_run(&rid)? {
        Some(r) if !p.roles.contains(&"runtime".to_string()) || r.runtime == p.id => {
            Ok(run_value(&r))
        }
        _ => Err(f(Code::NotFound, "run not found")),
    }
}

fn runs_control(d: &mut Daemon, p: &Principal, req_id: &str, params: &Value) -> Result<MOut, HErr> {
    let rid = id(params.get("id").unwrap())?;
    let expected = u(params.get("expected_revision").unwrap())?;
    let action = s(params.get("action").unwrap())?.to_string();
    let reason = text(params.get("reason").unwrap())?;
    let Some(run) = d.load_run(&rid)? else {
        return Ok(MOut::Rejected(f(Code::NotFound, "run not found")));
    };
    let is_operator = p.roles.contains(&"operator".to_string());
    let is_owner_runtime = p.roles.contains(&"runtime".to_string()) && run.runtime == p.id;
    match action.as_str() {
        "resume" => {
            if !is_operator {
                return Ok(MOut::Rejected(f(
                    Code::Forbidden,
                    "resume is operator-only",
                )));
            }
        }
        "pause" | "close" => {
            if !is_operator && !is_owner_runtime {
                return Ok(MOut::Rejected(f(Code::Forbidden, "not the run controller")));
            }
        }
        _ => return Ok(MOut::Rejected(f(Code::SchemaInvalid, "bad action"))),
    }
    if run.revision != expected {
        return Ok(MOut::Rejected(f(
            Code::RevisionConflict,
            "revision mismatch",
        )));
    }
    match action.as_str() {
        "pause" => {
            if run.state != RunState::Open {
                return Ok(MOut::Rejected(f(Code::StateConflict, "run not OPEN")));
            }
        }
        "resume" => {
            if run.state != RunState::Paused {
                return Ok(MOut::Rejected(f(Code::StateConflict, "run not PAUSED")));
            }
            // Fresh contiguous telemetry + unchanged policy required.
            let Some((dg, pol, _env)) = d.active_policy()? else {
                return Ok(MOut::Rejected(f(Code::PolicyStale, "no active policy")));
            };
            if run.policy != dg {
                return Ok(MOut::Rejected(f(Code::PolicyStale, "policy changed")));
            }
            let Some(env_bytes) = d.store.latest_observation(&rid)? else {
                return Ok(MOut::Rejected(f(Code::SourceGap, "no telemetry")));
            };
            let v = crate::json::parse(&env_bytes, &crate::json::Limits::reply())
                .map_err(|_| f(Code::AuditUnavailable, "obs parse"))?;
            let sv = signed(&v)?;
            let body = observation_body(&sv.body)?;
            if body.seq != run.cursor.seq || sv.digest != run.cursor.hash {
                return Ok(MOut::Rejected(f(
                    Code::SourceGap,
                    "telemetry not contiguous",
                )));
            }
            if d.now.saturating_sub(body.cut_ms) >= pol.freshness_ms {
                return Ok(MOut::Rejected(f(Code::SourceStale, "telemetry stale")));
            }
        }
        "close" => {
            if run.state == RunState::Closed {
                return Ok(MOut::Rejected(f(Code::StateConflict, "already closed")));
            }
        }
        _ => unreachable!(),
    }
    let now = d.now;
    let pid = p.id.clone();
    let req = req_id.to_string();
    let mut new_run = run.clone();
    new_run.revision += 1;
    match action.as_str() {
        "pause" => {
            new_run.state = RunState::Paused;
            new_run.pause_reason = Some(reason);
        }
        "resume" => {
            new_run.state = RunState::Open;
            new_run.pause_reason = None;
        }
        "close" => {
            new_run.state = RunState::Closed;
            new_run.pause_reason = Some(reason);
        }
        _ => unreachable!(),
    }
    let kind = match action.as_str() {
        "pause" => "RunPaused",
        "resume" => "RunResumed",
        "close" => "RunClosed",
        _ => unreachable!(),
    };
    d.mutate_h(now, move |d, tx, now, emitted| {
        let (seq, _) = emit(
            tx,
            &d.emit_ctx(),
            now,
            &pid,
            &req,
            kind,
            run_value(&new_run),
            vec![],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "runs",
            &rid,
            &jcs(&run_value(&new_run)).into_bytes(),
            seq,
            "runs",
        )?;
        match action.as_str() {
            "pause" => {
                d.expire_run_checks(tx, now, emitted, &rid)?;
            }
            "close" => {
                // Pending checks CANCELLED (not STALE) and reviews EXPIRED.
                let ids = {
                    let mut st = tx
                        .prepare("SELECT id FROM checks WHERE run=?1 AND state='EVALUATING'")
                        .map_err(|e| f(Code::AuditUnavailable, &e.to_string()))?;
                    let rows = st
                        .query_map(rusqlite::params![rid], |r| r.get::<_, String>(0))
                        .map_err(|e| f(Code::AuditUnavailable, &e.to_string()))?;
                    let mut v = Vec::new();
                    for r in rows {
                        v.push(r.map_err(|e| f(Code::AuditUnavailable, &e.to_string()))?);
                    }
                    v
                };
                for cid in ids {
                    let mut c = d.load_check_tx(tx, &cid)?.unwrap();
                    c.state = CheckState::Cancelled;
                    c.reason = "CANCELLED".into();
                    c.revision += 1;
                    let (s, _) = emit(
                        tx,
                        &d.emit_ctx(),
                        now,
                        "watchd",
                        "watchd",
                        "CheckFinalized",
                        check_value(&c),
                        vec![c.observation.hash.clone(), c.policy.clone()],
                        emitted,
                    )?;
                    Store::tx_put_entity(
                        tx,
                        "checks",
                        &cid,
                        &jcs(&check_value(&c)).into_bytes(),
                        s,
                        "checks",
                    )?;
                }
                d.expire_run_reviews(tx, now, emitted, &rid)?;
            }
            _ => {}
        }
        Ok(MOut::Ok(Value::obj(vec![
            ("id", Value::str(&rid)),
            ("revision", Value::ustr(&new_run.revision.to_string())),
            ("state", Value::str(new_run.state.as_str())),
        ])))
    })
}

fn observations_append(
    d: &mut Daemon,
    p: &Principal,
    req_id: &str,
    params: &Value,
) -> Result<MOut, HErr> {
    let env_v = params.get("observation").unwrap();
    let osv = signed(env_v)?;
    let body = observation_body(&osv.body).map_err(|e| f(Code::SchemaInvalid, &e.message))?;
    // Run binding first.
    let Some(run) = d.load_run(&body.run)? else {
        return Ok(MOut::Rejected(f(Code::NotFound, "run not found")));
    };
    if run.runtime != p.id {
        return Ok(MOut::Rejected(f(Code::Forbidden, "not the run runtime")));
    }
    if run.state == RunState::Closed || run.state == RunState::Quarantined {
        return Ok(MOut::Rejected(f(Code::StateConflict, "run closed")));
    }
    // Source signature/epoch: tag observation, signed by the source's
    // configured key under its own subject.
    if body.tenant != d.cfg.tenant || body.source != run.source || body.epoch != run.source_epoch {
        return Ok(MOut::Rejected(f(
            Code::SourceBinding,
            "source binding mismatch",
        )));
    }
    if body.boot != run.boot {
        return Ok(MOut::Rejected(f(Code::SourceBinding, "boot mismatch")));
    }
    let Some(src) = d.cfg.sources.iter().find(|x| x.id == body.source) else {
        return Ok(MOut::Rejected(f(Code::NotFound, "unknown source")));
    };
    crate::config::verify_signed_key(
        &d.trust,
        &d.cfg.tenant,
        "observation",
        &body.source,
        &src.key_id,
        src.key_epoch,
        &osv,
    )
    .map_err(|e| f(Code::SignatureInvalid, &e.message))?;
    // Sequence admission.
    let next = run.cursor.seq + 1;
    let env_bytes = jcs(env_v).into_bytes();
    // Exact duplicate of the current cursor head.
    if body.seq == run.cursor.seq {
        if osv.digest == run.cursor.hash {
            return Ok(MOut::Ok(Value::obj(vec![
                ("accepted", Value::Bool(false)),
                ("cursor", head_value(&run.cursor)),
                ("run_revision", Value::ustr(&run.revision.to_string())),
            ])));
        }
        // Same slot, different bytes → fork → quarantine.
        return quarantine(
            d,
            p,
            req_id,
            &run,
            Code::SourceFork,
            "same-slot conflicting bytes",
        );
    }
    if body.seq < run.cursor.seq {
        // Earlier source seq — replay of a known position.
        if let Some((sv, _b, _)) = d.observation_by_ref(&Ref {
            source: body.source.clone(),
            epoch: body.epoch,
            seq: body.seq,
            hash: osv.digest.clone(),
        })? {
            if sv.digest == osv.digest {
                return Ok(MOut::Ok(Value::obj(vec![
                    ("accepted", Value::Bool(false)),
                    ("cursor", head_value(&run.cursor)),
                    ("run_revision", Value::ustr(&run.revision.to_string())),
                ])));
            }
        }
        return quarantine(
            d,
            p,
            req_id,
            &run,
            Code::SourceFork,
            "earlier conflicting seq",
        );
    }
    if body.seq > next {
        // Gap — pause with expected cursor unchanged.
        return pause_source(d, p, req_id, &run, Code::SourceGap, "sequence gap");
    }
    // body.seq == next: prev must equal cursor hash.
    if body.prev != run.cursor.hash {
        return quarantine(d, p, req_id, &run, Code::SourceFork, "prev mismatch");
    }
    // Future cut / rollback checks.
    if body.cut_ms > d.now {
        return Ok(MOut::Rejected(f(Code::ClockFault, "future cut")));
    }
    if let Some(last_cut) = run.last_cut_ms {
        if body.cut_ms < last_cut {
            return quarantine(
                d,
                p,
                req_id,
                &run,
                Code::CounterRollback,
                "cut_ms decreased",
            );
        }
    }
    // Committed spend never decreases within an epoch.
    let prev_committed: Option<u64> = {
        let env = d.store.latest_observation(&run.id)?;
        match env {
            Some(b) => {
                let v = crate::json::parse(&b, &crate::json::Limits::reply())
                    .map_err(|_| f(Code::AuditUnavailable, "obs parse"))?;
                let sv = signed(&v)?;
                Some(observation_body(&sv.body)?.snapshot.committed_minor)
            }
            None => None,
        }
    };
    if prev_committed.map(|c| body.snapshot.committed_minor < c) == Some(true) {
        return quarantine(
            d,
            p,
            req_id,
            &run,
            Code::CounterRollback,
            "committed decreased",
        );
    }
    // Window telemetry: start multiple of 10000, end ≤ cut_ms, repeated
    // starts must carry identical counts.
    if let Some(w) = &body.snapshot.window {
        if w.start_ms % crate::WINDOW_MS != 0 {
            return Ok(MOut::Rejected(f(
                Code::SchemaInvalid,
                "window start misaligned",
            )));
        }
        if w.start_ms + crate::WINDOW_MS > body.cut_ms {
            return Ok(MOut::Rejected(f(
                Code::SchemaInvalid,
                "window end past cut",
            )));
        }
        if let Some(Some(existing)) = d.store.window_counts(&run.id, w.start_ms)? {
            let ev: Value = crate::json::parse(&existing, &crate::json::Limits::reply())
                .map_err(|_| f(Code::AuditUnavailable, "window parse"))?;
            let ew = window(&ev)?;
            if ew.counts != w.counts {
                return quarantine(
                    d,
                    p,
                    req_id,
                    &run,
                    Code::SourceFork,
                    "window counts changed",
                );
            }
        }
    }
    // Accept: durable observation row + ObservationAccepted (causes link the
    // envelope digest) + cursor update — one transaction.
    let now = d.now;
    let pid = p.id.clone();
    let req = req_id.to_string();
    let mut new_run = run.clone();
    new_run.cursor = Head {
        seq: body.seq,
        hash: osv.digest.clone(),
    };
    new_run.last_cut_ms = Some(body.cut_ms);
    new_run.last_received_ms = Some(now);
    new_run.revision += 1;
    let rev = new_run.revision;
    let digest = osv.digest.clone();
    let win = body.snapshot.window;
    d.mutate_h(now, move |d, tx, now, emitted| {
        Store::tx_insert_observation(
            tx,
            &new_run.id,
            &body.source,
            body.epoch,
            body.seq,
            &digest,
            &env_bytes,
        )?;
        if let Some(w) = &win {
            if !d.store.window_attempted(&new_run.id, w.start_ms)? {
                let wv = window_value(w);
                Store::tx_window_put(tx, &new_run.id, w.start_ms, Some(jcs(&wv).as_bytes()))?;
            }
        }
        let (seq, _) = emit(
            tx,
            &d.emit_ctx(),
            now,
            &pid,
            &req,
            "ObservationAccepted",
            run_value(&new_run),
            vec![digest.clone()],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "runs",
            &new_run.id,
            &jcs(&run_value(&new_run)).into_bytes(),
            seq,
            "runs",
        )?;
        Ok(MOut::Ok(Value::obj(vec![
            ("accepted", Value::Bool(true)),
            ("cursor", head_value(&new_run.cursor)),
            ("run_revision", Value::ustr(&rev.to_string())),
        ])))
    })
}

fn pause_source(
    d: &mut Daemon,
    p: &Principal,
    req_id: &str,
    run: &Run,
    code: Code,
    msg: &str,
) -> Result<MOut, HErr> {
    let now = d.now;
    let pid = p.id.clone();
    let req = req_id.to_string();
    let mut new_run = run.clone();
    new_run.state = RunState::Paused;
    new_run.pause_reason = Some(code.as_str().into());
    new_run.revision += 1;
    d.mutate_h(now, move |d, tx, now, emitted| {
        let (seq, _) = emit(
            tx,
            &d.emit_ctx(),
            now,
            &pid,
            &req,
            "RunPaused",
            run_value(&new_run),
            vec![],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "runs",
            &new_run.id,
            &jcs(&run_value(&new_run)).into_bytes(),
            seq,
            "runs",
        )?;
        d.expire_run_checks(tx, now, emitted, &new_run.id)?;
        d.bump(tx, "watch_source_faults_total", "", "gap", 1)?;
        Ok(MOut::Fault(f(code, msg)))
    })
}

fn quarantine(
    d: &mut Daemon,
    p: &Principal,
    req_id: &str,
    run: &Run,
    code: Code,
    msg: &str,
) -> Result<MOut, HErr> {
    let now = d.now;
    let pid = p.id.clone();
    let req = req_id.to_string();
    let mut new_run = run.clone();
    new_run.state = RunState::Quarantined;
    new_run.pause_reason = Some(code.as_str().into());
    new_run.revision += 1;
    d.mutate_h(now, move |d, tx, now, emitted| {
        let (seq, _) = emit(
            tx,
            &d.emit_ctx(),
            now,
            &pid,
            &req,
            "RunQuarantined",
            run_value(&new_run),
            vec![],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "runs",
            &new_run.id,
            &jcs(&run_value(&new_run)).into_bytes(),
            seq,
            "runs",
        )?;
        d.expire_run_checks(tx, now, emitted, &new_run.id)?;
        d.expire_run_reviews(tx, now, emitted, &new_run.id)?;
        let outcome = match code {
            Code::SourceFork => "fork",
            Code::CounterRollback => "binding",
            _ => "binding",
        };
        d.bump(tx, "watch_source_faults_total", "", outcome, 1)?;
        Ok(MOut::Fault(f(code, msg)))
    })
}

fn checks_create(
    d: &mut Daemon,
    p: &Principal,
    req_id: &str,
    params: &Value,
) -> Result<MOut, HErr> {
    let cid = id(params.get("id").unwrap())?;
    let rid = id(params.get("run").unwrap())?;
    let int = intent(params.get("intent").unwrap())?;
    let oref = ref_(params.get("observation").unwrap())?;
    let review_id = match params.get("review").unwrap() {
        Value::Null => None,
        v => Some(id(v)?),
    };
    // Run binding + visibility.
    let Some(run) = d.load_run(&rid)? else {
        return Ok(MOut::Rejected(f(Code::NotFound, "run not found")));
    };
    if run.runtime != p.id {
        return Ok(MOut::Rejected(f(Code::Forbidden, "not the run runtime")));
    }
    if d.load_check(&cid)?.is_some() {
        return Ok(MOut::Rejected(f(Code::StateConflict, "entity id reuse")));
    }
    if run.state != RunState::Open {
        return Ok(MOut::Rejected(f(Code::StateConflict, "run not OPEN")));
    }
    // Observation resolution: unknown → NOT_FOUND, other run →
    // SOURCE_BINDING, stale → SOURCE_STALE.
    let Some((_osv, obody, obs_env)) = d.observation_by_ref(&oref)? else {
        return Ok(MOut::Rejected(f(Code::NotFound, "unknown observation")));
    };
    if obody.run != rid {
        return Ok(MOut::Rejected(f(
            Code::SourceBinding,
            "observation bound to another run",
        )));
    }
    let Some((pdg, pol, _penv)) = d.active_policy()? else {
        return Ok(MOut::Rejected(f(Code::PolicyStale, "no active policy")));
    };
    if run.policy != pdg {
        return Ok(MOut::Rejected(f(Code::PolicyStale, "policy changed")));
    }
    if d.now.saturating_sub(obody.cut_ms) >= pol.freshness_ms {
        return Ok(MOut::Rejected(f(Code::SourceStale, "observation stale")));
    }
    if int.target_revision != obody.snapshot.target_revision {
        return Ok(MOut::Rejected(f(
            Code::TargetStale,
            "target revision mismatch",
        )));
    }
    // Action binding: (run, action) → intent digest.
    let intent_d = aggregate::intent_digest(&int);
    {
        use rusqlite::OptionalExtension;
        let prior: Option<(String, i64)> = d
            .store
            .conn
            .query_row(
                "SELECT intent_digest,rejected FROM actions WHERE run=?1 AND action=?2",
                rusqlite::params![rid, int.action],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|e| f(Code::AuditUnavailable, &e.to_string()))?;
        if let Some((dg, _rej)) = &prior {
            if *dg != intent_d {
                return Ok(MOut::Rejected(f(
                    Code::IdempotencyConflict,
                    "changed intent under recorded action",
                )));
            }
        }
    }
    // Supplied-review admission predicate (§2.2): full predicate at
    // admission — state, acceptance window, and basis fields.
    if let Some(rvid) = &review_id {
        match d.load_review(rvid)? {
            Some(rv) => {
                let covered_total = obody
                    .snapshot
                    .committed_minor
                    .saturating_add(obody.snapshot.reserved_minor)
                    .saturating_add(int.cost_minor);
                let ok = rv.state == ReviewState::Accepted
                    && rv.accepted_until_ms.map(|a| d.now < a).unwrap_or(false)
                    && rv.basis.as_ref().map(|b| {
                        b.run == rid
                            && b.intent == intent_d
                            && b.policy == pdg
                            && b.guard_epoch == run.guard_epoch
                            && b.target_revision == int.target_revision
                            && covered_total <= b.max_total_minor
                    }) == Some(true);
                if !ok {
                    return Ok(MOut::Rejected(f(
                        Code::ReviewStale,
                        "supplied review unusable",
                    )));
                }
            }
            None => {
                return Ok(MOut::Rejected(f(Code::NotFound, "unknown review")));
            }
        }
    }
    // Capacity: 128 total EVALUATING, 16 per run.
    let total: i64 = d
        .store
        .conn
        .query_row(
            "SELECT COUNT(*) FROM checks WHERE state='EVALUATING'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| f(Code::AuditUnavailable, &e.to_string()))?;
    let per_run: i64 = d
        .store
        .conn
        .query_row(
            "SELECT COUNT(*) FROM checks WHERE run=?1 AND state='EVALUATING'",
            rusqlite::params![rid],
            |r| r.get(0),
        )
        .map_err(|e| f(Code::AuditUnavailable, &e.to_string()))?;
    if (total as u64) >= crate::CHECK_TOTAL as u64
        || (per_run as u64) >= crate::CHECK_PER_RUN as u64
    {
        return Ok(MOut::Rejected(f(Code::Capacity, "check capacity")));
    }
    let now = d.now;
    let pid = p.id.clone();
    let req = req_id.to_string();
    let env_bytes = obs_env.clone();
    let check = Check {
        id: cid.clone(),
        revision: 1,
        run: rid.clone(),
        intent: int.clone(),
        observation: oref.clone(),
        policy: pdg.clone(),
        state: CheckState::Evaluating,
        created_ms: now,
        deadline_ms: now + pol.evaluation_ms,
        results: vec![],
        review: review_id.clone(),
        clearance: None,
        reason: "PENDING".into(),
    };
    let required: Vec<Monitor> = pol
        .monitors
        .iter()
        .filter(|m| m.mode == "blocking" && m.required)
        .cloned()
        .collect();
    let rejected_latch = {
        use rusqlite::OptionalExtension;
        d.store
            .conn
            .query_row(
                "SELECT rejected FROM actions WHERE run=?1 AND action=?2",
                rusqlite::params![rid, int.action],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(|e| f(Code::AuditUnavailable, &e.to_string()))?
            .unwrap_or(0)
            == 1
    };
    let action_id = int.action.clone();
    let res = d.mutate_h(now, move |d, tx, now, emitted| {
        let (seq, _) = emit(
            tx,
            &d.emit_ctx(),
            now,
            &pid,
            &req,
            "CheckStarted",
            check_value(&check),
            vec![oref.hash.clone()],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "checks",
            &cid,
            &jcs(&check_value(&check)).into_bytes(),
            seq,
            "checks",
        )?;
        for m in &required {
            Store::tx_slot_put(tx, &cid, &m.id, now + m.deadline_ms, "pending", None)?;
            let job = Value::obj(vec![
                ("v", Value::num(1)),
                ("job", Value::str(&format!("job_{}_{}", cid, m.id))),
                ("monitor", monitor_value(m)),
                ("policy", policy_value(&pol)),
                (
                    "observation",
                    crate::json::parse(&env_bytes, &crate::json::Limits::reply())
                        .map_err(|_| f(Code::AuditUnavailable, "obs parse"))?,
                ),
                ("intent", intent_value(&int)),
                ("drift", Value::Null),
                (
                    "deadline_ms",
                    Value::ustr(&(now + m.deadline_ms).to_string()),
                ),
            ]);
            Store::tx_outbox_put(
                tx,
                "monitor_job",
                &format!("job_{}_{}", cid, m.id),
                now,
                jcs(&job).as_bytes(),
            )?;
        }
        // Record the action→intent binding (rejected latch already known).
        Store::tx_action_put(tx, &rid, &action_id, &intent_d, rejected_latch)?;
        d.bump(
            tx,
            "watch_candidate_actions_total",
            &new_check_mode(&run),
            "",
            1,
        )?;
        if rejected_latch {
            // Latched rejection: the check exists and finalizes DENY.
            let mut c2 = check.clone();
            c2.state = CheckState::Deny;
            c2.reason = "REVIEW_REJECTED".into();
            c2.revision += 1;
            let (s2, _) = emit(
                tx,
                &d.emit_ctx(),
                now,
                "watchd",
                "watchd",
                "CheckFinalized",
                check_value(&c2),
                vec![oref.hash.clone(), pdg.clone()],
                emitted,
            )?;
            Store::tx_put_entity(
                tx,
                "checks",
                &cid,
                &jcs(&check_value(&c2)).into_bytes(),
                s2,
                "checks",
            )?;
            d.bump(tx, "watch_checks_total", "", "DENY", 1)?;
            return Ok(MOut::Ok(Value::obj(vec![
                ("id", Value::str(&cid)),
                ("revision", Value::ustr(&c2.revision.to_string())),
                ("state", Value::str("DENY")),
            ])));
        }
        Ok(MOut::Ok(Value::obj(vec![
            ("id", Value::str(&cid)),
            ("revision", Value::str("1")),
            ("state", Value::str("EVALUATING")),
        ])))
    });
    // After commit, dispatch the queued monitor jobs.
    if matches!(res, Ok(MOut::Ok(_))) {
        let _ = d.tick_outbox(now);
    }
    res
}

fn new_check_mode(run: &Run) -> String {
    run.mode.clone()
}

fn check_get(d: &Daemon, p: &Principal, params: &Value) -> R<Value> {
    let cid = id(params.get("id").unwrap())?;
    match d.load_check(&cid)? {
        Some(c) => {
            let run = d
                .load_run(&c.run)?
                .ok_or_else(|| f(Code::AuditUnavailable, "run lost"))?;
            if p.roles.contains(&"runtime".to_string()) && run.runtime != p.id {
                return Err(f(Code::NotFound, "check not found"));
            }
            Ok(check_value(&c))
        }
        None => Err(f(Code::NotFound, "check not found")),
    }
}

fn checks_cancel(
    d: &mut Daemon,
    p: &Principal,
    req_id: &str,
    params: &Value,
) -> Result<MOut, HErr> {
    let cid = id(params.get("id").unwrap())?;
    let expected = u(params.get("expected_revision").unwrap())?;
    let Some(c) = d.load_check(&cid)? else {
        return Ok(MOut::Rejected(f(Code::NotFound, "check not found")));
    };
    let run = d
        .load_run(&c.run)?
        .ok_or_else(|| f(Code::AuditUnavailable, "run lost"))?;
    let is_operator = p.roles.contains(&"operator".to_string());
    if !(is_operator || run.runtime == p.id) {
        return Ok(MOut::Rejected(f(Code::Forbidden, "not the run controller")));
    }
    if c.revision != expected {
        return Ok(MOut::Rejected(f(
            Code::RevisionConflict,
            "revision mismatch",
        )));
    }
    if c.state != CheckState::Evaluating {
        return Ok(MOut::Rejected(f(
            Code::StateConflict,
            "check already terminal",
        )));
    }
    let now = d.now;
    let pid = p.id.clone();
    let req = req_id.to_string();
    let mut c2 = c.clone();
    c2.state = CheckState::Cancelled;
    c2.reason = "CANCELLED".into();
    c2.revision += 1;
    d.mutate_h(now, move |d, tx, now, emitted| {
        let (seq, _) = emit(
            tx,
            &d.emit_ctx(),
            now,
            &pid,
            &req,
            "CheckFinalized",
            check_value(&c2),
            vec![c2.observation.hash.clone(), c2.policy.clone()],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "checks",
            &cid,
            &jcs(&check_value(&c2)).into_bytes(),
            seq,
            "checks",
        )?;
        d.bump(tx, "watch_checks_total", "", "CANCELLED", 1)?;
        Ok(MOut::Ok(Value::obj(vec![
            ("id", Value::str(&cid)),
            ("revision", Value::ustr(&c2.revision.to_string())),
            ("state", Value::str("CANCELLED")),
        ])))
    })
}

fn effects_record(
    d: &mut Daemon,
    p: &Principal,
    req_id: &str,
    params: &Value,
) -> Result<MOut, HErr> {
    let env_v = params.get("effect").unwrap();
    let esv = signed(env_v)?;
    let eb = effect_body(&esv.body).map_err(|e| f(Code::SchemaInvalid, &e.message))?;
    let Some(run) = d.load_run(&eb.run)? else {
        return Ok(MOut::Rejected(f(Code::NotFound, "run not found")));
    };
    if run.runtime != p.id || eb.runtime != p.id {
        return Ok(MOut::Rejected(f(Code::Forbidden, "not the run runtime")));
    }
    if eb.tenant != d.cfg.tenant {
        return Ok(MOut::Rejected(f(Code::SourceBinding, "tenant mismatch")));
    }
    // Signature: tag "effect" under the runtime's pinned key.
    let Some(src) = d.cfg.sources.iter().find(|x| x.runtime == p.id) else {
        return Ok(MOut::Rejected(f(Code::Forbidden, "no source for runtime")));
    };
    crate::config::verify_signed_key(
        &d.trust,
        &d.cfg.tenant,
        "effect",
        &eb.runtime,
        &src.key_id,
        src.key_epoch,
        &esv,
    )
    .map_err(|e| f(Code::SignatureInvalid, &e.message))?;
    if eb.guard_epoch != run.guard_epoch || eb.boot != run.boot {
        return Ok(MOut::Rejected(f(
            Code::StateConflict,
            "epoch/boot mismatch",
        )));
    }
    if eb.at_ms > d.now {
        return Ok(MOut::Rejected(f(Code::ClockFault, "future effect")));
    }
    // The seeded check + GUARDED clearance are required evidence.
    let Some(c) = d.load_check(&eb.check)? else {
        return Ok(MOut::Rejected(f(Code::StateConflict, "missing check seed")));
    };
    if c.run != eb.run {
        return Ok(MOut::Rejected(f(
            Code::StateConflict,
            "check bound elsewhere",
        )));
    }
    if c.state != CheckState::Clear {
        return Ok(MOut::Rejected(f(
            Code::StateConflict,
            "no finalized clearance",
        )));
    }
    let Some(cl) = &c.clearance else {
        return Ok(MOut::Rejected(f(
            Code::StateConflict,
            "no clearance on check",
        )));
    };
    if cl.digest != eb.clearance {
        return Ok(MOut::Rejected(f(
            Code::StateConflict,
            "clearance digest mismatch",
        )));
    }
    let cl_body = clearance_body(&cl.body)?;
    if cl_body.mode != "GUARDED" {
        return Ok(MOut::Rejected(f(Code::Forbidden, "non-GUARDED clearance")));
    }
    if eb.intent != aggregate::intent_digest(&c.intent) {
        return Ok(MOut::Rejected(f(Code::EffectConflict, "intent mismatch")));
    }
    // Effect chain rules.
    let env_bytes = jcs(env_v).into_bytes();
    use rusqlite::OptionalExtension;
    let prior: Option<(String, String)> = d
        .store
        .conn
        .query_row(
            "SELECT digest,state FROM effects WHERE run=?1 AND action=?2 ORDER BY rowid DESC LIMIT 1",
            rusqlite::params![eb.run, eb.action],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|e| f(Code::AuditUnavailable, &e.to_string()))?;
    let exists: Option<(String, Vec<u8>)> = {
        d.store
            .conn
            .query_row(
                "SELECT digest,envelope FROM effects WHERE digest=?1",
                rusqlite::params![esv.digest],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|e| f(Code::AuditUnavailable, &e.to_string()))?
    };
    if let Some((dg, env)) = exists {
        if env == env_bytes {
            let b = crate::json::parse(&env, &crate::json::Limits::reply())
                .map_err(|_| f(Code::AuditUnavailable, "effect parse"))?;
            let sv = signed(&b)?;
            let body = effect_body(&sv.body)?;
            return Ok(MOut::Ok(Value::obj(vec![
                ("action", Value::str(&body.action)),
                ("state", Value::str(body.state.as_str())),
                ("digest", Value::str(&dg)),
            ])));
        }
    }
    match &prior {
        None => {
            if eb.predecessor.is_some() {
                return Ok(MOut::Rejected(f(
                    Code::EffectConflict,
                    "root has predecessor",
                )));
            }
            if eb.state != EffectState::Declared && eb.state != EffectState::NotDispatched {
                return Ok(MOut::Rejected(f(Code::EffectConflict, "root must declare")));
            }
        }
        Some((pdg, pstate)) => {
            if eb.predecessor.as_deref() != Some(pdg.as_str()) {
                return Ok(MOut::Rejected(f(
                    Code::EffectConflict,
                    "predecessor mismatch",
                )));
            }
            let ok = matches!(
                (pstate.as_str(), eb.state),
                ("DECLARED", EffectState::Confirmed)
                    | ("DECLARED", EffectState::NotDispatched)
                    | ("DECLARED", EffectState::Unknown)
                    | ("UNKNOWN", EffectState::Confirmed)
                    | ("UNKNOWN", EffectState::NotDispatched)
            );
            if !ok {
                return Ok(MOut::Rejected(f(
                    Code::EffectConflict,
                    "contradictory evidence",
                )));
            }
        }
    }
    let now = d.now;
    let pid = p.id.clone();
    let req = req_id.to_string();
    let digest = esv.digest.clone();
    let action = eb.action.clone();
    let st_str = eb.state.as_str().to_string();
    d.mutate_h(now, move |d, tx, now, emitted| {
        Store::tx_effect_insert(
            tx,
            &digest,
            &eb.run,
            &action,
            eb.predecessor.as_deref(),
            &st_str,
            &env_bytes,
        )?;
        emit(
            tx,
            &d.emit_ctx(),
            now,
            &pid,
            &req,
            "EffectRecorded",
            signed_value(&esv),
            vec![digest.clone()],
            emitted,
        )?;
        Ok(MOut::Ok(Value::obj(vec![
            ("action", Value::str(&action)),
            ("state", Value::str(&st_str)),
            ("digest", Value::str(&digest)),
        ])))
    })
}

// ---- listing ----

fn list_page(d: &Daemon, entity: &str, params: &Value) -> R<Value> {
    let run = match params.get("run").unwrap() {
        Value::Null => None,
        v => Some(id(v)?),
    };
    let after = u(params.get("after").unwrap())?;
    let limit = n(params.get("limit").unwrap())? as usize;
    let through = resolve_through(d, params.get("through").unwrap())?;
    let (items, next) = d
        .store
        .list_at(entity, run.as_deref(), after, through.seq, limit)?;
    let mut vals = Vec::new();
    for (_seq, body) in items {
        let v = crate::json::parse(&body, &crate::json::Limits::reply())
            .map_err(|_| f(Code::AuditUnavailable, "body parse"))?;
        vals.push(v);
    }
    Ok(Value::obj(vec![
        ("items", Value::Arr(vals)),
        ("through", head_value(&through)),
        (
            "next_after",
            match next {
                Some(x) => Value::ustr(&x.to_string()),
                None => Value::Null,
            },
        ),
    ]))
}

fn resolve_through(d: &Daemon, v: &Value) -> R<Head> {
    match v {
        Value::Null => d.store.head(),
        _ => {
            let h = head(v)?;
            if !d.store.head_exists(&h)? {
                return Err(f(Code::NotFound, "through head not in retained history"));
            }
            Ok(h)
        }
    }
}

fn review_card(d: &Daemon, p: &Principal, params: &Value) -> R<Value> {
    let rid = id(params.get("id").unwrap())?;
    let Some(rv) = d.load_review(&rid)? else {
        return Err(f(Code::NotFound, "review not found"));
    };
    let run = d
        .load_run(&rv.run)?
        .ok_or_else(|| f(Code::AuditUnavailable, "run lost"))?;
    if p.roles.contains(&"runtime".to_string()) {
        return Err(f(Code::NotFound, "review not found"));
    }
    let check_v = match &rv.check {
        Some(cid) => d
            .load_check(cid)?
            .map(|c| check_value(&c))
            .unwrap_or(Value::Null),
        None => Value::Null,
    };
    let alert_v = match &rv.alert {
        Some(aid) => d
            .load_alert(aid)?
            .map(|a| alert_value(&a))
            .unwrap_or(Value::Null),
        None => Value::Null,
    };
    // Original observation: from the linked check; null only on a terminal
    // card whose bytes were explicitly retired.
    let obs_v = match &rv.check {
        Some(cid) => match d.load_check(cid)? {
            Some(c) => match d.observation_by_ref(&c.observation)? {
                Some((sv, _b, env)) => {
                    let _ = sv;
                    crate::json::parse(&env, &crate::json::Limits::reply())
                        .map_err(|_| f(Code::AuditUnavailable, "obs parse"))?
                }
                None => {
                    if rv.state.active() {
                        return Err(f(Code::ArtifactUnavailable, "evidence retired"));
                    }
                    Value::Null
                }
            },
            None => Value::Null,
        },
        None => Value::Null,
    };
    let Some((_dg, _p, penv)) = d.store.policy_get(&run.policy)?.and_then(|b| {
        crate::json::parse(&b, &crate::json::Limits::reply())
            .ok()
            .and_then(|v| signed(&v).ok().map(|sv| (sv.digest.clone(), v.clone(), v)))
    }) else {
        return Err(f(Code::ArtifactUnavailable, "policy unavailable"));
    };
    let _ = penv;
    let pol_bytes = d.store.policy_get(&run.policy)?.unwrap();
    let pol_v = crate::json::parse(&pol_bytes, &crate::json::Limits::reply())
        .map_err(|_| f(Code::AuditUnavailable, "policy parse"))?;
    Ok(Value::obj(vec![
        ("review", review_value(&rv)),
        ("check", check_v),
        ("alert", alert_v),
        ("observation", obs_v),
        ("policy", pol_v),
        ("run", run_value(&run)),
        ("at_ms", Value::ustr(&d.now.to_string())),
    ]))
}

// ---- review queue ----

/// Priority order for claim next: critical, warning, info; round-robin run
/// within level; FIFO created_seq within run.
fn next_open_review(d: &Daemon) -> R<Option<Review>> {
    let mut st = d
        .store
        .conn
        .prepare("SELECT body FROM reviews WHERE state='OPEN' ORDER BY id")
        .map_err(|e| f(Code::AuditUnavailable, &e.to_string()))?;
    let rows = st
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .map_err(|e| f(Code::AuditUnavailable, &e.to_string()))?;
    let mut items: Vec<Review> = Vec::new();
    for r in rows {
        let b = r.map_err(|e| f(Code::AuditUnavailable, &e.to_string()))?;
        let v = crate::json::parse(&b, &crate::json::Limits::reply())
            .map_err(|_| f(Code::AuditUnavailable, "review parse"))?;
        items.push(review(&v)?);
    }
    if items.is_empty() {
        return Ok(None);
    }
    let rank = |l: &Level| match l {
        Level::Critical => 0,
        Level::Warning => 1,
        Level::Info => 2,
    };
    let best_level = items.iter().map(|r| rank(&r.level)).min().unwrap();
    let mut level_items: Vec<&Review> = items
        .iter()
        .filter(|r| rank(&r.level) == best_level)
        .collect();
    // Round-robin by run using the persisted last-served cursor.
    let cursor = d
        .store
        .meta_get(&format!("queue_cursor:{best_level}"))?
        .unwrap_or_default();
    level_items.sort_by_key(|a| (a.run.clone(), a.created_seq));
    let chosen = if cursor.is_empty() {
        level_items[0]
    } else {
        level_items
            .iter()
            .find(|r| r.run.as_str() > cursor.as_str())
            .copied()
            .unwrap_or(level_items[0])
    };
    Ok(Some(chosen.clone()))
}

fn reviews_claim(
    d: &mut Daemon,
    p: &Principal,
    req_id: &str,
    params: &Value,
) -> Result<MOut, HErr> {
    let named = match params.get("id").unwrap() {
        Value::Null => None,
        v => Some(id(v)?),
    };
    let expected = match params.get("expected_revision").unwrap() {
        Value::Null => None,
        v => Some(u(v)?),
    };
    let rv = match &named {
        Some(rid) => match d.load_review(rid)? {
            Some(r) => r,
            None => return Ok(MOut::Rejected(f(Code::NotFound, "review not found"))),
        },
        None => match next_open_review(d)? {
            Some(r) => r,
            None => return Ok(MOut::Rejected(f(Code::NotFound, "queue empty"))),
        },
    };
    if let Some(e) = expected {
        if rv.revision != e {
            return Ok(MOut::Rejected(f(
                Code::RevisionConflict,
                "revision mismatch",
            )));
        }
    }
    let Some((_dg, pol, _env)) = (match d
        .store
        .policy_get(&{ d.load_run(&rv.run)?.map(|r| r.policy).unwrap_or_default() })?
    {
        Some(b) => {
            let v = crate::json::parse(&b, &crate::json::Limits::reply())
                .map_err(|_| f(Code::AuditUnavailable, "policy parse"))?;
            let sv = signed(&v)?;
            Some((sv.digest.clone(), policy(&sv.body)?, v))
        }
        None => None,
    }) else {
        return Ok(MOut::Rejected(f(
            Code::ArtifactUnavailable,
            "policy unavailable",
        )));
    };
    // Boundary: a claim at/after hard due commits expiry + LEASE_EXPIRED.
    if d.now >= rv.due_ms {
        return expire_then_fault(d, p, req_id, &rv, Code::LeaseExpired, "past due");
    }
    let claimable = rv.state == ReviewState::Open
        || (rv.state == ReviewState::Claimed && rv.owner.as_deref() == Some(p.id.as_str()));
    if !claimable {
        return Ok(MOut::Rejected(f(Code::StateConflict, "not claimable")));
    }
    // A CLAIMED item with a live lease can only be renewed by its owner;
    // a boundary-expired lease releases first.
    if rv.state == ReviewState::Claimed {
        if let Some(l) = rv.lease_until_ms {
            if d.now >= l && rv.owner.as_deref() != Some(p.id.as_str()) {
                return release_then_fault(d, p, req_id, &rv, Code::LeaseExpired, "lease expired");
            }
        }
    }
    let now = d.now;
    let pid = p.id.clone();
    let req = req_id.to_string();
    let mut r2 = rv.clone();
    r2.state = ReviewState::Claimed;
    r2.owner = Some(pid.clone());
    r2.lease_until_ms = Some((now + pol.claim_lease_ms).min(rv.due_ms));
    r2.revision += 1;
    let rev = r2.revision;
    let level_rank = match rv.level {
        Level::Critical => 0,
        Level::Warning => 1,
        Level::Info => 2,
    };
    d.mutate_h(now, move |d, tx, now, emitted| {
        let (seq, _) = emit(
            tx,
            &d.emit_ctx(),
            now,
            &pid,
            &req,
            "ReviewClaimed",
            review_value(&r2),
            vec![],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "reviews",
            &r2.id,
            &jcs(&review_value(&r2)).into_bytes(),
            seq,
            "reviews",
        )?;
        Store::tx_meta_set(tx, &format!("queue_cursor:{level_rank}"), &r2.run)?;
        Ok(MOut::Ok(Value::obj(vec![
            ("id", Value::str(&r2.id)),
            ("revision", Value::ustr(&rev.to_string())),
            ("state", Value::str("CLAIMED")),
        ])))
    })
}

/// Commit ReviewExpired then return a fault (boundary-first ordering §2.4).
fn expire_then_fault(
    d: &mut Daemon,
    p: &Principal,
    req_id: &str,
    rv: &Review,
    code: Code,
    msg: &str,
) -> Result<MOut, HErr> {
    let now = d.now;
    let pid = p.id.clone();
    let req = req_id.to_string();
    let mut r2 = rv.clone();
    r2.state = ReviewState::Expired;
    r2.revision += 1;
    r2.owner = None;
    r2.lease_until_ms = None;
    d.mutate_h(now, move |d, tx, now, emitted| {
        let (seq, _) = emit(
            tx,
            &d.emit_ctx(),
            now,
            &pid,
            &req,
            "ReviewExpired",
            review_value(&r2),
            vec![],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "reviews",
            &r2.id,
            &jcs(&review_value(&r2)).into_bytes(),
            seq,
            "reviews",
        )?;
        Ok(MOut::Fault(f(code, msg)))
    })
}

fn release_then_fault(
    d: &mut Daemon,
    p: &Principal,
    req_id: &str,
    rv: &Review,
    code: Code,
    msg: &str,
) -> Result<MOut, HErr> {
    let now = d.now;
    let pid = p.id.clone();
    let req = req_id.to_string();
    let mut r2 = rv.clone();
    r2.state = ReviewState::Open;
    r2.revision += 1;
    r2.owner = None;
    r2.lease_until_ms = None;
    d.mutate_h(now, move |d, tx, now, emitted| {
        let (seq, _) = emit(
            tx,
            &d.emit_ctx(),
            now,
            &pid,
            &req,
            "ReviewReleased",
            review_value(&r2),
            vec![],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "reviews",
            &r2.id,
            &jcs(&review_value(&r2)).into_bytes(),
            seq,
            "reviews",
        )?;
        Ok(MOut::Fault(f(code, msg)))
    })
}

fn reviews_resolve(
    d: &mut Daemon,
    p: &Principal,
    req_id: &str,
    params: &Value,
) -> Result<MOut, HErr> {
    let rid = id(params.get("id").unwrap())?;
    let expected = u(params.get("expected_revision").unwrap())?;
    let action = s(params.get("action").unwrap())?.to_string();
    let reason = text(params.get("reason").unwrap())?;
    let wake = match params.get("wake_ms").unwrap() {
        Value::Null => None,
        v => Some(u(v)?),
    };
    let Some(rv) = d.load_review(&rid)? else {
        return Ok(MOut::Rejected(f(Code::NotFound, "review not found")));
    };
    if rv.revision != expected {
        return Ok(MOut::Rejected(f(
            Code::RevisionConflict,
            "revision mismatch",
        )));
    }
    // Hard due wins at equal timestamps: commit expiry, return LEASE_EXPIRED.
    if d.now >= rv.due_ms {
        return expire_then_fault(d, p, req_id, &rv, Code::LeaseExpired, "past due");
    }
    // Lease boundary on a CLAIMED item: release then fault.
    if rv.state == ReviewState::Claimed {
        if let Some(l) = rv.lease_until_ms {
            if d.now >= l {
                return release_then_fault(d, p, req_id, &rv, Code::LeaseExpired, "lease expired");
            }
        }
        if rv.owner.as_deref() != Some(p.id.as_str()) {
            return Ok(MOut::Rejected(f(Code::Forbidden, "not the owner")));
        }
    }
    // State guards.
    let legal = match (rv.state, action.as_str()) {
        (ReviewState::Claimed, "accept_risk") => rv.kind == "blocking",
        (ReviewState::Claimed, "reject") => rv.kind == "blocking",
        (ReviewState::Claimed, "annotate") => rv.kind == "trailing",
        (ReviewState::Claimed, "release") => true,
        (ReviewState::Claimed, "defer") => true,
        _ => false,
    };
    if !legal {
        return Ok(MOut::Rejected(f(Code::StateConflict, "no such transition")));
    }
    if action == "defer" {
        let w = wake.ok_or_else(|| f(Code::SchemaInvalid, "defer needs wake_ms"))?;
        if !(d.now < w && w < rv.due_ms) {
            return Ok(MOut::Rejected(f(
                Code::SchemaInvalid,
                "wake outside (now,due)",
            )));
        }
    }
    let now = d.now;
    let pid = p.id.clone();
    let req = req_id.to_string();
    let mut r2 = rv.clone();
    let kind_ev;
    match action.as_str() {
        "accept_risk" => {
            let pol = d
                .policy_for_run(&rv.run)?
                .ok_or_else(|| f(Code::ArtifactUnavailable, "policy unavailable"))?;
            r2.state = ReviewState::Accepted;
            r2.accepted_until_ms = Some((now + pol.review_accept_ms).min(rv.due_ms));
            kind_ev = "ReviewAccepted";
        }
        "reject" => {
            r2.state = ReviewState::Rejected;
            kind_ev = "ReviewRejected";
        }
        "annotate" => {
            r2.state = ReviewState::Closed;
            kind_ev = "ReviewClosed";
        }
        "release" => {
            r2.state = ReviewState::Open;
            r2.owner = None;
            r2.lease_until_ms = None;
            kind_ev = "ReviewReleased";
        }
        "defer" => {
            r2.state = ReviewState::Deferred;
            r2.owner = None;
            r2.lease_until_ms = None;
            r2.wake_ms = wake;
            kind_ev = "ReviewDeferred";
        }
        _ => unreachable!(),
    }
    r2.revision += 1;
    r2.resolution = Some(reason);
    r2.resolved_by = Some(pid.clone());
    let rev = r2.revision;
    let st_str = r2.state.as_str().to_string();
    let latch_action = if action == "reject" && rv.kind == "blocking" {
        // Latch (run, Intent.action) as rejected via the review's check.
        rv.check
            .clone()
            .and_then(|cid| d.load_check(&cid).ok().flatten().map(|c| c.intent.action))
    } else {
        None
    };
    d.mutate_h(now, move |d, tx, now, emitted| {
        let (seq, _) = emit(
            tx,
            &d.emit_ctx(),
            now,
            &pid,
            &req,
            kind_ev,
            review_value(&r2),
            vec![],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "reviews",
            &rid,
            &jcs(&review_value(&r2)).into_bytes(),
            seq,
            "reviews",
        )?;
        if let Some(act) = &latch_action {
            // Mark the action rejected; keep its intent binding.
            let intent_d = {
                use rusqlite::OptionalExtension;
                tx.query_row(
                    "SELECT intent_digest FROM actions WHERE run=?1 AND action=?2",
                    rusqlite::params![r2.run, act],
                    |r| r.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| f(Code::AuditUnavailable, &e.to_string()))?
                .unwrap_or_default()
            };
            if !intent_d.is_empty() {
                Store::tx_action_put(tx, &r2.run, act, &intent_d, true)?;
            }
        }
        Ok(MOut::Ok(Value::obj(vec![
            ("id", Value::str(&rid)),
            ("revision", Value::ustr(&rev.to_string())),
            ("state", Value::str(&st_str)),
        ])))
    })
}

fn alerts_resolve(
    d: &mut Daemon,
    p: &Principal,
    req_id: &str,
    params: &Value,
) -> Result<MOut, HErr> {
    let aid = id(params.get("id").unwrap())?;
    let expected = u(params.get("expected_revision").unwrap())?;
    let action = s(params.get("action").unwrap())?.to_string();
    let _reason = text(params.get("reason").unwrap())?;
    let Some(a) = d.load_alert(&aid)? else {
        return Ok(MOut::Rejected(f(Code::NotFound, "alert not found")));
    };
    if a.revision != expected {
        return Ok(MOut::Rejected(f(
            Code::RevisionConflict,
            "revision mismatch",
        )));
    }
    let legal = matches!(
        (a.state, action.as_str()),
        (AlertState::Open, "acknowledge")
            | (AlertState::Open, "resolve")
            | (AlertState::Acknowledged, "resolve")
    );
    if !legal {
        return Ok(MOut::Rejected(f(Code::StateConflict, "no such transition")));
    }
    let now = d.now;
    let pid = p.id.clone();
    let req = req_id.to_string();
    let mut a2 = a.clone();
    let kind_ev;
    match action.as_str() {
        "acknowledge" => {
            a2.state = AlertState::Acknowledged;
            kind_ev = "AlertAcknowledged";
        }
        "resolve" => {
            a2.state = AlertState::Resolved;
            a2.resolved_by = Some(pid.clone());
            kind_ev = "AlertResolved";
        }
        _ => unreachable!(),
    }
    a2.revision += 1;
    let rev = a2.revision;
    let st_str = a2.state.as_str().to_string();
    d.mutate_h(now, move |d, tx, now, emitted| {
        let (seq, _) = emit(
            tx,
            &d.emit_ctx(),
            now,
            &pid,
            &req,
            kind_ev,
            alert_value(&a2),
            vec![],
            emitted,
        )?;
        Store::tx_put_entity(
            tx,
            "alerts",
            &aid,
            &jcs(&alert_value(&a2)).into_bytes(),
            seq,
            "alerts",
        )?;
        Ok(MOut::Ok(Value::obj(vec![
            ("id", Value::str(&aid)),
            ("revision", Value::ustr(&rev.to_string())),
            ("state", Value::str(&st_str)),
        ])))
    })
}

fn audit_evaluate(
    d: &mut Daemon,
    p: &Principal,
    req_id: &str,
    params: &Value,
) -> Result<MOut, HErr> {
    let input = eval_input(params.get("input").unwrap())?;
    let input_digest = crate::crypto::d("eval-input", params.get("input").unwrap());
    // Idempotent by input digest.
    if let Some(out) = d.store.evaluation_by_input(&input_digest)? {
        let v = crate::json::parse(&out, &crate::json::Limits::reply())
            .map_err(|_| f(Code::AuditUnavailable, "eval parse"))?;
        return Ok(MOut::Ok(v));
    }
    if d.store.evaluation_by_id(&input.id)?.is_some() {
        return Ok(MOut::Rejected(f(
            Code::IdempotencyConflict,
            "evaluation id reused",
        )));
    }
    let output_v = crate::auditmath::evaluate(&input, params.get("input").unwrap())?;
    let now = d.now;
    let pid = p.id.clone();
    let req = req_id.to_string();
    let input_bytes = jcs(params.get("input").unwrap()).into_bytes();
    let out_bytes = jcs(&output_v).into_bytes();
    let eval_id = input.id.clone();
    let res = d.mutate_h(now, move |d, tx, now, emitted| {
        // Encrypted object first, then DB reference (§6.1).
        if let Some(objects) = &d.objects {
            objects
                .put(&d.cfg.tenant, "eval-input", &input_digest, &input_bytes)
                .map_err(|e| f(Code::ArtifactUnavailable, &e.message))?;
            Store::tx_object_put(
                tx,
                &input_digest,
                "eval-input",
                input_bytes.len() as u64,
                "sealed",
                "never",
            )?;
        }
        let (seq, _) = emit(
            tx,
            &d.emit_ctx(),
            now,
            &pid,
            &req,
            "EvaluationRecorded",
            crate::json::parse(&out_bytes, &crate::json::Limits::reply())
                .map_err(|_| f(Code::AuditUnavailable, "eval parse"))?,
            vec![input_digest.clone()],
            emitted,
        )?;
        Store::tx_evaluation_put(tx, &eval_id, &input_digest, &out_bytes, seq)?;
        Ok(MOut::Ok(
            crate::json::parse(&out_bytes, &crate::json::Limits::reply())
                .map_err(|_| f(Code::AuditUnavailable, "eval parse"))?,
        ))
    });
    res
}

fn audit_sample(params: &Value) -> R<Value> {
    let pop_v = params.get("population").unwrap();
    let pop: Vec<String> = arr(pop_v)?.iter().map(id).collect::<R<Vec<_>>>()?;
    let pdg = hash(params.get("population_digest").unwrap())?;
    let seed = hash(params.get("seed").unwrap())?;
    let k = n(params.get("k").unwrap())? as usize;
    if d("population", pop_v) != pdg {
        return Err(f(Code::SchemaInvalid, "population_digest mismatch"));
    }
    // Deterministic selection: sort by D("sample-rank",{seed,member}).
    let mut ranked: Vec<(String, String)> = pop
        .iter()
        .map(|m| {
            (
                d(
                    "sample-rank",
                    &Value::obj(vec![("member", Value::str(m)), ("seed", Value::str(&seed))]),
                ),
                m.clone(),
            )
        })
        .collect();
    ranked.sort();
    let selected: Vec<Value> = ranked
        .into_iter()
        .take(k)
        .map(|(_, m)| Value::str(&m))
        .collect();
    let commitment = d(
        "sample-commit",
        &Value::obj(vec![
            ("k", Value::num(k as u64)),
            ("population", Value::str(&pdg)),
            ("seed", Value::str(&seed)),
        ]),
    );
    Ok(Value::obj(vec![
        ("selected", Value::Arr(selected)),
        ("commitment", Value::str(&commitment)),
    ]))
}

fn events_read(d: &Daemon, params: &Value) -> R<Value> {
    let after = u(params.get("after").unwrap())?;
    let limit = n(params.get("limit").unwrap())? as usize;
    let through = resolve_through(d, params.get("through").unwrap())?;
    let (items, next) = d.store.events_page(after, through.seq, limit)?;
    let mut vals = Vec::new();
    for b in items {
        vals.push(
            crate::json::parse(&b, &crate::json::Limits::reply())
                .map_err(|_| f(Code::AuditUnavailable, "event parse"))?,
        );
    }
    Ok(Value::obj(vec![
        ("items", Value::Arr(vals)),
        ("through", head_value(&through)),
        (
            "next_after",
            match next {
                Some(x) => Value::ustr(&x.to_string()),
                None => Value::Null,
            },
        ),
    ]))
}

fn bundle_export(
    d: &mut Daemon,
    p: &Principal,
    req_id: &str,
    params: &Value,
) -> Result<MOut, HErr> {
    let through = match resolve_through(d, params.get("through").unwrap()) {
        Ok(t) => t,
        Err(e) => return Ok(MOut::Rejected(e)),
    };
    let disclosure = s(params.get("disclosure").unwrap())?.to_string();
    let recipient = id(params.get("recipient").unwrap())?;
    let bundle = match crate::bundle::export(d, &through, &disclosure, &recipient) {
        Ok(b) => b,
        Err(e) => return Ok(MOut::Rejected(e)),
    };
    // Size bound: one Reply frame ≤ 8 MiB — check before output.
    let bytes = jcs(&bundle).into_bytes();
    if bytes.len() > crate::REPLY_MAX {
        return Ok(MOut::Rejected(f(
            Code::BundleLimit,
            "export exceeds reply bound",
        )));
    }
    let digest = crate::crypto::sha256_hex(&bytes);
    let now = d.now;
    let pid = p.id.clone();
    let req = req_id.to_string();
    let d2 = disclosure.clone();
    let rec = recipient.clone();
    let res = d.mutate_h(now, move |d, tx, now, emitted| {
        // Export object stored encrypted; the event records the manifest.
        if let Some(objects) = &d.objects {
            objects
                .put(&d.cfg.tenant, "export", &digest, &bytes)
                .map_err(|e| f(Code::ArtifactUnavailable, &e.message))?;
            Store::tx_object_put(tx, &digest, "export", bytes.len() as u64, "sealed", "never")?;
        }
        let er = Value::obj(vec![
            ("bundle", Value::str(&digest)),
            ("through", head_value(&through)),
            ("disclosure", Value::str(&d2)),
            ("recipient", Value::str(&rec)),
        ]);
        emit(
            tx,
            &d.emit_ctx(),
            now,
            &pid,
            &req,
            "ExportRecorded",
            er,
            vec![],
            emitted,
        )?;
        Ok(MOut::Ok(
            crate::json::parse(&bytes, &crate::json::Limits::reply())
                .map_err(|_| f(Code::AuditUnavailable, "bundle parse"))?,
        ))
    });
    res
}
