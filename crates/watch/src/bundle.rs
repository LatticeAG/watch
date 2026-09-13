//! §9.4 proof export: Bundle = {manifest:Signed<BundleBody>, events,
//! policies, observations, effects, evaluations}. `from` is EMPTY in v1;
//! FULL carries every referenced artifact, COMMITMENTS inventories them
//! with present=false.

use crate::crypto::sign_envelope;
use crate::daemon::Daemon;
use crate::fault::{Code, Fault};
use crate::json::{parse, Limits, Value};
use crate::schema::*;

type R<T> = Result<T, Fault>;

pub fn export(d: &Daemon, through: &Head, disclosure: &str, _recipient: &str) -> R<Value> {
    // All audit events ≤ through.seq, in order. An empty cut exports the
    // EMPTY_HISTORY bundle: no events, no inventory.
    let events = if through.seq == 0 {
        vec![]
    } else {
        d.store.events_to(through.seq)?
    };
    let empty_cut = through.seq == 0;
    let mut event_hashes = Vec::new();
    let mut event_vals = Vec::new();
    for b in &events {
        let v = parse(b, &Limits::reply())
            .map_err(|_| Fault::new(Code::AuditUnavailable, "event parse"))?;
        event_hashes.push(Value::str(&crate::crypto::sha256_hex(b)));
        event_vals.push(v);
    }

    // Referenced policies: all activated policies in the window (v1: all).
    let mut policy_vals = Vec::new();
    let mut inventory: Vec<(String, String, u64, bool)> = Vec::new();
    if !empty_cut {
        let mut st = d
            .store
            .conn
            .prepare("SELECT digest,body FROM policies ORDER BY generation")
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        let rows = st
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        for r in rows {
            let (dg, body) = r.map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let v = parse(&body, &Limits::reply())
                .map_err(|_| Fault::new(Code::AuditUnavailable, "policy parse"))?;
            // Inventory digest is the envelope's body digest.
            let sv = signed(&v)?;
            inventory.push(("policy".into(), sv.digest, body.len() as u64, true));
            policy_vals.push(v);
            let _ = dg;
        }
    }

    // Observations + effects: FULL includes bytes; COMMITMENTS inventories
    // them with present=false.
    let full = disclosure == "FULL";
    let mut obs_vals = Vec::new();
    let mut eff_vals = Vec::new();
    if !empty_cut {
        let mut st = d
            .store
            .conn
            .prepare("SELECT digest,envelope FROM observations ORDER BY run,seq")
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        let rows = st
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        for r in rows {
            let (_dg, env) = r.map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let v = parse(&env, &Limits::reply())
                .map_err(|_| Fault::new(Code::AuditUnavailable, "obs parse"))?;
            let sv = signed(&v)?;
            inventory.push((
                "observation".into(),
                sv.digest.clone(),
                env.len() as u64,
                full,
            ));
            if full {
                obs_vals.push(v);
            }
        }
    }
    if !empty_cut {
        let mut st = d
            .store
            .conn
            .prepare("SELECT digest,envelope FROM effects ORDER BY run,action")
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        let rows = st
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        for r in rows {
            let (_dg, env) = r.map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let v = parse(&env, &Limits::reply())
                .map_err(|_| Fault::new(Code::AuditUnavailable, "effect parse"))?;
            let sv = signed(&v)?;
            inventory.push(("effect".into(), sv.digest.clone(), env.len() as u64, full));
            if full {
                eff_vals.push(v);
            }
        }
    }

    // Evaluations: complete {input,output} pairs in output.id order. The
    // input lives encrypted in the object store keyed by eval-input digest.
    let mut eval_vals = Vec::new();
    if !empty_cut {
        let mut st = d
            .store
            .conn
            .prepare("SELECT id,input_digest,output FROM evaluations ORDER BY id")
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
        for r in rows {
            let (_id, idg, out) =
                r.map_err(|e| Fault::new(Code::AuditUnavailable, &e.to_string()))?;
            let out_v = parse(&out, &Limits::reply())
                .map_err(|_| Fault::new(Code::AuditUnavailable, "eval parse"))?;
            let pair_digest = crate::crypto::d(
                "evaluation",
                &Value::obj(vec![
                    ("input", Value::Null), // placeholder replaced below
                    ("output", out_v.clone()),
                ]),
            );
            let _ = pair_digest;
            let input_v = if let Some(objects) = &d.objects {
                match objects.get(&d.cfg.tenant, "eval-input", &idg) {
                    Ok(b) => parse(&b, &Limits::reply())
                        .map_err(|_| Fault::new(Code::AuditUnavailable, "eval input parse"))?,
                    Err(_) if full => {
                        return Err(Fault::new(
                            Code::ArtifactUnavailable,
                            "eval input object missing",
                        ))
                    }
                    Err(_) => Value::Null,
                }
            } else {
                if full {
                    return Err(Fault::new(
                        Code::ArtifactUnavailable,
                        "object store unavailable",
                    ));
                }
                Value::Null
            };
            let present = full && input_v != Value::Null;
            // The inventory covers the {input,output} pair digest.
            let pair_d = if present {
                crate::crypto::d(
                    "evaluation",
                    &Value::obj(vec![("input", input_v.clone()), ("output", out_v.clone())]),
                )
            } else {
                idg.clone()
            };
            inventory.push(("evaluation".into(), pair_d, out.len() as u64, present));
            if present {
                eval_vals.push(Value::obj(vec![("input", input_v), ("output", out_v)]));
            }
        }
    }

    inventory.sort();
    let mut limitations = Vec::new();
    if empty_cut {
        limitations.push("EMPTY_HISTORY".to_string());
    } else if !full {
        limitations.push("observations/effects/evaluations omitted; commitments only".to_string());
    }
    let manifest_body = Value::obj(vec![
        ("v", Value::num(1)),
        ("format", Value::str("watch-proof/1")),
        ("tenant", Value::str(&d.cfg.tenant)),
        ("from", head_value(&empty_head())),
        ("through", head_value(through)),
        ("disclosure", Value::str(disclosure)),
        (
            "inventory",
            Value::Arr(
                inventory
                    .iter()
                    .map(|(tag, dg, bytes, present)| {
                        Value::obj(vec![
                            ("tag", Value::str(tag)),
                            ("digest", Value::str(dg)),
                            ("bytes", Value::ustr(&bytes.to_string())),
                            ("present", Value::Bool(*present)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("event_hashes", Value::Arr(event_hashes)),
        (
            "limitations",
            Value::Arr(limitations.iter().map(|l| Value::str(l)).collect()),
        ),
        (
            "semantics",
            Value::str("OBSERVATIONS_NOT_ACTION_AUTHORIZATION"),
        ),
    ]);
    let manifest = sign_envelope(
        "bundle",
        &manifest_body,
        &d.cfg.signer_key_id,
        &d.cfg.signer_key_epoch.to_string(),
        &d.sk,
    );
    Ok(Value::obj(vec![
        ("manifest", manifest),
        ("events", Value::Arr(event_vals)),
        ("policies", Value::Arr(policy_vals)),
        ("observations", Value::Arr(obs_vals)),
        ("effects", Value::Arr(eff_vals)),
        ("evaluations", Value::Arr(eval_vals)),
    ]))
}
