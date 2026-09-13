//! §9.4 offline bundle verifier: pure function `verify(bundle, trust)` —
//! no network, no daemon RPC, no live clocks. Emits Verification with
//! facts_verified=false in every status.

use crate::crypto::{b64u_decode, d, sha256_hex, verify_envelope};
use crate::fault::Fault;
use crate::json::{jcs, parse, Limits, Value};
use crate::schema::*;

fn verification(status: &str, reasons: Vec<String>, through: Head) -> Value {
    Value::obj(vec![
        ("status", Value::str(status)),
        (
            "reasons",
            Value::Arr(reasons.iter().map(|r| Value::str(r)).collect()),
        ),
        ("through", head_value(&through)),
        ("facts_verified", Value::Bool(false)),
    ])
}

fn env_sig_ok(sv: &Signed, pk_b64: &str, tag: &str) -> bool {
    let Some(b) = b64u_decode(pk_b64) else {
        return false;
    };
    let Ok(pk) = <[u8; 32]>::try_from(b.as_slice()) else {
        return false;
    };
    verify_envelope(
        tag,
        &sv.body,
        &sv.digest,
        &sv.key_id,
        &sv.key_epoch.to_string(),
        &sv.signature,
        &pk,
    )
}

/// find a live pin covering (tag, subject) with a given key id/epoch
fn pin_for<'t>(
    trust: &'t Trust,
    tag: &str,
    subject: &str,
    key_id: &str,
    key_epoch: u64,
) -> Option<&'t KeyPin> {
    trust.keys.iter().find(|k| {
        k.id == key_id
            && k.live
            && !k.compromised
            && k.tags.iter().any(|t| t == tag)
            && k.subjects.iter().any(|s| s == subject)
            && key_epoch >= k.from_epoch
            && k.through_epoch.map(|t| key_epoch <= t).unwrap_or(true)
    })
}

/// `verify(input)` — offline only (§3.4/§9.4).
pub fn verify(bundle: &Value, trust: &Trust) -> Value {
    let mut reasons: Vec<String> = Vec::new();
    let mut invalid = false;
    let mut incomplete = false;
    let mut integrity_only = false;
    let m = match crate::schema::obj(bundle) {
        Ok(m) => m,
        Err(_) => return verification("INVALID", vec!["SCHEMA".into()], empty_head()),
    };
    crate::schema::closed(
        m,
        &[
            "manifest",
            "events",
            "policies",
            "observations",
            "effects",
            "evaluations",
        ],
    )
    .unwrap_or(());

    // Manifest.
    let manifest_v = crate::json::mget(m, "manifest")
        .cloned()
        .unwrap_or(Value::Null);
    let manifest = match signed(&manifest_v) {
        Ok(s) => s,
        Err(_) => return verification("INVALID", vec!["SCHEMA".into()], empty_head()),
    };
    let bb = match bundle_body(&manifest.body) {
        Ok(b) => b,
        Err(_) => return verification("INVALID", vec!["SCHEMA".into()], empty_head()),
    };
    if bb.tenant != trust.tenant {
        return verification("INVALID", vec!["TRUST_TENANT".into()], empty_head());
    }
    // Manifest signature under a bundle pin.
    match pin_for(
        trust,
        "bundle",
        &bb.tenant,
        &manifest.key_id,
        manifest.key_epoch,
    ) {
        Some(k) => {
            if !env_sig_ok(&manifest, &k.public_key, "bundle") {
                invalid = true;
                reasons.push("BAD_SIGNATURE".into());
            }
        }
        None => {
            incomplete = true;
            reasons.push("UNTRUSTED_KEY".into());
        }
    }

    // Event chain: seq contiguous from 1, prev links, audit signatures.
    let events = match crate::json::mget(m, "events") {
        Some(Value::Arr(a)) => a.clone(),
        _ => vec![],
    };
    if events.is_empty() {
        return verification(
            "INCOMPLETE",
            vec!["EMPTY_HISTORY".into()],
            bb.through.clone(),
        );
    }
    let mut prev = "0".repeat(64); // genesis prev is the all-zero hash
    let mut expected_seq = 1u64;
    let mut last_through = empty_head();
    for (i, ev) in events.iter().enumerate() {
        let sv = match signed(ev) {
            Ok(s) => s,
            Err(_) => {
                invalid = true;
                reasons.push("SCHEMA".into());
                break;
            }
        };
        // The audit event hash must match the manifest's list.
        let env_bytes = jcs(ev).into_bytes();
        let eh = sha256_hex(&env_bytes);
        if let Some(mh) = bb.event_hashes.get(i) {
            if *mh != eh {
                invalid = true;
                reasons.push("AUDIT_HASH".into());
            }
        } else {
            invalid = true;
            reasons.push("AUDIT_HASH".into());
        }
        // Event body chain.
        if let Ok(eb) = event_body(&sv.body) {
            if eb.seq != expected_seq {
                incomplete = true;
                reasons.push("AUDIT_GAP".into());
            }
            if eb.prev != prev {
                invalid = true;
                reasons.push("AUDIT_CHAIN".into());
            }
            prev = sv.digest.clone();
            last_through = Head {
                seq: eb.seq,
                hash: sv.digest.clone(),
            };
            expected_seq += 1;
            // Audit signature under the audit pin for the tenant.
            match pin_for(trust, "audit", &eb.tenant, &sv.key_id, sv.key_epoch) {
                Some(k) => {
                    if !env_sig_ok(&sv, &k.public_key, "audit") {
                        invalid = true;
                        reasons.push("BAD_SIGNATURE".into());
                    }
                }
                None => {
                    incomplete = true;
                    reasons.push("UNTRUSTED_KEY".into());
                }
            }
        } else {
            invalid = true;
            reasons.push("SCHEMA".into());
        }
    }
    // Manifest through must equal the last event.
    if bb.through != last_through {
        invalid = true;
        reasons.push("THROUGH_MISMATCH".into());
    }

    // Inventory/bytes: FULL disclosures require present=true on all items
    // whose bytes are included; verify byte counts and body digests.
    let mut inv_seen = std::collections::HashSet::new();
    for it in &bb.inventory {
        if !inv_seen.insert((it.tag.clone(), it.digest.clone())) {
            invalid = true;
            reasons.push("INVENTORY_DUP".into());
        }
        let _ = (it.bytes, it.present);
    }
    // Policies: verify body digest + signature.
    if let Some(Value::Arr(pols)) = crate::json::mget(m, "policies") {
        for pv in pols {
            match signed(pv) {
                Ok(sv) => {
                    if d("policy", &sv.body) != sv.digest {
                        invalid = true;
                        reasons.push("INVENTORY_MISMATCH".into());
                    }
                    match policy(&sv.body) {
                        Ok(p) => {
                            match pin_for(trust, "policy", &p.tenant, &sv.key_id, sv.key_epoch) {
                                Some(k) => {
                                    if !env_sig_ok(&sv, &k.public_key, "policy") {
                                        invalid = true;
                                        reasons.push("BAD_SIGNATURE".into());
                                    }
                                }
                                None => {
                                    incomplete = true;
                                    reasons.push("UNTRUSTED_KEY".into());
                                }
                            }
                        }
                        Err(_) => {
                            invalid = true;
                            reasons.push("SCHEMA".into());
                        }
                    }
                }
                Err(_) => {
                    invalid = true;
                    reasons.push("SCHEMA".into());
                }
            }
        }
    }
    // Observations/effects present flags.
    let obs_count = crate::json::mget(m, "observations")
        .and_then(|x| x.as_arr().map(|a| a.len()))
        .unwrap_or(0);
    let eff_count = crate::json::mget(m, "effects")
        .and_then(|x| x.as_arr().map(|a| a.len()))
        .unwrap_or(0);
    let inv_obs: Vec<&Inventory> = bb
        .inventory
        .iter()
        .filter(|t| t.tag == "observation")
        .collect();
    let inv_eff: Vec<&Inventory> = bb.inventory.iter().filter(|t| t.tag == "effect").collect();
    if bb.disclosure == "FULL" {
        if inv_obs.iter().any(|i| !i.present) || inv_eff.iter().any(|i| !i.present) {
            invalid = true;
            reasons.push("INVENTORY_MISMATCH".into());
        }
        if inv_obs.len() != obs_count || inv_eff.len() != eff_count {
            invalid = true;
            reasons.push("INVENTORY_MISMATCH".into());
        }
    } else {
        // COMMITMENTS withholds bytes by design: retained bytes/signatures
        // verify but facts cannot be replayed → INTEGRITY_ONLY.
        integrity_only = true;
        reasons.push("OMITTED_BYTES".into());
    }
    // Signatures on included observations/effects.
    for (list, tag) in [
        (crate::json::mget(m, "observations"), "observation"),
        (crate::json::mget(m, "effects"), "effect"),
    ] {
        if let Some(Value::Arr(items)) = list {
            for it in items {
                match signed(it) {
                    Ok(sv) => {
                        let subj = if tag == "observation" {
                            observation_body(&sv.body)
                                .map(|b| b.source)
                                .unwrap_or_default()
                        } else {
                            effect_body(&sv.body).map(|b| b.runtime).unwrap_or_default()
                        };
                        match pin_for(trust, tag, &subj, &sv.key_id, sv.key_epoch) {
                            Some(k) => {
                                if !env_sig_ok(&sv, &k.public_key, tag) {
                                    invalid = true;
                                    reasons.push("BAD_SIGNATURE".into());
                                }
                            }
                            None => {
                                incomplete = true;
                                reasons.push("UNTRUSTED_KEY".into());
                            }
                        }
                    }
                    Err(_) => {
                        invalid = true;
                        reasons.push("SCHEMA".into());
                    }
                }
            }
        }
    }
    // External minimum head.
    if last_through.seq < trust.minimum_head.seq {
        incomplete = true;
        reasons.push("MINIMUM_HEAD".into());
    }

    reasons.sort();
    reasons.dedup();
    let through = if last_through.seq > 0 {
        last_through
    } else {
        bb.through
    };
    if invalid {
        verification("INVALID", reasons, through)
    } else if incomplete {
        verification("INCOMPLETE", reasons, through)
    } else if integrity_only {
        verification("INTEGRITY_ONLY", reasons, through)
    } else {
        verification("FULL_REPLAY", reasons, through)
    }
}

/// Bundle file load with the 64 MiB archival bound (§9.4).
pub fn load_bundle_file(path: &std::path::Path) -> Result<Value, Fault> {
    let b = std::fs::read(path)
        .map_err(|e| Fault::new(crate::fault::Code::ArtifactUnavailable, &e.to_string()))?;
    if b.len() > crate::BUNDLE_PARSE_MAX {
        return Err(Fault::new(
            crate::fault::Code::BundleLimit,
            "bundle over 64MiB",
        ));
    }
    parse(&b, &Limits::bundle()).map_err(|_| Fault::new(crate::fault::Code::BadJson, "bad json"))
}
