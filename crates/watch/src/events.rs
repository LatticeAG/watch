//! Signed audit event emission inside the writer transaction (§1.3/§6.1).

use ed25519_dalek::SigningKey;
use rusqlite::Transaction;

use crate::crypto::{d, sign_envelope};
use crate::fault::{Code, Fault};
use crate::json::{jcs, Value};
use crate::schema::{event_body, event_body_value, EventBody};
use crate::store::Store;

/// Signer/host context for event emission.
pub struct EmitCtx<'a> {
    pub tenant: &'a str,
    pub epoch: u64,
    pub boot: &'a str,
    pub key_id: &'a str,
    pub key_epoch: u64,
    pub sk: &'a SigningKey,
}

/// Build, sign, and durably append one audit event. `emitted` carries the
/// digests of events already appended in this transaction so causes may
/// reference them. Returns (seq, event digest).
#[allow(clippy::too_many_arguments)]
pub fn emit(
    tx: &Transaction,
    ctx: &EmitCtx,
    now: u64,
    actor: &str,
    request: &str,
    kind: &str,
    value: Value,
    causes: Vec<String>,
    emitted: &mut Vec<String>,
) -> Result<(u64, String), Fault> {
    let head = Store::tx_head(tx)?;
    let seq = head.seq + 1;

    // causes: sorted unique set of already-durable local commitments.
    let mut causes = causes;
    causes.sort();
    causes.dedup();
    if causes.len() > crate::SET_MAX {
        return Err(Fault::new(Code::SchemaInvalid, "causes set too large"));
    }
    for c in &causes {
        if !emitted.contains(c) && !Store::tx_known_commitment(tx, c)? {
            return Err(Fault::new(Code::AuditUnavailable, "cause not durable"));
        }
    }

    let body = EventBody {
        tenant: ctx.tenant.to_string(),
        seq,
        prev: head.hash.clone(),
        epoch: ctx.epoch,
        boot: ctx.boot.to_string(),
        at_ms: now,
        actor: actor.to_string(),
        request: request.to_string(),
        kind: kind.to_string(),
        value,
        causes,
    };
    let body_v = event_body_value(&body);
    // Never emit an event our own schema would reject.
    match event_body(&body_v) {
        Ok(_) => {}
        Err(e) => {
            eprintln!(
                "EMIT REJECT kind={} err={} {}",
                kind,
                e.code.as_str(),
                e.message
            );
            eprintln!("body={}", jcs(&body_v));
            return Err(Fault::new(Code::AuditUnavailable, &e.message));
        }
    }
    let body_bytes = jcs(&body_v).into_bytes();
    let env_v = sign_envelope(
        "audit",
        &body_v,
        ctx.key_id,
        &ctx.key_epoch.to_string(),
        ctx.sk,
    );
    let env_bytes = jcs(&env_v).into_bytes();
    let digest = d("audit", &body_v);
    Store::tx_append_audit(
        tx,
        &body_bytes,
        &env_bytes,
        seq,
        &digest,
        &head.hash,
        ctx.epoch,
        kind,
    )?;
    emitted.push(digest.clone());
    Ok((seq, digest))
}
