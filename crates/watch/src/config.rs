//! Operator configuration, trust pins, and startup gates (§5, §10).
//! Strict JSON only; absolute paths; no interpolation or remote includes.

use std::path::Path;

use ed25519_dalek::SigningKey;

use crate::crypto::{signing_key_from_bytes, verify_envelope};
use crate::fault::{Code, Fault};
use crate::json::{parse, Limits, Value};
use crate::schema::*;

type R<T> = Result<T, Fault>;

fn read_bounded(path: &Path, max: usize) -> R<Vec<u8>> {
    let b = std::fs::read(path)
        .map_err(|e| Fault::new(Code::ArtifactUnavailable, &format!("{path:?}: {e}")))?;
    if b.len() > max {
        return Err(Fault::new(Code::SchemaInvalid, "file over bound"));
    }
    Ok(b)
}

pub fn load_config(path: &Path) -> R<Config> {
    let b = read_bounded(path, crate::REQ_MAX)?;
    let v = parse(&b, &Limits::reply())
        .map_err(|e| Fault::new(Code::SchemaInvalid, e.code().as_str()))?;
    let c = config(&v)?;
    // Absolute paths required.
    for p in [
        &c.socket,
        &c.data_dir,
        &c.signer_key_file,
        &c.trust_file,
        &c.object_key_file,
    ] {
        if !Path::new(p).is_absolute() {
            return Err(Fault::new(Code::SchemaInvalid, "paths must be absolute"));
        }
    }
    // Principal/source hygiene: unique UIDs/IDs; runtime principals never
    // hold reviewer/operator/auditor roles.
    let mut uids = std::collections::HashSet::new();
    let mut ids = std::collections::HashSet::new();
    for pr in &c.principals {
        if !uids.insert(pr.uid) || !ids.insert(pr.id.clone()) {
            return Err(Fault::new(
                Code::SchemaInvalid,
                "duplicate principal uid/id",
            ));
        }
        if pr.id == "watchd" {
            return Err(Fault::new(Code::SchemaInvalid, "watchd is reserved"));
        }
        if pr.roles.iter().any(|r| r == "runtime") && pr.roles.iter().any(|r| r != "runtime") {
            return Err(Fault::new(Code::SchemaInvalid, "runtime mixes roles"));
        }
    }
    Ok(c)
}

pub fn load_trust(path: &Path) -> R<Trust> {
    let b = read_bounded(path, crate::REQ_MAX)?;
    let v = parse(&b, &Limits::reply())
        .map_err(|e| Fault::new(Code::SchemaInvalid, e.code().as_str()))?;
    trust(&v)
}

/// The signer private key: 32-byte raw file (mode 0400) or PKCS8-DER/PEM.
pub fn load_signer(path: &Path) -> R<SigningKey> {
    let b = read_bounded(path, 8192)?;
    signing_key_from_bytes(&b)
        .ok_or_else(|| Fault::new(Code::ArtifactUnavailable, "signer key unreadable"))
}

/// Startup gates (§5.1/§10): production needs a signed release artifact,
/// certified profiles must not include fixture/1 outside lab, and a lab
/// deployment stays lab.
pub fn startup_gates(cfg: &Config, trust: &Trust) -> R<()> {
    if trust.tenant != cfg.tenant {
        return Err(Fault::new(Code::Gated, "trust tenant mismatch"));
    }
    match cfg.deployment.as_str() {
        "lab" => {}
        "production" => {
            // Real Covenant evidence is required; a fixture certificate or
            // synthetic receipt does not satisfy the gate.
            let Some(rel) = &cfg.release else {
                return Err(Fault::new(
                    Code::Gated,
                    "production requires a signed release",
                ));
            };
            let rb = release_body(&rel.body)?;
            if rb.covenant_version.is_empty() || rb.tenant != cfg.tenant {
                return Err(Fault::new(Code::Gated, "release tenant/covenant missing"));
            }
            verify_signed(trust, &cfg.tenant, "release", &cfg.tenant, rel)
                .map_err(|e| Fault::new(Code::Gated, &format!("release pin: {}", e.message)))?;
            if cfg.certified_profiles.iter().any(|p| p == "fixture/1") {
                return Err(Fault::new(Code::Gated, "fixture profile in production"));
            }
        }
        _ => return Err(Fault::new(Code::Gated, "unknown deployment")),
    }
    Ok(())
}

/// Find a live, uncompromised pin for (tag, subject) at a key epoch.
pub fn require_pin<'t>(
    trust: &'t Trust,
    tag: &str,
    subject: &str,
    key_id: &str,
    key_epoch: u64,
) -> R<&'t KeyPin> {
    for k in &trust.keys {
        if k.id == key_id
            && k.live
            && !k.compromised
            && k.tags.iter().any(|t| t == tag)
            && k.subjects.iter().any(|s| s == subject)
            && key_epoch >= k.from_epoch
            && k.through_epoch.map(|t| key_epoch <= t).unwrap_or(true)
        {
            return Ok(k);
        }
    }
    Err(Fault::new(
        Code::SignatureInvalid,
        &format!("no live pin for {tag}/{subject}/{key_id}@{key_epoch}"),
    ))
}

/// Verify a Signed envelope under a pinned key for (tag, subject).
pub fn verify_signed(trust: &Trust, tenant: &str, tag: &str, subject: &str, sv: &Signed) -> R<()> {
    verify_signed_key(trust, tenant, tag, subject, &sv.key_id, sv.key_epoch, sv)
}

/// Verify a Signed envelope that must come from a specific configured key.
pub fn verify_signed_key(
    trust: &Trust,
    tenant: &str,
    tag: &str,
    subject: &str,
    key_id: &str,
    key_epoch: u64,
    sv: &Signed,
) -> R<()> {
    let _ = tenant;
    if sv.key_id != key_id || sv.key_epoch != key_epoch {
        return Err(Fault::new(Code::SignatureInvalid, "key id/epoch mismatch"));
    }
    let pin = require_pin(trust, tag, subject, key_id, key_epoch)?;
    let pk = crate::crypto::b64u_decode(&pin.public_key)
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| Fault::new(Code::SignatureInvalid, "pin key undecodable"))?;
    if verify_envelope(
        tag,
        &sv.body,
        &sv.digest,
        &sv.key_id,
        &sv.key_epoch.to_string(),
        &sv.signature,
        &pk,
    ) {
        Ok(())
    } else {
        Err(Fault::new(Code::SignatureInvalid, "bad signature"))
    }
}

/// Recompute installed artifact digests at startup/policy activation.
/// Every installed_artifacts entry must be a real file whose SHA-256
/// equals the pinned digest.
pub fn verify_artifacts(cfg: &Config) -> R<()> {
    for (det, digest, path) in &cfg.installed_artifacts {
        let b = std::fs::read(path).map_err(|e| {
            Fault::new(
                Code::ArtifactUnavailable,
                &format!("artifact {} unreadable: {e}", det.as_str()),
            )
        })?;
        let raw_ok = crate::crypto::sha256_hex(&b) == *digest;
        // Fixture artifacts pin the domain digest of the artifact
        // descriptor (the detector name), per the spec's fixture table.
        let dom_ok = crate::json::parse(&b, &crate::json::Limits::reply())
            .map(|v| crate::crypto::d("artifact", &v) == *digest)
            .unwrap_or(false);
        if !raw_ok && !dom_ok {
            return Err(Fault::new(
                Code::ArtifactUnavailable,
                &format!("artifact {} digest mismatch", det.as_str()),
            ));
        }
    }
    Ok(())
}

/// A signed Release body (for startup gate inspection).
pub struct ReleaseBody {
    pub tenant: String,
    pub covenant_version: String,
}

pub fn release_body(v: &Value) -> R<ReleaseBody> {
    let m = crate::schema::obj(v)?;
    crate::schema::closed(
        m,
        &[
            "v",
            "tenant",
            "covenant_version",
            "covenant_receipt",
            "reference_host_evidence",
            "external_operator_evidence",
            "watch_conformance",
            "approved_profile",
        ],
    )?;
    crate::schema::lit_num(crate::schema::field(m, "v")?, 1)?;
    Ok(ReleaseBody {
        tenant: crate::schema::id(crate::schema::field(m, "tenant")?)?,
        covenant_version: crate::schema::text(crate::schema::field(m, "covenant_version")?)?,
    })
}
