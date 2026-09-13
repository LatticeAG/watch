//! Hashing domains, Ed25519 envelopes, and wire encodings.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::json::{jcs, Value};

/// SHA-256 hex digest of raw bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex_lower(&h.finalize())
}

/// `D(tag,x)=hex(H(UTF8("LAGI-WATCH/1/"+tag)||0x00||J(x)))`.
pub fn d(tag: &str, x: &Value) -> String {
    let mut h = Sha256::new();
    h.update(format!("LAGI-WATCH/1/{tag}").as_bytes());
    h.update([0x00]);
    h.update(jcs(x).as_bytes());
    hex_lower(&h.finalize())
}

/// Signature message for a signed envelope:
/// `UTF8("LAGI-WATCH/1/sign/"+tag)||0x00||J({digest,key_id,key_epoch})`.
pub fn sign_message(tag: &str, digest: &str, key_id: &str, key_epoch: &str) -> Vec<u8> {
    let meta = Value::obj(vec![
        ("digest", Value::str(digest)),
        ("key_id", Value::str(key_id)),
        ("key_epoch", Value::str(key_epoch)),
    ]);
    let mut m = format!("LAGI-WATCH/1/sign/{tag}").into_bytes();
    m.push(0);
    m.extend_from_slice(jcs(&meta).as_bytes());
    m
}

/// Produce a complete `Signed<T>` envelope value.
pub fn sign_envelope(
    tag: &str,
    body: &Value,
    key_id: &str,
    key_epoch: &str,
    sk: &SigningKey,
) -> Value {
    let digest = d(tag, body);
    let msg = sign_message(tag, &digest, key_id, key_epoch);
    let sig = sk.sign(&msg);
    Value::obj(vec![
        ("body", body.clone()),
        ("digest", Value::str(&digest)),
        ("key_id", Value::str(key_id)),
        ("key_epoch", Value::str(key_epoch)),
        ("signature", Value::str(&b64u_encode(&sig.to_bytes()))),
    ])
}

/// Verify a signed envelope's digest and signature against a public key.
pub fn verify_envelope(
    tag: &str,
    body: &Value,
    digest: &str,
    key_id: &str,
    key_epoch: &str,
    signature: &str,
    public_key: &[u8; 32],
) -> bool {
    if d(tag, body) != digest {
        return false;
    }
    let sig_bytes = match b64u_decode(signature) {
        Some(b) if b.len() == 64 => b,
        _ => return false,
    };
    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let vk = match VerifyingKey::from_bytes(public_key) {
        Ok(v) => v,
        Err(_) => return false,
    };
    vk.verify(&sign_message(tag, digest, key_id, key_epoch), &sig)
        .is_ok()
}

pub fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = hex_nibble(b[i])?;
        let lo = hex_nibble(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

pub fn b64u_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Strict unpadded base64url decode; rejects padding and foreign alphabets.
pub fn b64u_decode(s: &str) -> Option<Vec<u8>> {
    if s.contains('=') {
        return None;
    }
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// A 64-byte canonical signature encoding.
pub fn is_sig(s: &str) -> bool {
    b64u_decode(s).map(|b| b.len() == 64).unwrap_or(false)
}

/// A 32-byte canonical public key encoding.
pub fn is_pub(s: &str) -> bool {
    b64u_decode(s).map(|b| b.len() == 32).unwrap_or(false)
}

/// A 24-byte canonical nonce encoding.
pub fn is_nonce(s: &str) -> bool {
    b64u_decode(s).map(|b| b.len() == 24).unwrap_or(false)
}

pub fn pub_b64u(key: &[u8; 32]) -> String {
    b64u_encode(key)
}

/// Load an Ed25519 signing key from PKCS8 DER or a raw 32-byte seed.
pub fn signing_key_from_bytes(der_or_seed: &[u8]) -> Option<SigningKey> {
    if der_or_seed.len() == 32 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(der_or_seed);
        return Some(SigningKey::from_bytes(&seed));
    }
    // PKCS8 DER: 302e020100300506032b657004220420<32-byte seed>
    const PKCS8_PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    if der_or_seed.len() == 48 && der_or_seed[..16] == PKCS8_PREFIX {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&der_or_seed[16..48]);
        return Some(SigningKey::from_bytes(&seed));
    }
    // PEM armor
    if let Ok(text) = std::str::from_utf8(der_or_seed) {
        let body: String = text
            .lines()
            .filter(|l| !l.starts_with("-----") && !l.trim().is_empty())
            .collect();
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(body.trim()) {
            return signing_key_from_bytes(&der);
        }
    }
    None
}
