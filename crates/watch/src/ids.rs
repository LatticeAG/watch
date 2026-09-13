//! Identifier grammar and entity prefixes.

/// `Id` matches `^[a-z][a-z0-9_-]{0,63}$`.
pub fn valid_id(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return false;
    }
    if !(b[0] >= b'a' && b[0] <= b'z') {
        return false;
    }
    b.iter().all(|c| {
        (*c >= b'a' && *c <= b'z') || (*c >= b'0' && *c <= b'9') || *c == b'_' || *c == b'-'
    })
}

/// `Text`: Unicode scalars, no NUL, at most 512 UTF-8 bytes.
pub fn valid_text(s: &str) -> bool {
    !s.contains('\0') && s.len() <= crate::TEXT_MAX
}

/// `Hash`: exactly 64 lowercase hexadecimal characters.
pub fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c: u8| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// `Boot`: lowercase Linux boot UUID.
pub fn valid_boot(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, c) in b.iter().enumerate() {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            if *c != b'-' {
                return false;
            }
        } else if !c.is_ascii_hexdigit() || c.is_ascii_uppercase() {
            return false;
        }
    }
    true
}

/// Entity prefix owners. Other IDs carry no authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityPrefix {
    Run,
    Check,
    Review,
    Alert,
    Policy,
    Evaluation,
}

pub fn entity_prefix(id: &str) -> Option<EntityPrefix> {
    if id.starts_with("wtr_") {
        Some(EntityPrefix::Run)
    } else if id.starts_with("wtc_") {
        Some(EntityPrefix::Check)
    } else if id.starts_with("wth_") {
        Some(EntityPrefix::Review)
    } else if id.starts_with("wta_") {
        Some(EntityPrefix::Alert)
    } else if id.starts_with("wtp_") {
        Some(EntityPrefix::Policy)
    } else if id.starts_with("wte_") {
        Some(EntityPrefix::Evaluation)
    } else {
        None
    }
}

/// Sorted unique ID set ≤ 64 entries in ascending ASCII order.
pub fn valid_id_set(ids: &[String]) -> bool {
    if ids.len() > crate::SET_MAX {
        return false;
    }
    for w in ids.windows(2) {
        if w[0] >= w[1] {
            return false;
        }
    }
    ids.iter().all(|i| valid_id(i))
}

/// The zero hash is permitted only as genesis predecessor, empty audit head,
/// or an explicitly typed absence sentinel.
pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Reserved autonomous principal; never enrolled, never authenticates.
pub const WATCHD_PRINCIPAL: &str = "watchd";
