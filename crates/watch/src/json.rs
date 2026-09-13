//! Strict JSON admission plus RFC 8785 canonicalization (`J(x)`).
//!
//! Stage one (`parse`) enforces document syntax, duplicate members, trailing
//! bytes, and the structural bounds (depth/members/array/bytes). Stage two is
//! schema validation, which additionally enforces the protocol number profile:
//! nonnegative safe integers in ordinary decimal notation.

/// JSON value. `Num` keeps the raw lexeme; the integer profile is checked by
/// schema validators, never silently coerced.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// Raw number lexeme as it appeared on the wire.
    Num(String),
    Str(String),
    Arr(Vec<Value>),
    /// Members in document order; duplicates were rejected at parse.
    Obj(Vec<(String, Value)>),
}

impl Value {
    pub fn str(s: &str) -> Value {
        Value::Str(s.to_string())
    }
    pub fn string(s: String) -> Value {
        Value::Str(s)
    }
    pub fn num(n: u64) -> Value {
        Value::Num(n.to_string())
    }
    pub fn ustr(n: &str) -> Value {
        Value::Str(n.to_string())
    }
    /// Integer value if the lexeme satisfies the protocol number profile:
    /// `0` or `[1-9][0-9]*`, bounded by the JSON safe-integer limit.
    pub fn as_int(&self) -> Option<u64> {
        match self {
            Value::Num(raw) => int_profile(raw),
            _ => None,
        }
    }
    /// Integer value if the lexeme is an integer profile token bounded by the
    /// U counter limit (2^63-1).
    pub fn as_u(&self) -> Option<u64> {
        self.as_int().filter(|v| *v <= crate::U_MAX)
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_arr(&self) -> Option<&[Value]> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_obj(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Obj(o) => Some(o),
            _ => None,
        }
    }
    /// Look up a member of an object value.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(o) => o.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn obj(pairs: Vec<(&str, Value)>) -> Value {
        Value::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
}

/// `0` or `[1-9][0-9]*` bounded by `safe_max`.
fn int_profile_bounded(raw: &str, safe_max: u64) -> Option<u64> {
    let b = raw.as_bytes();
    if b.is_empty() {
        return None;
    }
    if b[0] == b'0' {
        if b.len() != 1 {
            return None;
        }
        return Some(0);
    }
    if !b[0].is_ascii_digit() {
        return None;
    }
    for c in b {
        if !c.is_ascii_digit() {
            return None;
        }
    }
    let v: u64 = raw.parse().ok()?;
    if v > safe_max {
        None
    } else {
        Some(v)
    }
}

/// Protocol number profile: nonnegative safe integer in ordinary decimal
/// notation (no fraction, exponent, sign, or leading zeros).
pub fn int_profile(raw: &str) -> Option<u64> {
    int_profile_bounded(raw, crate::SAFE_INT_MAX)
}

/// U counter profile: canonical decimal bounded by 2^63-1.
pub fn u_profile(raw: &str) -> Option<u64> {
    match raw.as_bytes() {
        b"0" => Some(0),
        _ => int_profile_bounded(raw, crate::U_MAX),
    }
}

/// Checked U decimal-string parser (for `Value::Str` counters).
pub fn u_str(s: &str) -> Option<u64> {
    int_profile_bounded(s, crate::U_MAX)
}

/// Canonical decimal string for a U value.
pub fn u_to_string(v: u64) -> String {
    v.to_string()
}

/// Parser error classes mapped onto wire codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErr {
    /// Malformed JSON syntax or duplicate member → BAD_JSON.
    Syntax,
    /// Structural bound violation (depth/members/array/bytes) → SCHEMA_INVALID.
    Bound,
}

impl ParseErr {
    pub fn code(&self) -> crate::fault::Code {
        match self {
            ParseErr::Syntax => crate::fault::Code::BadJson,
            ParseErr::Bound => crate::fault::Code::SchemaInvalid,
        }
    }
}

pub struct Limits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_members: usize,
    pub max_array: usize,
}

impl Limits {
    pub fn request() -> Limits {
        Limits {
            max_bytes: crate::REQ_MAX,
            max_depth: crate::DEPTH_MAX,
            max_members: crate::MEMBERS_MAX,
            max_array: crate::ARRAY_MAX,
        }
    }
    pub fn reply() -> Limits {
        Limits {
            max_bytes: crate::REPLY_MAX,
            max_depth: crate::DEPTH_MAX,
            max_members: crate::MEMBERS_MAX,
            max_array: crate::ARRAY_MAX,
        }
    }
    pub fn bundle() -> Limits {
        Limits {
            max_bytes: crate::BUNDLE_PARSE_MAX,
            max_depth: crate::DEPTH_MAX,
            max_members: crate::MEMBERS_MAX,
            max_array: crate::ARRAY_MAX,
        }
    }
}

/// Parse a UTF-8 JSON document under the strict admission profile.
/// Rejects BOM, duplicate members, invalid scalars, and trailing bytes.
pub fn parse(bytes: &[u8], lim: &Limits) -> Result<Value, ParseErr> {
    if bytes.len() > lim.max_bytes || bytes.is_empty() {
        return Err(ParseErr::Bound);
    }
    let s = std::str::from_utf8(bytes).map_err(|_| ParseErr::Syntax)?;
    if s.starts_with('\u{feff}') {
        return Err(ParseErr::Syntax);
    }
    let mut p = Parser {
        s: s.as_bytes(),
        pos: 0,
        lim,
    };
    let v = p.value(0)?;
    p.ws();
    if p.pos != p.s.len() {
        return Err(ParseErr::Syntax);
    }
    Ok(v)
}

/// Parse a `&str` document (already UTF-8).
pub fn parse_str(s: &str, lim: &Limits) -> Result<Value, ParseErr> {
    parse(s.as_bytes(), lim)
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
    lim: &'a Limits,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.pos < self.s.len() {
            match self.s[self.pos] {
                b' ' | b'\t' | b'\n' | b'\r' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseErr> {
        if depth > self.lim.max_depth {
            return Err(ParseErr::Bound);
        }
        self.ws();
        match self.peek().ok_or(ParseErr::Syntax)? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => Ok(Value::Str(self.string()?)),
            b't' => self.lit("true", Value::Bool(true)),
            b'f' => self.lit("false", Value::Bool(false)),
            b'n' => self.lit("null", Value::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(ParseErr::Syntax),
        }
    }

    fn lit(&mut self, lit: &str, v: Value) -> Result<Value, ParseErr> {
        if self.s[self.pos..].starts_with(lit.as_bytes()) {
            self.pos += lit.len();
            Ok(v)
        } else {
            Err(ParseErr::Syntax)
        }
    }

    fn number(&mut self) -> Result<Value, ParseErr> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek().ok_or(ParseErr::Syntax)? {
            b'0' => {
                self.pos += 1;
            }
            b'1'..=b'9' => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(ParseErr::Syntax),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(ParseErr::Syntax);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(ParseErr::Syntax);
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let raw = std::str::from_utf8(&self.s[start..self.pos]).map_err(|_| ParseErr::Syntax)?;
        Ok(Value::Num(raw.to_string()))
    }

    fn string(&mut self) -> Result<String, ParseErr> {
        debug_assert_eq!(self.peek(), Some(b'"'));
        self.pos += 1;
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or(ParseErr::Syntax)?;
            self.pos += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.peek().ok_or(ParseErr::Syntax)?;
                    self.pos += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let cp = self.hex4()?;
                            if (0xD800..=0xDBFF).contains(&cp) {
                                if self.peek() != Some(b'\\') {
                                    return Err(ParseErr::Syntax);
                                }
                                self.pos += 1;
                                if self.peek() != Some(b'u') {
                                    return Err(ParseErr::Syntax);
                                }
                                self.pos += 1;
                                let lo = self.hex4()?;
                                if !(0xDC00..=0xDFFF).contains(&lo) {
                                    return Err(ParseErr::Syntax);
                                }
                                let c =
                                    0x10000 + (((cp - 0xD800) as u32) << 10) + (lo as u32 - 0xDC00);
                                out.push(char::from_u32(c).ok_or(ParseErr::Syntax)?);
                            } else if (0xDC00..=0xDFFF).contains(&cp) {
                                return Err(ParseErr::Syntax);
                            } else {
                                out.push(char::from_u32(cp as u32).ok_or(ParseErr::Syntax)?);
                            }
                        }
                        _ => return Err(ParseErr::Syntax),
                    }
                }
                0x00..=0x1F => return Err(ParseErr::Syntax),
                _ => {
                    // Multi-byte UTF-8 consumed byte-wise; input was validated
                    // as UTF-8 up front so byte slicing stays on boundaries for
                    // ASCII and lead bytes carry their continuation.
                    let len = utf8_len(c);
                    if len > 1 {
                        let start = self.pos - 1;
                        let end = start + len;
                        if end > self.s.len() {
                            return Err(ParseErr::Syntax);
                        }
                        let chunk = std::str::from_utf8(&self.s[start..end])
                            .map_err(|_| ParseErr::Syntax)?;
                        out.push_str(chunk);
                        self.pos = end;
                    } else {
                        out.push(c as char);
                    }
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u16, ParseErr> {
        let mut v: u16 = 0;
        for _ in 0..4 {
            let c = self.peek().ok_or(ParseErr::Syntax)?;
            self.pos += 1;
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return Err(ParseErr::Syntax),
            };
            v = (v << 4) | d as u16;
        }
        Ok(v)
    }

    fn object(&mut self, depth: usize) -> Result<Value, ParseErr> {
        debug_assert_eq!(self.peek(), Some(b'{'));
        self.pos += 1;
        let mut members: Vec<(String, Value)> = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Obj(members));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(ParseErr::Syntax);
            }
            let key = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err(ParseErr::Syntax);
            }
            self.pos += 1;
            let v = self.value(depth + 1)?;
            if members.iter().any(|(k, _)| *k == key) {
                return Err(ParseErr::Syntax); // duplicate member
            }
            members.push((key, v));
            if members.len() > self.lim.max_members {
                return Err(ParseErr::Bound);
            }
            self.ws();
            match self.peek().ok_or(ParseErr::Syntax)? {
                b',' => {
                    self.pos += 1;
                }
                b'}' => {
                    self.pos += 1;
                    return Ok(Value::Obj(members));
                }
                _ => return Err(ParseErr::Syntax),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ParseErr> {
        debug_assert_eq!(self.peek(), Some(b'['));
        self.pos += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Arr(items));
        }
        loop {
            let v = self.value(depth + 1)?;
            items.push(v);
            if items.len() > self.lim.max_array {
                return Err(ParseErr::Bound);
            }
            self.ws();
            match self.peek().ok_or(ParseErr::Syntax)? {
                b',' => {
                    self.pos += 1;
                }
                b']' => {
                    self.pos += 1;
                    return Ok(Value::Arr(items));
                }
                _ => return Err(ParseErr::Syntax),
            }
        }
    }
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >= 0xF0 {
        4
    } else if b >= 0xE0 {
        3
    } else if b >= 0xC0 {
        2
    } else {
        1
    }
}

/// Escape a string per RFC 8785.
fn escape_into(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000a}' => out.push_str("\\n"),
            '\u{000c}' => out.push_str("\\f"),
            '\u{000d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

/// UTF-16 code-unit ordering for object keys (RFC 8785).
fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Serialize a value to canonical RFC 8785 form. Number lexemes are emitted
/// verbatim; only schema-validated integer-profile values may be signed or
/// hashed, so a non-canonical number never reaches a commitment.
pub fn jcs(v: &Value) -> String {
    let mut out = String::new();
    jcs_into(v, &mut out);
    out
}

fn jcs_into(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Num(raw) => out.push_str(raw),
        Value::Str(s) => {
            out.push('"');
            escape_into(out, s);
            out.push('"');
        }
        Value::Arr(items) => {
            out.push('[');
            for (i, it) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_into(it, out);
            }
            out.push(']');
        }
        Value::Obj(members) => {
            let mut sorted: Vec<&(String, Value)> = members.iter().collect();
            sorted.sort_by(|a, b| utf16_cmp(&a.0, &b.0));
            out.push('{');
            for (i, (k, val)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push('"');
                escape_into(out, k);
                out.push_str("\":");
                jcs_into(val, out);
            }
            out.push('}');
        }
    }
}

/// Member lookup on an object member slice.
pub fn mget<'a>(m: &'a [(String, Value)], k: &str) -> Option<&'a Value> {
    m.iter().find(|(k2, _)| k2 == k).map(|(_, v)| v)
}
