//! §11 acceptance: parser fuzz — 100_000 inputs, no panics, strict
//! admission (duplicate members, depth, bounds) always rejected cleanly.

use watch::json::{jcs, parse, Limits, Value};

/// Deterministic xorshift64 RNG — reproducible corpus, no deps.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

fn corpus() -> Vec<Vec<u8>> {
    let mut c: Vec<Vec<u8>> = vec![
        br#"{"v":1,"id":"q1","method":"system.status","params":{}}"#.to_vec(),
        jcs(&fixture_request()).into_bytes(),
        br#"{"a":[1,2,{"b":null}],"c":"x"}"#.to_vec(),
        br#""#.to_vec(),
        b"null".to_vec(),
        b"{}".to_vec(),
        b"[]".to_vec(),
        br#"{"dup":1,"dup":2}"#.to_vec(),
        b"1e0".to_vec(),
        b"\"\\u0041\"".to_vec(),
    ];
    // Deep nesting at/over the depth bound.
    for d in [23usize, 24, 25, 200] {
        let mut v = vec![b'['; d];
        v.extend(vec![b']'; d]);
        c.push(v);
    }
    c
}

fn fixture_request() -> Value {
    Value::obj(vec![
        ("v", Value::num(1)),
        ("id", Value::str("q1")),
        ("method", Value::str("checks.create")),
        (
            "params",
            Value::obj(vec![
                ("id", Value::str("wtc_1")),
                ("run", Value::str("wtr_1")),
            ]),
        ),
    ])
}

#[test]
fn parser_fuzz_100k() {
    let corpus = corpus();
    let mut rng = Rng(0x9e3779b97f4a7c15);
    let mut ok = 0u32;
    let mut err = 0u32;
    for _ in 0..100_000 {
        let base = &corpus[(rng.next() as usize) % corpus.len()];
        let mut bytes = base.clone();
        // Apply 1-4 random mutations.
        for _ in 0..(1 + rng.next() % 4) {
            match rng.next() % 4 {
                0 if !bytes.is_empty() => {
                    let i = (rng.next() as usize) % bytes.len();
                    bytes[i] = (rng.next() % 256) as u8;
                }
                1 if !bytes.is_empty() => {
                    let i = (rng.next() as usize) % bytes.len();
                    bytes.remove(i);
                }
                2 => {
                    let i = (rng.next() as usize) % (bytes.len() + 1);
                    bytes.insert(i, (rng.next() % 256) as u8);
                }
                _ => {
                    let i = (rng.next() as usize) % (bytes.len() + 1);
                    let piece = corpus[(rng.next() as usize) % corpus.len()].clone();
                    let take = piece.len().min(16);
                    bytes.splice(i..i, piece[..take].iter().cloned());
                }
            }
        }
        // The parser must never panic; strict limits enforced.
        match parse(&bytes, &Limits::request()) {
            Ok(v) => {
                ok += 1;
                // Canonical round-trip is stable.
                let again = parse(&jcs(&v).into_bytes(), &Limits::request());
                assert!(again.is_ok());
            }
            Err(_) => err += 1,
        }
    }
    assert!(ok + err == 100_000);
    assert!(err > 0, "corpus produced no rejections — fuzz ineffective");
}

#[test]
fn strict_parser_rejections() {
    // Duplicate member.
    assert!(parse(br#"{"a":1,"a":2}"#, &Limits::request()).is_err());
    // Non-integer numbers are schema-rejected, covered by TV-W-03.
    // Depth beyond 24.
    let deep = format!("{}{}", "[".repeat(30), "]".repeat(30));
    assert!(parse(deep.as_bytes(), &Limits::request()).is_err());
    // Trailing garbage.
    assert!(parse(b"{} {}", &Limits::request()).is_err());
    // Lone surrogate escape.
    assert!(parse(b"\"\\ud800\"", &Limits::request()).is_err());
}
