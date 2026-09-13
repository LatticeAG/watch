//! TV-W conformance vectors (spec §11): every row is executed against the
//! real daemon/store/monitors — no mocks.

use watch::conform::{fixture, matches, resolve, run_vector};
use watch::json::{jcs, parse, Limits, Value};

const VECTORS: &str = include_str!("../src/bin/vectors.json");

#[test]
fn all_tv_w_vectors() {
    let arr = parse(VECTORS.as_bytes(), &Limits::reply()).unwrap();
    let rows = arr.as_arr().unwrap();
    let mut fails = Vec::new();
    for v in rows {
        let m = v.as_obj().unwrap();
        let id = m
            .iter()
            .find(|(k, _)| k == "id")
            .unwrap()
            .1
            .as_str()
            .unwrap()
            .to_string();
        let input = resolve(
            m.iter()
                .find(|(k, _)| k == "input")
                .map(|(_, v)| v)
                .unwrap(),
        );
        let expected = resolve(
            m.iter()
                .find(|(k, _)| k == "expected")
                .map(|(_, v)| v)
                .unwrap(),
        );
        match std::panic::catch_unwind(|| run_vector(&input)) {
            Ok(actual) if matches(&expected, &actual) => {}
            Ok(actual) => fails.push(format!(
                "{id}: expected {} got {}",
                jcs(&expected),
                jcs(&actual)
            )),
            Err(_) => fails.push(format!("{id}: panic")),
        }
    }
    assert!(fails.is_empty(), "vector failures:\n{}", fails.join("\n"));
    assert_eq!(rows.len(), 72, "spec defines 72 TV-W vectors");
}

#[test]
fn fixtures_are_deterministic() {
    // The fixture environment must be reproducible: two resolutions equal.
    let a = fixture("O");
    let b = fixture("O");
    assert_eq!(jcs(&a), jcs(&b));
    assert!(matches(&fixture("CL.body"), &fixture("CL.body")));
    let _ = Value::Null;
}
