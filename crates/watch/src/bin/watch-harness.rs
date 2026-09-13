//! watch-harness — the TV-W conformance vector runner.

use watch::conform::{matches, resolve, run_vector};
use watch::json::{jcs, parse, Limits};

const VECTORS: &str = include_str!("vectors.json");

fn main() {
    let filter: Option<String> = std::env::args().nth(1);
    let arr = parse(VECTORS.as_bytes(), &Limits::reply()).unwrap();
    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut fails = vec![];
    for v in arr.as_arr().unwrap() {
        let m = v.as_obj().unwrap();
        let id = m
            .iter()
            .find(|(k, _)| k == "id")
            .unwrap()
            .1
            .as_str()
            .unwrap()
            .to_string();
        if let Some(f) = &filter {
            if !id.contains(f.as_str()) {
                continue;
            }
        }
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
        let actual = std::panic::catch_unwind(|| run_vector(&input));
        match actual {
            Ok(a) if matches(&expected, &a) => {
                pass += 1;
            }
            Ok(a) => {
                fail += 1;
                fails.push(format!("{id}: expected {} got {}", jcs(&expected), jcs(&a)));
            }
            Err(_) => {
                fail += 1;
                fails.push(format!("{id}: panic"));
            }
        }
    }
    for f in &fails {
        eprintln!("FAIL {f}");
    }
    println!("{{\"pass\":{pass},\"fail\":{fail}}}");
    std::process::exit(if fail == 0 { 0 } else { 1 });
}
