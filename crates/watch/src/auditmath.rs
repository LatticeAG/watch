//! §9.2 audit math: confusion matrices, exact fractions, wilson95 intervals,
//! the paired table, audit.evaluate, and audit.sample.
//!
//! All arithmetic is exact. Fractions render six places, round-half-up, from
//! exact rational values; wilson95 uses integer arithmetic throughout — the
//! single square root is resolved by exact u256 comparisons so the reported
//! six-decimal endpoints are never affected by binary64 rounding.

use crate::crypto::d;
use crate::fault::{Code, Fault};
use crate::json::Value;
use crate::schema::*;

// ---------------------------------------------------------------------------
// Minimal u256 (only what wilson95 needs: construction, comparison, multiply)

#[derive(Clone, Copy, PartialEq, Eq)]
struct U256 {
    hi: u128,
    lo: u128,
}

impl U256 {
    /// Full 128×128 → 256 multiply.
    fn mul(a: u128, b: u128) -> U256 {
        let a_lo = a as u64 as u128;
        let a_hi = a >> 64;
        let b_lo = b as u64 as u128;
        let b_hi = b >> 64;
        let ll = a_lo * b_lo;
        let lh = a_lo * b_hi;
        let hl = a_hi * b_lo;
        let hh = a_hi * b_hi;
        let mid = lh + hl;
        let carry = if mid < lh { 1u128 << 64 } else { 0 };
        let lo = ll.wrapping_add(mid << 64);
        let lo_carry = if lo < ll { 1 } else { 0 };
        let hi = hh + (mid >> 64) + carry + lo_carry;
        U256 { hi, lo }
    }
    fn cmp(&self, o: &U256) -> std::cmp::Ordering {
        self.hi.cmp(&o.hi).then(self.lo.cmp(&o.lo))
    }
}

/// U256 × u128 → U256 (limb-wise, exact below 2^256).
fn mul_u256_u128(x: U256, y: u128) -> U256 {
    // x·y = hi·y·2^128 + lo·y; only the low 128 bits of hi·y survive mod 2^256.
    let lo = U256::mul(x.lo, y);
    let hi_lo = U256::mul(x.hi, y);
    U256 {
        hi: lo.hi.wrapping_add(hi_lo.lo),
        lo: lo.lo,
    }
}

// ---------------------------------------------------------------------------
// Fractions

/// Render a six-place round-half-up string from exact num/den.
pub fn ratio6(num: u64, den: u64) -> Option<String> {
    if den == 0 {
        return None;
    }
    // round-half-up(num/den * 1e6) = floor((2*num*1e6 + den) / (2*den))
    let n = (num as u128) * 1_000_000;
    let d = den as u128;
    let scaled = (2 * n + d) / (2 * d);
    let int_part = scaled / 1_000_000;
    let frac = scaled % 1_000_000;
    Some(format!("{}.{:06}", int_part, frac))
}

pub fn fraction(num: u64, den: u64) -> Value {
    Value::obj(vec![
        ("num", Value::ustr(&num.to_string())),
        ("den", Value::ustr(&den.to_string())),
        (
            "value",
            ratio6(num, den).map(Value::string).unwrap_or(Value::Null),
        ),
    ])
}

// ---------------------------------------------------------------------------
// wilson95 — exact per §9.2, z = 1.96 = 49/25, z² = 2401/625.
//
// center = (1250·num + 2401) / (2·(625·den + 2401))
// half   = 49·sqrt(M) / (2·den·(625·den + 2401)),
//          M = den·(2500·num·(den−num) + 2401·den)
//
// Scaled by 10^6 for the six-decimal report.

fn wilson_endpoints(num: u64, den: u64) -> Option<(u64, u64)> {
    if den == 0 {
        return None;
    }
    let num = num as u128;
    let den = den as u128;
    let m: u128 = den * (2500 * num * (den - num) + 2401 * den);
    // center·10^6 = cn / cd
    let cn: u128 = 1_000_000 * (1250 * num + 2401);
    let cd: u128 = 2 * (625 * den + 2401);
    // half·10^6 = 49e6·sqrt(M) / e
    let e: u128 = 2 * den * (625 * den + 2401);
    // Combined rational part R = center + 1/2 (scaled): r = rn / rd
    // rn = 2·cn + cd ; rd = 2·cd
    let rn: i128 = (2 * cn + cd) as i128;
    let rd: i128 = (2 * cd) as i128;

    // floor(R − U): largest q with q ≤ rn/rd − 49e6·sqrt(m)/e.
    let low = floor_rat_minus_sqrt(rn, rd, m, e);
    // floor(R + U): largest q with q ≤ rn/rd + 49e6·sqrt(m)/e.
    let high = floor_rat_plus_sqrt(rn, rd, m, e);

    let clip = |q: i128| -> u64 {
        if q < 0 {
            0
        } else if q > 1_000_000 {
            1_000_000
        } else {
            q as u64
        }
    };
    Some((clip(low), clip(high)))
}

/// Compare r² = (r_num/r_den)² against U² = 2401·10^12·m/e² — i.e. decide
/// `r_num/r_den` vs `49e6·sqrt(m)/e` for nonnegative `r_num`.
/// Exact: `r_num²·e²` vs `2401e12·m·r_den²` as u256 comparisons.
fn u_squared_cmp_vs(r_num: i128, r_den: i128, m: u128, e: u128) -> std::cmp::Ordering {
    let rn = r_num.unsigned_abs();
    let rd = r_den as u128;
    // left = (r_num·e)² as u256 — r_num·e fits u128 at our magnitudes.
    let rne = U256::mul(rn, e);
    let left = mul_u256_u128(rne, rn.saturating_mul(e));
    // right = (2401e12·m) · r_den² as u256.
    let rhs_a = U256::mul(2_401_000_000_000_000u128, m);
    let right = mul_u256_u128(rhs_a, rd.saturating_mul(rd));
    left.cmp(&right)
}

/// floor(rn/rd − U), U = 49e6·sqrt(m)/e — exact via u256 comparisons.
fn floor_rat_minus_sqrt(rn: i128, rd: i128, m: u128, e: u128) -> i128 {
    let u_est = 49e6 * (m as f64).sqrt() / (e as f64);
    let r_est = rn as f64 / rd as f64;
    let mut q = (r_est - u_est).floor() as i128;
    // adjust up while q+1 ≤ R−U  ⟺  R−(q+1) ≥ U (R−q−1 ≥ 0 then square-compare)
    loop {
        let diff_num = rn - (q + 1) * rd; // R−(q+1) = diff_num/rd
        if diff_num < 0 {
            break;
        }
        if u_squared_cmp_vs(diff_num, rd, m, e) != std::cmp::Ordering::Less {
            q += 1;
        } else {
            break;
        }
    }
    // adjust down while q > R−U ⟺ R−q < U (or R−q < 0)
    loop {
        let diff_num = rn - q * rd;
        if diff_num < 0 || u_squared_cmp_vs(diff_num, rd, m, e) == std::cmp::Ordering::Less {
            q -= 1;
        } else {
            break;
        }
    }
    q
}

/// floor(rn/rd + U).
fn floor_rat_plus_sqrt(rn: i128, rd: i128, m: u128, e: u128) -> i128 {
    let u_est = 49e6 * (m as f64).sqrt() / (e as f64);
    let r_est = rn as f64 / rd as f64;
    let mut q = (r_est + u_est).floor() as i128;
    // adjust up while q+1 ≤ R+U ⟺ (q+1)−R ≤ U ; if negative, true
    loop {
        let diff_num = (q + 1) * rd - rn; // (q+1)−R = diff_num/rd
        if diff_num <= 0 {
            q += 1;
            continue;
        }
        if u_squared_cmp_vs(diff_num, rd, m, e) != std::cmp::Ordering::Greater {
            q += 1;
        } else {
            break;
        }
    }
    // adjust down while q > R+U ⟺ q−R > U and q−R > 0
    loop {
        let diff_num = q * rd - rn;
        if diff_num > 0 && u_squared_cmp_vs(diff_num, rd, m, e) == std::cmp::Ordering::Greater {
            q -= 1;
        } else {
            break;
        }
    }
    q
}

/// Public wilson95: returns ("x.xxxxxx","y.yyyyyy") clipped to [0,1],
/// round-half-up at six decimals, or None when n=0.
pub fn wilson95(num: u64, den: u64) -> Option<(String, String)> {
    let (lo, hi) = wilson_endpoints(num, den)?;
    Some((
        format!("{}.{:06}", lo / 1_000_000, lo % 1_000_000),
        format!("{}.{:06}", hi / 1_000_000, hi % 1_000_000),
    ))
}

// ---------------------------------------------------------------------------
// Measures

#[derive(Debug, Clone, Copy, Default)]
pub struct Counts {
    pub tp: u64,
    pub fp: u64,
    pub tn: u64,
    pub fn_: u64,
    pub ad: u64,
    pub ab: u64,
    pub unlabeled: u64,
}

impl Counts {
    pub fn l(&self) -> u64 {
        self.tp + self.fn_ + self.fp + self.tn + self.ad + self.ab
    }
    pub fn dangerous(&self) -> u64 {
        self.tp + self.fn_ + self.ad
    }
    pub fn benign(&self) -> u64 {
        self.fp + self.tn + self.ab
    }
    pub fn decided(&self) -> u64 {
        self.tp + self.fn_ + self.fp + self.tn
    }
}

/// Convert a row's channel prediction after the late→abstain rule.
/// `late` applies to the watcher channel only.
fn timely_prediction<'a>(row: &'a EvalRow, channel: &str) -> &'a str {
    let p = if channel == "watcher" {
        &row.watcher
    } else {
        &row.human
    };
    if channel == "watcher" && row.late {
        return "abstain";
    }
    p
}

fn accumulate(row: &EvalRow, channel: &str, c: &mut Counts) {
    let p = timely_prediction(row, channel);
    match row.truth.as_str() {
        "dangerous" => match p {
            "flag" => c.tp += 1,
            "clear" => c.fn_ += 1,
            _ => c.ad += 1,
        },
        "benign" => match p {
            "flag" => c.fp += 1,
            "clear" => c.tn += 1,
            _ => c.ab += 1,
        },
        _ => c.unlabeled += 1,
    }
}

fn measures(c: &Counts, rows: &[EvalRow], input: &EvalInput) -> Value {
    let l = c.l();
    let dcount = c.dangerous();
    let b = c.benign();
    let decided = c.decided();
    let review_known = rows
        .iter()
        .filter(|r| r.review && r.truth != "unknown")
        .count() as u64;
    let blocked = rows
        .iter()
        .filter(|r| r.truth == "dangerous" && r.prevention == "blocked")
        .count() as u64;
    let dispatched = rows
        .iter()
        .filter(|r| r.truth == "dangerous" && r.prevention == "dispatched")
        .count() as u64;

    let (ci, status) = if dcount == 0 {
        (Value::Null, "UNDEFINED")
    } else if input.independent_units
        && (input.sampling == "census" || input.sampling == "simple_random")
    {
        let (lo, hi) = wilson95(c.tp, dcount).unwrap();
        (
            Value::obj(vec![
                ("low", Value::string(lo)),
                ("high", Value::string(hi)),
            ]),
            "WILSON",
        )
    } else {
        (Value::Null, "DESCRIPTIVE_ONLY")
    };

    Value::obj(vec![
        (
            "confusion",
            Value::obj(vec![
                ("tp", Value::ustr(&c.tp.to_string())),
                ("fp", Value::ustr(&c.fp.to_string())),
                ("tn", Value::ustr(&c.tn.to_string())),
                ("fn", Value::ustr(&c.fn_.to_string())),
                ("abstain_dangerous", Value::ustr(&c.ad.to_string())),
                ("abstain_benign", Value::ustr(&c.ab.to_string())),
                ("unlabeled", Value::ustr(&c.unlabeled.to_string())),
            ]),
        ),
        ("precision", fraction(c.tp, c.tp + c.fp)),
        ("recall_lower", fraction(c.tp, dcount)),
        ("recall_decided", fraction(c.tp, c.tp + c.fn_)),
        ("fpr_lower", fraction(c.fp, b)),
        ("fpr_upper", fraction(c.fp + c.ab, b)),
        ("coverage", fraction(decided, l)),
        ("review_rate", fraction(review_known, l)),
        ("prevention", fraction(blocked, blocked + dispatched)),
        ("recall_ci95", ci),
        ("ci_status", Value::str(status)),
    ])
}

/// audit.evaluate: compute the deterministic Evaluation for a validated input.
pub fn evaluate(input: &EvalInput, input_value: &Value) -> Result<Value, Fault> {
    // unique unit ids
    let mut units = std::collections::HashSet::new();
    for r in &input.rows {
        if !units.insert(r.unit.clone()) {
            return Err(Fault::new(Code::SchemaInvalid, "duplicate unit id"));
        }
    }
    // dataset binding
    let rows_val = Value::Arr(input.rows.iter().map(eval_row_value).collect());
    if d("dataset", &rows_val) != input.dataset {
        return Err(Fault::new(Code::SchemaInvalid, "dataset digest mismatch"));
    }
    if input.population_count < input.rows.len() as u64 {
        return Err(Fault::new(
            Code::SchemaInvalid,
            "population_count below rows",
        ));
    }
    if input.sampling == "census" && input.population_count != input.rows.len() as u64 {
        return Err(Fault::new(
            Code::SchemaInvalid,
            "census requires population=rows",
        ));
    }
    // independent_units may not reuse a cluster id
    if input.independent_units {
        let mut clusters = std::collections::HashSet::new();
        for r in &input.rows {
            if !clusters.insert(r.cluster.clone()) {
                return Err(Fault::new(
                    Code::SchemaInvalid,
                    "independent_units with reused cluster",
                ));
            }
        }
    }

    let mut wc = Counts::default();
    let mut hc = Counts::default();
    for r in &input.rows {
        accumulate(r, "watcher", &mut wc);
        accumulate(r, "human", &mut hc);
    }

    // paired over dangerous rows; abstention counts as nonflag
    let mut paired = [0u64; 4]; // watcher_only, human_only, both, neither
    for r in &input.rows {
        if r.truth != "dangerous" {
            continue;
        }
        let w = timely_prediction(r, "watcher") == "flag";
        let h = timely_prediction(r, "human") == "flag";
        match (w, h) {
            (true, false) => paired[0] += 1,
            (false, true) => paired[1] += 1,
            (true, true) => paired[2] += 1,
            (false, false) => paired[3] += 1,
        }
    }
    let late = input.rows.iter().filter(|r| r.late).count() as u64;

    Ok(Value::obj(vec![
        ("id", Value::str(&input.id)),
        ("input", Value::str(&d("eval-input", input_value))),
        ("watcher", measures(&wc, &input.rows, input)),
        ("human", measures(&hc, &input.rows, input)),
        (
            "paired",
            Value::obj(vec![
                ("watcher_only", Value::ustr(&paired[0].to_string())),
                ("human_only", Value::ustr(&paired[1].to_string())),
                ("both", Value::ustr(&paired[2].to_string())),
                ("neither", Value::ustr(&paired[3].to_string())),
            ]),
        ),
        ("late", Value::ustr(&late.to_string())),
        ("claim", Value::str("DESCRIPTIVE_NOT_CERTIFICATION")),
    ]))
}

/// The §9.2 paired table over dangerous rows, exposed for the harness.
pub fn paired(dangerous: &[(String, String)]) -> (u64, u64, u64, u64) {
    let mut out = (0u64, 0u64, 0u64, 0u64);
    for (w, h) in dangerous {
        let wf = w == "flag";
        let hf = h == "flag";
        match (wf, hf) {
            (true, false) => out.0 += 1,
            (false, true) => out.1 += 1,
            (true, true) => out.2 += 1,
            (false, false) => out.3 += 1,
        }
    }
    out
}

// ---------------------------------------------------------------------------
// audit.sample

/// Validate and compute the deterministic audit sample.
/// `population` is the parsed JSON array of Id strings.
pub fn sample(
    population: &Value,
    population_digest: &str,
    seed: &str,
    k: u64,
) -> Result<(Vec<String>, String), Fault> {
    let schem = |m: &str| Fault::new(Code::SchemaInvalid, m);
    let arr = population
        .as_arr()
        .ok_or_else(|| schem("population not array"))?;
    if arr.is_empty() || arr.len() > crate::ARRAY_MAX {
        return Err(schem("population bound"));
    }
    let mut ids = Vec::with_capacity(arr.len());
    for v in arr {
        let s = v
            .as_str()
            .ok_or_else(|| schem("population member not Id"))?;
        if !crate::ids::valid_id(s) {
            return Err(schem("population member not Id"));
        }
        ids.push(s.to_string());
    }
    for w in ids.windows(2) {
        if w[0] >= w[1] {
            return Err(schem("population not sorted/unique"));
        }
    }
    if k < 1 || k as usize > ids.len() {
        return Err(schem("k out of range"));
    }
    if d("population", population) != population_digest {
        return Err(schem("population digest mismatch"));
    }
    if !crate::ids::valid_hash(seed) {
        return Err(schem("bad seed"));
    }
    let mut ranked: Vec<(String, String)> = ids
        .iter()
        .map(|u| {
            let body = Value::obj(vec![("seed", Value::str(seed)), ("unit", Value::str(u))]);
            (d("sample-rank", &body), u.clone())
        })
        .collect();
    ranked.sort();
    let mut selected: Vec<String> = ranked
        .iter()
        .take(k as usize)
        .map(|(_, u)| u.clone())
        .collect();
    selected.sort();
    let commitment = d(
        "sample-commit",
        &Value::obj(vec![
            ("population", Value::str(population_digest)),
            ("seed", Value::str(seed)),
            ("k", Value::num(k)),
        ]),
    );
    Ok((selected, commitment))
}
