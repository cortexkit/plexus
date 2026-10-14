//! Strict RFC 8785 JSON Canonicalization Scheme (JCS).
//!
//! Used for every canonical JSON hash, including catalog schemas, stored
//! payloads, approval arguments, and parity with the external decision plane.
//!
//! RFC 8785 writes every number through an IEEE-754 double, which holds
//! integers exactly only up to 2^53. Past that, distinct integers collapse:
//! 2^53 + 1 canonicalizes to the same bytes, and so the same hash, as 2^53.
//! That is the standard, and parity with every other JCS verifier (the
//! decision plane's grant hash among them) depends on keeping it. So a JCS hash is NOT an
//! integer-exact identity, and nothing may treat two equal hashes as proof of
//! equal arguments: approvals and reservations compare the argument values
//! themselves. An identity that must keep every integer apart and is computed
//! only by plexus uses [`canonicalize_exact_integers`] instead.

use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

/// Errors raised while producing a JCS byte string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JcsError {
    /// JSON numbers must be finite IEEE-754 values; NaN and ±Infinity are rejected.
    NonFiniteNumber,
}

impl std::fmt::Display for JcsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonFiniteNumber => {
                formatter.write_str("non-finite JSON number is not permitted by JCS")
            }
        }
    }
}

impl std::error::Error for JcsError {}

/// How integers beyond the exact range of a double are written.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Integers {
    /// Through the double, as RFC 8785 requires.
    Rfc8785,
    /// Verbatim, so distinct integers never share bytes.
    Exact,
}

/// The largest magnitude up to which every integer has an exact double.
const EXACT_DOUBLE_LIMIT: u64 = 1 << 53;

/// Canonicalize `value` to RFC 8785 JCS bytes (no whitespace).
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, JcsError> {
    let mut out = Vec::with_capacity(64);
    write_value(&mut out, value, Integers::Rfc8785)?;
    Ok(out)
}

/// Canonicalize like [`canonicalize`], but write integers whose magnitude exceeds
/// 2^53 as exact decimal digits rather than rounding through a double. Match
/// RFC 8785 byte for byte for integers up to 2^53 and for non-integers. Derived
/// keys differ only where RFC 8785 would merge distinct integers.
///
/// Use this for identities that only plexus computes, such as the keys that
/// distinguish stored events and suppress duplicate deliveries. Distinct items
/// must not share an identity because integer rounding merged their values.
/// Use [`canonicalize`] instead for hashes another party verifies under RFC 8785.
pub fn canonicalize_exact_integers(value: &Value) -> Result<Vec<u8>, JcsError> {
    let mut out = Vec::with_capacity(64);
    write_value(&mut out, value, Integers::Exact)?;
    Ok(out)
}

/// SHA-256 of the JCS bytes, formatted as `sha256:<hex>`.
pub fn jcs_sha256(value: &Value) -> Result<String, JcsError> {
    #[cfg(test)]
    if test_seam::should_fail() {
        return Err(JcsError::NonFiniteNumber);
    }

    let bytes = canonicalize(value)?;
    let digest = Sha256::digest(&bytes);
    Ok(format!("sha256:{digest:x}"))
}

#[cfg(test)]
pub(crate) fn with_sha256_failure_on_call<T>(call: usize, operation: impl FnOnce() -> T) -> T {
    test_seam::with_failure_on_call(call, operation)
}

#[cfg(test)]
mod test_seam {
    use std::cell::Cell;

    // Keep injected failures on the calling test thread so parallel tests cannot
    // turn an unrelated production path into a refusal.
    thread_local! {
        static FAILURE_ON_CALL: Cell<Option<usize>> = const { Cell::new(None) };
    }

    pub(super) fn should_fail() -> bool {
        FAILURE_ON_CALL.with(|failure| match failure.get() {
            Some(0) => {
                failure.set(None);
                true
            }
            Some(remaining) => {
                failure.set(Some(remaining - 1));
                false
            }
            None => false,
        })
    }

    pub(super) fn with_failure_on_call<T>(call: usize, operation: impl FnOnce() -> T) -> T {
        struct Reset(Option<usize>);

        impl Drop for Reset {
            fn drop(&mut self) {
                FAILURE_ON_CALL.with(|failure| failure.set(self.0));
            }
        }

        let previous = FAILURE_ON_CALL.with(|failure| failure.replace(Some(call)));
        let _reset = Reset(previous);
        operation()
    }
}

fn write_value(out: &mut Vec<u8>, value: &Value, integers: Integers) -> Result<(), JcsError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => write_number(out, number, integers)?,
        Value::String(text) => write_string(out, text)?,
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_value(out, item, integers)?;
            }
            out.push(b']');
        }
        Value::Object(object) => write_object(out, object, integers)?,
    }
    Ok(())
}

fn write_object(
    out: &mut Vec<u8>,
    object: &Map<String, Value>,
    integers: Integers,
) -> Result<(), JcsError> {
    let mut entries = object.iter().collect::<Vec<_>>();
    entries.sort_by(|(left, _), (right, _)| left.encode_utf16().cmp(right.encode_utf16()));
    out.push(b'{');
    for (index, (key, value)) in entries.into_iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        write_string(out, key)?;
        out.push(b':');
        write_value(out, value, integers)?;
    }
    out.push(b'}');
    Ok(())
}

fn write_number(out: &mut Vec<u8>, number: &Number, integers: Integers) -> Result<(), JcsError> {
    if integers == Integers::Exact {
        let beyond_exact = number
            .as_i64()
            .map(|integer| integer.unsigned_abs() > EXACT_DOUBLE_LIMIT)
            .or_else(|| number.as_u64().map(|integer| integer > EXACT_DOUBLE_LIMIT))
            .unwrap_or(false);
        if beyond_exact {
            out.extend_from_slice(number.to_string().as_bytes());
            return Ok(());
        }
    }
    // serde_json may retain integers; JCS still serializes through the ES double path.
    let Some(float) = number.as_f64() else {
        return Err(JcsError::NonFiniteNumber);
    };
    if !float.is_finite() {
        return Err(JcsError::NonFiniteNumber);
    }
    let mut buffer = ryu_js::Buffer::new();
    out.extend_from_slice(buffer.format_finite(float).as_bytes());
    Ok(())
}

fn write_string(out: &mut Vec<u8>, text: &str) -> Result<(), JcsError> {
    out.push(b'"');
    for ch in text.chars() {
        match ch {
            '"' => out.extend_from_slice(br#"\""#),
            '\\' => out.extend_from_slice(br#"\\"#),
            '\u{0008}' => out.extend_from_slice(br#"\b"#),
            '\u{0009}' => out.extend_from_slice(br#"\t"#),
            '\u{000A}' => out.extend_from_slice(br#"\n"#),
            '\u{000C}' => out.extend_from_slice(br#"\f"#),
            '\u{000D}' => out.extend_from_slice(br#"\r"#),
            c if (c as u32) <= 0x1F => {
                let code = c as u32;
                out.extend_from_slice(format!("\\u{code:04x}").as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "manual canonical key-sort measurement"]
    fn measure_key_sort() {
        let keys: Vec<String> = (0..256)
            .map(|n| format!("key-{n:03}-\u{1f600}"))
            .rev()
            .collect();
        let start = std::time::Instant::now();
        let mut allocated = 0;
        for _ in 0..2_000 {
            let mut entries: Vec<_> = keys.iter().collect();
            entries.sort_by_key(|key| {
                allocated += 1;
                key.encode_utf16().collect::<Vec<_>>()
            });
            std::hint::black_box(entries);
        }
        println!(
            "allocated comparator: {:?}, {allocated} Vec allocations",
            start.elapsed()
        );
        let start = std::time::Instant::now();
        for _ in 0..2_000 {
            let mut entries: Vec<_> = keys.iter().collect();
            entries.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            std::hint::black_box(entries);
        }
        println!(
            "iterator comparator: {:?}, 0 comparator allocations",
            start.elapsed()
        );
    }

    #[test]
    fn rfc_8785_appendix_b_number_vectors() {
        for (bits, expected) in [
            (0x0000000000000000, "0"),
            (0x8000000000000000, "0"),
            (0x0000000000000001, "5e-324"),
            (0x8000000000000001, "-5e-324"),
            (0x7fefffffffffffff, "1.7976931348623157e+308"),
            (0xffefffffffffffff, "-1.7976931348623157e+308"),
            (0x4340000000000000, "9007199254740992"),
            (0xc340000000000000, "-9007199254740992"),
            (0x4430000000000000, "295147905179352830000"),
            (0x44b52d02c7e14af5, "9.999999999999997e+22"),
            (0x44b52d02c7e14af6, "1e+23"),
            (0x44b52d02c7e14af7, "1.0000000000000001e+23"),
            (0x444b1ae4d6e2ef4e, "999999999999999700000"),
            (0x444b1ae4d6e2ef4f, "999999999999999900000"),
            (0x444b1ae4d6e2ef50, "1e+21"),
            (0x3eb0c6f7a0b5ed8c, "9.999999999999997e-7"),
            (0x3eb0c6f7a0b5ed8d, "0.000001"),
            (0x41b3de4355555553, "333333333.3333332"),
            (0x41b3de4355555554, "333333333.33333325"),
            (0x41b3de4355555555, "333333333.3333333"),
            (0x41b3de4355555556, "333333333.3333334"),
            (0x41b3de4355555557, "333333333.33333343"),
            (0xbecbf647612f3696, "-0.0000033333333333333333"),
        ] {
            let value = Value::Number(Number::from_f64(f64::from_bits(bits)).unwrap());
            assert_eq!(
                canonicalize(&value).unwrap(),
                expected.as_bytes(),
                "RFC 8785 Appendix B {bits:016x}"
            );
        }
        for bits in [0x7fffffffffffffff, 0x7ff0000000000000, 0xfff0000000000000] {
            assert!(
                Number::from_f64(f64::from_bits(bits)).is_none(),
                "nonfinite inputs cannot enter JSON"
            );
        }
    }

    #[test]
    fn rfc_8785_section_3_sample_object() {
        let value: Value = serde_json::from_str(r#"{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\nA'B\"\\\\\"/","literals":[null,true,false]}"#).unwrap();
        assert_eq!(
            String::from_utf8(canonicalize(&value).unwrap()).unwrap(),
            r#"{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}"#,
            "RFC 8785 section 3 worked object must match byte-for-byte"
        );
    }

    use super::*;
    use serde_json::json;

    #[test]
    fn finite_numbers_serialize() {
        let bytes = canonicalize(&json!(0.0)).expect("zero");
        assert_eq!(bytes, b"0");
        // serde_json refuses to construct non-finite Number values, so the
        // NonFiniteNumber arm is covered by the write_number guard on as_f64.
        let _ = Number::from(1);
    }

    #[test]
    fn object_keys_sort_lexicographically() {
        let value = json!({"b": 1, "a": 2});
        let bytes = canonicalize(&value).expect("jcs");
        assert_eq!(bytes, br#"{"a":2,"b":1}"#);
    }

    /// Keys sort by UTF-16 CODE UNIT, which is not the same as Rust's default
    /// string order, and the difference is invisible on ASCII.
    ///
    /// RFC 8785 orders keys by UTF-16 code unit. Rust's `str` ordering is by
    /// Unicode scalar value. The two agree on everything below U+FFFF and
    /// disagree above it: U+1F600 encodes as the surrogate pair 0xD83D 0xDE00,
    /// and 0xD83D sorts BELOW 0xE000, while the scalar 0x1F600 sorts ABOVE it.
    /// So a canonicalizer using the natural sort emits a different byte string
    /// for the same object, and every ASCII test still passes.
    ///
    /// This is not hypothetical: `serde_jcs` 0.1.0 fails exactly this ordering
    /// against the RFC's own worked example. Had this crate reached for that
    /// dependency instead of sorting by `encode_utf16`, the grant-hash path
    /// would disagree with every other conforming verifier on any object
    /// carrying an astral-plane key.
    ///
    /// Asserted as BYTES rather than as a sort-key comparison, because the
    /// property that matters is what goes on the wire.
    #[test]
    fn keys_sort_by_utf16_code_unit_not_by_scalar_value() {
        let value = json!({"\u{E000}": 1, "\u{1F600}": 2});
        let bytes = canonicalize(&value).expect("jcs");

        let emoji_at = bytes
            .windows(4)
            .position(|w| w == "\u{1F600}".as_bytes())
            .expect("the astral key must appear");
        let pua_at = bytes
            .windows(3)
            .position(|w| w == "\u{E000}".as_bytes())
            .expect("the private-use key must appear");

        assert!(
            emoji_at < pua_at,
            "U+1F600 must precede U+E000 under UTF-16 ordering; scalar-value \
             ordering would reverse them. bytes={}",
            String::from_utf8_lossy(&bytes)
        );
    }

    #[test]
    fn hash_prefix_is_stable() {
        let hash = jcs_sha256(&json!({"team":"core"})).expect("hash");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), "sha256:".len() + 64);
    }

    /// RFC 8785 rounds integers past 2^53 through a double. Keep that behavior
    /// in `canonicalize` so grant-hash verifiers following RFC 8785 compute the
    /// same bytes. Check the rounding explicitly so callers do not mistake an
    /// RFC-compatible hash for an identity that preserves every integer.
    #[test]
    fn rfc_canonicalization_collapses_integers_past_2_pow_53() {
        let two_pow_53: u64 = 1 << 53;
        assert_eq!(
            canonicalize(&json!(two_pow_53 + 1)).unwrap(),
            canonicalize(&json!(two_pow_53)).unwrap(),
            "RFC 8785 writes 2^53 + 1 through a double, as 2^53"
        );
        assert_eq!(
            canonicalize(&json!(1u64 << 60)).unwrap(),
            b"1152921504606847000"
        );
    }

    /// The exact canonicalizer keeps every integer apart, and is byte-identical
    /// to RFC 8785 wherever RFC 8785 is itself exact: every integer up to 2^53
    /// in magnitude and every non-integer.
    #[test]
    fn exact_canonicalization_keeps_large_integers_apart_and_matches_rfc_elsewhere() {
        let two_pow_53: u64 = 1 << 53;
        assert_ne!(
            canonicalize_exact_integers(&json!({"id": two_pow_53 + 1})).unwrap(),
            canonicalize_exact_integers(&json!({"id": two_pow_53})).unwrap(),
            "distinct integers past 2^53 must not share bytes"
        );
        assert_eq!(
            canonicalize_exact_integers(&json!(two_pow_53 + 1)).unwrap(),
            b"9007199254740993"
        );
        assert_eq!(
            canonicalize_exact_integers(&json!(-(two_pow_53 as i64) - 1)).unwrap(),
            b"-9007199254740993"
        );
        assert_eq!(
            canonicalize_exact_integers(&json!(u64::MAX)).unwrap(),
            b"18446744073709551615"
        );
        assert_eq!(
            canonicalize_exact_integers(&json!(i64::MIN)).unwrap(),
            b"-9223372036854775808"
        );
        for same in [
            json!(two_pow_53),
            json!(-(two_pow_53 as i64)),
            json!(0),
            json!(-7),
            json!(12_345),
            json!(1.5),
            json!(1e21),
            json!(-0.000001),
            json!({"b": [1, 2.25, "x", null, true], "a": {"\u{1F600}": 9_007_199_254_740_991_u64}}),
        ] {
            assert_eq!(
                canonicalize_exact_integers(&same).unwrap(),
                canonicalize(&same).unwrap(),
                "{same} must canonicalize exactly as RFC 8785 does"
            );
        }
    }
}
