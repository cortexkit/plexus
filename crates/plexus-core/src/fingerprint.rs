//! Safe identifiers for secret handles and other bearer references.

use sha2::{Digest, Sha256};

/// Return a short, non-reversible display identifier for a handle.
///
/// The returned value contains only the first twelve hexadecimal characters of
/// SHA-256 and never embeds any bytes from the input handle.
///
/// Twelve hex characters are 48 bits, so among n distinct inputs some pair
/// shares a value with probability about n^2 / 2^49 (an even chance near 2^24
/// inputs, about 16 million). That is fine for what this is used for:
/// attributing audit rows, redacting credential references out of logged
/// arguments, and naming the connection in a decision-plane envelope, where a
/// deployment holds tens of handles. It is NOT a unique key: nothing may look a
/// credential up by it or treat two equal fingerprints as proof of one
/// credential. Use the stored reference or connection id for that.
pub fn fingerprint(handle: &[u8]) -> String {
    // Only the first six digest bytes, so not `jcs::sha256_hex`.
    let digest = Sha256::digest(handle);
    format!("ckfp_{}", hex::encode(&digest[..6]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_short_and_prefixed() {
        let value = fingerprint(b"secret-handle");
        assert!(value.starts_with("ckfp_"));
        assert_eq!(value.len(), 17);
    }

    /// Distinct handles must fingerprint distinctly.
    ///
    /// Every other assertion here checks the SHAPE of the output — prefix,
    /// length, absence of the input bytes — and a constant satisfies all of
    /// them. Replacing the body with a fixed string passed the entire core and
    /// module suites, so nothing established that the output depends on the
    /// input at all.
    ///
    /// That matters because a fingerprint stands in for the handle wherever a
    /// handle may not be written: audit rows attribute a call by it, and the
    /// stub credential source used by tests indexes its canned responses by it
    /// (a test convenience, not a production lookup). A fingerprint that
    /// ignores its input collapses every distinct handle onto one value, which
    /// reads as correct everywhere it appears. (It is a 48-bit display value,
    /// not a collision-free key; see the function's documentation.)
    #[test]
    fn distinct_handles_fingerprint_distinctly() {
        assert_ne!(
            fingerprint(b"handle-one"),
            fingerprint(b"handle-two"),
            "a fingerprint that ignores its input collapses distinct handles onto one identity"
        );
        // A one-byte difference must still separate them: the digest must
        // depend on the whole input rather than on its length or its prefix.
        assert_ne!(fingerprint(b"ckh_aaaa"), fingerprint(b"ckh_aaab"));
        // And the same input must fingerprint the same way, or lookups keyed
        // on it would miss.
        assert_eq!(fingerprint(b"ckh_stable"), fingerprint(b"ckh_stable"));
    }

    #[test]
    fn fingerprint_never_contains_input_bytes() {
        let handle = b"raw-handle-that-must-not-leak";
        let value = fingerprint(handle);
        assert!(!value
            .as_bytes()
            .windows(handle.len())
            .any(|window| window == handle));
        assert!(!value.contains("raw-handle"));
    }
}
