//! Credential-reference decoding regression tests.

use super::*;

#[test]
fn reference_binding_decoder_refuses_legacy_blobs() {
    let reference = encode_reference_binding("apikey:github").unwrap();
    assert_eq!(
        decode_connection_binding(&reference).unwrap().kind(),
        "reference"
    );
    assert_eq!(
        format!("{:?}", decode_connection_binding(&reference).unwrap()),
        "reference"
    );
    assert!(decode_connection_binding(&[42; 64]).is_err());
}
