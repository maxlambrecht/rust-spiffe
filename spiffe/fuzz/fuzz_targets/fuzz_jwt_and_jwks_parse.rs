#![no_main]
#![expect(clippy::expect_used, missing_docs, reason = "fuzz target")]

use base64ct::{Base64UrlUnpadded, Encoding as _};
use libfuzzer_sys::fuzz_target;
use spiffe::{JwtBundle, JwtSvid, TrustDomain};

const VALID_HEADER: &[u8] = br#"{"alg":"ES256","kid":"fuzz-key","typ":"JWT"}"#;
const VALID_CLAIMS: &[u8] =
    br#"{"sub":"spiffe://example.org/workload","aud":["service"],"exp":4294967295}"#;

fn compact_token(header: &[u8], claims: &[u8]) -> String {
    let header = Base64UrlUnpadded::encode_string(header);
    let claims = Base64UrlUnpadded::encode_string(claims);
    format!("{header}.{claims}.signature")
}

fuzz_target!(|data: &[u8]| {
    let raw = String::from_utf8_lossy(data);
    let parsed = JwtSvid::parse_insecure(raw.as_ref());
    let parsed_again = JwtSvid::parse_insecure(raw.as_ref());
    assert_eq!(parsed.is_ok(), parsed_again.is_ok());

    // Keep one segment structurally valid so arbitrary bytes reach both header
    // and claims deserialization/validation paths.
    for token in [
        compact_token(data, VALID_CLAIMS),
        compact_token(VALID_HEADER, data),
    ] {
        let first = JwtSvid::parse_insecure(&token);
        let second = JwtSvid::parse_insecure(&token);
        assert_eq!(first.is_ok(), second.is_ok());
        if let (Ok(first), Ok(second)) = (first, second) {
            assert_eq!(first, second);
            let round_trip = first.spiffe_id().to_string();
            assert_eq!(round_trip.parse(), Ok(first.spiffe_id().clone()));
        }
    }

    let trust_domain = TrustDomain::new("example.org").expect("fixed trust domain is valid");
    let first = JwtBundle::from_jwt_authorities(trust_domain.clone(), data);
    let second = JwtBundle::from_jwt_authorities(trust_domain, data);
    assert_eq!(first.is_ok(), second.is_ok());
    if let (Ok(first), Ok(second)) = (first, second) {
        assert_eq!(first, second);
    }
});
