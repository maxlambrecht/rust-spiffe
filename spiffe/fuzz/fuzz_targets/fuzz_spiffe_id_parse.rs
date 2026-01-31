#![no_main]
#![expect(clippy::expect_used, missing_docs, reason = "fuzz target")]

use libfuzzer_sys::fuzz_target;
use spiffe::{SpiffeId, TrustDomain};

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);

    let parsed_new = SpiffeId::new(s.as_ref());
    let parsed_fromstr = s.as_ref().parse::<SpiffeId>();

    // Consistency between APIs.
    assert_eq!(parsed_new.is_ok(), parsed_fromstr.is_ok());

    if let Ok(id) = parsed_new {
        // Round-trip must always succeed for a validated ID.
        let rt = id.to_string();
        assert!(rt.starts_with("spiffe://"));

        let id2 = SpiffeId::new(&rt).expect("round-trip parse must succeed");
        assert_eq!(id, id2);

        // Trust domain invariants.
        let td = id.trust_domain_name();
        assert!(!td.is_empty());
        let td2 = TrustDomain::new(td).expect("trust domain name must re-parse");
        assert_eq!(td2.as_str(), td);

        // Path invariants.
        let path = id.path();
        assert!(path.is_empty() || path.starts_with('/'));
    }
});
