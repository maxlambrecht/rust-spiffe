#![no_main]
#![expect(clippy::expect_used, missing_docs, reason = "fuzz target")]

use libfuzzer_sys::fuzz_target;
use spiffe::TrustDomain;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);

    let parsed_new = TrustDomain::new(s.as_ref());
    let parsed_fromstr = s.as_ref().parse::<TrustDomain>();

    // Consistency between APIs.
    assert_eq!(parsed_new.is_ok(), parsed_fromstr.is_ok());

    if let Ok(td) = parsed_new {
        // Round-trip must always succeed for a validated ID.
        let rt = td.to_string();
        let td2 = TrustDomain::new(&rt).expect("round-trip parse must succeed");
        assert_eq!(td, td2);

        // Trust domain invariants.
        assert!(!td.as_str().is_empty());
        assert_eq!(td.as_str(), rt);

        // id_string must be stable, parseable, and canonical.
        let id_str = td.id_string();
        assert_eq!(
            id_str.strip_prefix("spiffe://").expect(&id_str),
            td.as_str()
        );

        let td3 = TrustDomain::new(&id_str).expect("id_string must be parseable");
        assert_eq!(td, td3);
    }
});
