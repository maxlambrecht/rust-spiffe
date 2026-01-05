#![no_main]

use libfuzzer_sys::fuzz_target;
use spiffe::TrustDomain;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let s = s.as_ref();

    let parsed_new = TrustDomain::new(s);
    let parsed_fromstr = s.parse::<TrustDomain>();

    // Consistency between APIs (cheap, keep always).
    assert_eq!(parsed_new.is_ok(), parsed_fromstr.is_ok());

    // If valid, enforce invariants.
    if let Ok(td) = parsed_new {
        // Cheap invariants (keep always).
        let name = td.as_str();
        assert!(!name.is_empty());
        assert!(!name.contains('/'));

        // Heavier checks only sometimes to reduce allocations.
        if data.first().map(|b| b & 0x3F == 0).unwrap_or(false) {
            let rt = td.to_string();
            let td2 = TrustDomain::new(&rt).expect("round-trip parse must succeed");
            assert_eq!(td, td2);

            let id_str = td.id_string();
            let td3 = TrustDomain::new(&id_str).expect("id_string must be parseable");
            assert_eq!(td, td3);
        }
    }
});
