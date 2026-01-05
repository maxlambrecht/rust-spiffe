#![no_main]

use libfuzzer_sys::fuzz_target;
use spiffe::{SpiffeId, TrustDomain};

fuzz_target!(|data: &[u8]| {
    let s = std::string::String::from_utf8_lossy(data);
    let s = s.as_ref();

    let parsed_new = SpiffeId::new(s);
    let parsed_fromstr = s.parse::<SpiffeId>();

    // Consistency between APIs.
    assert_eq!(parsed_new.is_ok(), parsed_fromstr.is_ok());

    if let Ok(id) = parsed_new {
        // Invariants that must always hold.
        let td = id.trust_domain_name();
        assert!(!td.is_empty());
        let _ = TrustDomain::new(td).expect("trust domain name must re-parse");

        let path = id.path();
        assert!(path.is_empty() || path.starts_with('/'));
    }
});
