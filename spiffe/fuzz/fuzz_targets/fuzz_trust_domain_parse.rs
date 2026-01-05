#![no_main]

use libfuzzer_sys::fuzz_target;
use spiffe::TrustDomain;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let s = s.as_ref();

    let parsed_new = TrustDomain::new(s);
    let parsed_fromstr = s.parse::<TrustDomain>();

    let new_ok = parsed_new.is_ok();
    let fromstr_ok = parsed_fromstr.is_ok();

    if let Ok(td) = parsed_new {
        let rt = td.to_string();
        let td2 = TrustDomain::new(&rt).expect("round-trip parse must succeed");
        assert_eq!(td, td2);

        // Trust domain invariants
        assert!(!td.as_str().is_empty());
        assert_eq!(td.as_str(), rt);

        let id_str = td.id_string();
        let td3 = TrustDomain::new(&id_str).expect("id_string must be parseable");
        assert_eq!(td, td3);
    }

    // API consistency
    assert_eq!(new_ok, fromstr_ok);
});
