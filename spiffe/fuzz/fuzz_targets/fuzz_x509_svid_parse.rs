#![no_main]
#![expect(
    clippy::indexing_slicing,
    clippy::expect_used,
    missing_docs,
    reason = "fuzz target"
)]

use libfuzzer_sys::fuzz_target;
use spiffe::X509Svid;

const VALID_CHAIN: &[u8] = include_bytes!("../../tests/testdata/svid/x509/1-svid-chain.der");
const VALID_KEY: &[u8] = include_bytes!("../../tests/testdata/svid/x509/1-key.der");

fuzz_target!(|data: &[u8]| {
    // Exercise raw attacker-controlled certificate and key inputs independently.
    let raw_chain = X509Svid::parse_from_der(data, VALID_KEY);
    let raw_chain_again = X509Svid::parse_from_der(data, VALID_KEY);
    assert_eq!(raw_chain.is_ok(), raw_chain_again.is_ok());

    let raw_key = X509Svid::parse_from_der(VALID_CHAIN, data);
    let raw_key_again = X509Svid::parse_from_der(VALID_CHAIN, data);
    assert_eq!(raw_key.is_ok(), raw_key_again.is_ok());

    // Starting from a valid chain lets mutations reach profile validation paths
    // that unconstrained random DER would almost never exercise.
    let mut mutated_chain = VALID_CHAIN.to_vec();
    for (index, byte) in data.iter().copied().take(256).enumerate() {
        let position = index.wrapping_mul(257) % mutated_chain.len();
        mutated_chain[position] ^= byte;
    }
    let mutated = X509Svid::parse_from_der(&mutated_chain, VALID_KEY);
    let mutated_again = X509Svid::parse_from_der(&mutated_chain, VALID_KEY);
    assert_eq!(mutated.is_ok(), mutated_again.is_ok());

    // Also vary the certificate/key boundary for concatenated untrusted input.
    let split = data.len() / 2;
    let _unused = X509Svid::parse_from_der(&data[..split], &data[split..]);
});
