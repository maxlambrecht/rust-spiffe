//! Redacted diagnostics for the generated SPIRE credential messages.

use crate::pb::spire::api::{agent::delegatedidentity::v1::X509svidWithKey, types::Jwtsvid};
use std::fmt;

impl fmt::Debug for X509svidWithKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Require an explicit diagnostic policy if generation adds fields.
        let Self {
            x509_svid,
            x509_svid_key,
        } = self;
        f.debug_struct("X509svidWithKey")
            .field("x509_svid", x509_svid)
            .field(
                "x509_svid_key",
                &Redacted("PrivateKey", x509_svid_key.len()),
            )
            .finish()
    }
}

impl fmt::Debug for Jwtsvid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            token,
            id,
            expires_at,
            issued_at,
            hint,
        } = self;
        f.debug_struct("Jwtsvid")
            .field("token", &Redacted("Token", token.len()))
            .field("id", id)
            .field("expires_at", expires_at)
            .field("issued_at", issued_at)
            .field("hint", hint)
            .finish()
    }
}

// Match the Broker API's length-only credential placeholders.
struct Redacted(&'static str, usize);

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(self.0).field("len", &self.1).finish()
    }
}
