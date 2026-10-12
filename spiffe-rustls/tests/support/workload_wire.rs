// Test-only wire messages matching the Workload API protobuf tags.
// Kept local so packaged integration tests do not depend on a sibling checkout.

#[expect(
    clippy::empty_structs_with_brackets,
    reason = "prost Message derive requires braces for empty messages"
)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, ::prost::Message)]
pub(super) struct X509svidRequest {}

#[derive(Clone, PartialEq, ::prost::Message)]
pub(super) struct X509svidResponse {
    /// Required. A list of X509SVID messages, each of which includes a single
    /// X.509-SVID, its private key, and the bundle for the trust domain.
    #[prost(message, repeated, tag = "1")]
    pub svids: ::prost::alloc::vec::Vec<X509svid>,
    /// Optional. ASN.1 DER encoded certificate revocation lists.
    #[prost(bytes = "bytes", repeated, tag = "2")]
    pub crl: ::prost::alloc::vec::Vec<::prost::bytes::Bytes>,
    /// Optional. CA certificate bundles belonging to foreign trust domains that
    /// the workload should trust, keyed by the SPIFFE ID of the foreign trust
    /// domain. Bundles are ASN.1 DER encoded.
    #[prost(map = "string, bytes", tag = "3")]
    pub federated_bundles:
        ::std::collections::HashMap<::prost::alloc::string::String, ::prost::bytes::Bytes>,
}

#[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
pub(super) struct X509svid {
    /// Required. The SPIFFE ID of the SVID in this entry
    #[prost(string, tag = "1")]
    pub spiffe_id: ::prost::alloc::string::String,
    /// Required. ASN.1 DER encoded certificate chain. MAY include
    /// intermediates, the leaf certificate (or SVID itself) MUST come first.
    #[prost(bytes = "bytes", tag = "2")]
    pub x509_svid: ::prost::bytes::Bytes,
    /// Required. ASN.1 DER encoded PKCS#8 private key. MUST be unencrypted.
    #[prost(bytes = "bytes", tag = "3")]
    pub x509_svid_key: ::prost::bytes::Bytes,
    /// Required. ASN.1 DER encoded X.509 bundle for the trust domain.
    #[prost(bytes = "bytes", tag = "4")]
    pub bundle: ::prost::bytes::Bytes,
    /// Optional. An operator-specified string used to provide guidance on how this
    /// identity should be used by a workload when more than one SVID is returned.
    /// For example, `internal` and `external` to indicate an SVID for internal or
    /// external use, respectively.
    #[prost(string, tag = "5")]
    pub hint: ::prost::alloc::string::String,
}

#[expect(
    clippy::empty_structs_with_brackets,
    reason = "prost Message derive requires braces for empty messages"
)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, ::prost::Message)]
pub(super) struct JwtBundlesRequest {}

#[derive(Clone, PartialEq, ::prost::Message)]
pub(super) struct JwtBundlesResponse {
    /// Required. JWK encoded JWT bundles, keyed by the SPIFFE ID of the trust
    /// domain.
    #[prost(map = "string, bytes", tag = "1")]
    pub bundles: ::std::collections::HashMap<::prost::alloc::string::String, ::prost::bytes::Bytes>,
}
