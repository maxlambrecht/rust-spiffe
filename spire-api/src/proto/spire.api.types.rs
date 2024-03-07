#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Selector {
    /// The type of the selector. This is typically the name of the plugin that
    /// produces the selector.
    #[prost(string, tag = "1")]
    pub r#type: ::prost::alloc::string::String,
    /// The value of the selector.
    #[prost(string, tag = "2")]
    pub value: ::prost::alloc::string::String,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SelectorMatch {
    /// The set of selectors to match on.
    #[prost(message, repeated, tag = "1")]
    pub selectors: ::prost::alloc::vec::Vec<Selector>,
    /// How to match the selectors.
    #[prost(enumeration = "selector_match::MatchBehavior", tag = "2")]
    pub r#match: i32,
}
/// Nested message and enum types in `SelectorMatch`.
pub mod selector_match {
    #[derive(
        Clone,
        Copy,
        Debug,
        PartialEq,
        Eq,
        Hash,
        PartialOrd,
        Ord,
        ::prost::Enumeration
    )]
    #[repr(i32)]
    pub enum MatchBehavior {
        /// Indicates that the selectors in this match are equal to the
        /// candidate selectors, independent of ordering.
        /// Example:
        ///    Given:
        ///      - 'e1 { Selectors: \["a:1", "b:2", "c:3"\]}'
        ///      - 'e2 { Selectors: \["a:1", "b:2"\]}'
        ///      - 'e3 { Selectors: \["a:1"\]}'
        ///    Operation:
        ///      - MATCH_EXACT \["a:1", "b:2"\]
        ///    Entries that match:
        ///      - 'e2'
        MatchExact = 0,
        /// Indicates that all candidates which have a non-empty subset
        /// of the provided set of selectors will match.
        /// Example:
        ///    Given:
        ///      - 'e1 { Selectors: \["a:1", "b:2", "c:3"\]}'
        ///      - 'e2 { Selectors: \["a:1", "b:2"\]}'
        ///      - 'e3 { Selectors: \["a:1"\]}'
        ///    Operation:
        ///      - MATCH_SUBSET \["a:1"\]
        ///    Entries that match:
        ///      - 'e1'
        MatchSubset = 1,
        /// Indicates that all candidates which are a superset
        /// of the provided selectors will match.
        /// Example:
        ///    Given:
        ///      - 'e1 { Selectors: \["a:1", "b:2", "c:3"\]}'
        ///      - 'e2 { Selectors: \["a:1", "b:2"\]}'
        ///      - 'e3 { Selectors: \["a:1"\]}'
        ///    Operation:
        ///      - MATCH_SUPERSET \["a:1", "b:2"\]
        ///    Entries that match:
        ///      - 'e1'
        ///      - 'e2'
        MatchSuperset = 2,
        /// Indicates that all candidates which have at least one
        /// of the provided set of selectors will match.
        /// Example:
        ///    Given:
        ///      - 'e1 { Selectors: \["a:1", "b:2", "c:3"\]}'
        ///      - 'e2 { Selectors: \["a:1", "b:2"\]}'
        ///      - 'e3 { Selectors: \["a:1"\]}'
        ///    Operation:
        ///      - MATCH_ANY \["a:1"\]
        ///    Entries that match:
        ///      - 'e1'
        ///      - 'e2'
        ///      - 'e3'
        MatchAny = 3,
    }
    impl MatchBehavior {
        /// String value of the enum field names used in the ProtoBuf definition.
        ///
        /// The values are not transformed in any way and thus are considered stable
        /// (if the ProtoBuf definition does not change) and safe for programmatic use.
        pub fn as_str_name(&self) -> &'static str {
            match self {
                MatchBehavior::MatchExact => "MATCH_EXACT",
                MatchBehavior::MatchSubset => "MATCH_SUBSET",
                MatchBehavior::MatchSuperset => "MATCH_SUPERSET",
                MatchBehavior::MatchAny => "MATCH_ANY",
            }
        }
        /// Creates an enum from field names used in the ProtoBuf definition.
        pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
            match value {
                "MATCH_EXACT" => Some(Self::MatchExact),
                "MATCH_SUBSET" => Some(Self::MatchSubset),
                "MATCH_SUPERSET" => Some(Self::MatchSuperset),
                "MATCH_ANY" => Some(Self::MatchAny),
                _ => None,
            }
        }
    }
}
/// A SPIFFE ID, consisting of the trust domain name and a path portions of
/// the SPIFFE ID URI.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Spiffeid {
    /// Trust domain portion the SPIFFE ID (e.g. "example.org")
    #[prost(string, tag = "1")]
    pub trust_domain: ::prost::alloc::string::String,
    /// The path component of the SPIFFE ID (e.g. "/foo/bar/baz"). The path
    /// SHOULD have a leading slash. Consumers MUST normalize the path before
    /// making any sort of comparison between IDs.
    #[prost(string, tag = "2")]
    pub path: ::prost::alloc::string::String,
}
/// X.509 SPIFFE Verifiable Identity Document. It contains the raw X.509
/// certificate data as well as a few denormalized fields for convenience.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct X509svid {
    /// Certificate and intermediates required to form a chain of trust back to
    /// the X.509 authorities of the trust domain (ASN.1 DER encoded).
    #[prost(bytes = "bytes", repeated, tag = "1")]
    pub cert_chain: ::prost::alloc::vec::Vec<::prost::bytes::Bytes>,
    /// SPIFFE ID of the SVID.
    #[prost(message, optional, tag = "2")]
    pub id: ::core::option::Option<Spiffeid>,
    /// Expiration timestamp (seconds since Unix epoch).
    #[prost(int64, tag = "3")]
    pub expires_at: i64,
    /// Optional. An operator-specified string used to provide guidance on how this
    /// identity should be used by a workload when more than one SVID is returned.
    /// For example, `internal` and `external` to indicate an SVID for internal or
    /// external use, respectively.
    #[prost(string, tag = "4")]
    pub hint: ::prost::alloc::string::String,
}
/// JWT SPIFFE Verifiable Identity Document. It contains the raw JWT token
/// as well as a few denormalized fields for convenience.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Jwtsvid {
    /// The serialized JWT token.
    #[prost(string, tag = "1")]
    pub token: ::prost::alloc::string::String,
    /// The SPIFFE ID of the JWT-SVID.
    #[prost(message, optional, tag = "2")]
    pub id: ::core::option::Option<Spiffeid>,
    /// Expiration timestamp (seconds since Unix epoch).
    #[prost(int64, tag = "3")]
    pub expires_at: i64,
    /// Issuance timestamp (seconds since Unix epoch).
    #[prost(int64, tag = "4")]
    pub issued_at: i64,
    /// Optional. An operator-specified string used to provide guidance on how this
    /// identity should be used by a workload when more than one SVID is returned.
    /// For example, `internal` and `external` to indicate an SVID for internal or
    /// external use, respectively.
    #[prost(string, tag = "5")]
    pub hint: ::prost::alloc::string::String,
}
