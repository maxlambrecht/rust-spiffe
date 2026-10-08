//! Selectors conforming to SPIRE standards.
use crate::pb::spire::api::types::Selector as SpiffeSelector;

const K8S_TYPE: &str = "k8s";
const UNIX_TYPE: &str = "unix";

/// Converts user-defined selectors into SPIFFE selectors.
impl From<Selector> for SpiffeSelector {
    fn from(s: Selector) -> Self {
        match s {
            Selector::K8s(k8s_selector) => Self {
                r#type: K8S_TYPE.to_string(),
                value: k8s_selector.into(),
            },
            Selector::Unix(unix_selector) => Self {
                r#type: UNIX_TYPE.to_string(),
                value: unix_selector.into(),
            },
            Selector::Generic((k, v)) => Self {
                r#type: k,
                value: v,
            },
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Represents various types of SPIFFE identity selectors.
pub enum Selector {
    /// Represents a SPIFFE identity selector based on Kubernetes constructs.
    K8s(K8s),
    /// Represents a SPIFFE identity selector based on Unix system constructs such as PID, GID, and UID.
    Unix(Unix),
    /// Represents a generic SPIFFE identity selector defined by a key-value pair.
    Generic((String, String)),
}

const K8S_SA_TYPE: &str = "sa";
const K8S_NS_TYPE: &str = "ns";

/// Converts Kubernetes selectors to their string representation.
impl From<K8s> for String {
    fn from(k: K8s) -> Self {
        match k {
            K8s::ServiceAccount(s) => format!("{K8S_SA_TYPE}:{s}"),
            K8s::Namespace(s) => format!("{K8S_NS_TYPE}:{s}"),
        }
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
/// Represents a SPIFFE identity selector for Kubernetes.
pub enum K8s {
    /// SPIFFE identity selector for a Kubernetes service account.
    ServiceAccount(String),
    /// SPIFFE identity selector for a Kubernetes namespace.
    Namespace(String),
}

const UNIX_PID_TYPE: &str = "pid";
const UNIX_GID_TYPE: &str = "gid";
const UNIX_UID_TYPE: &str = "uid";

/// Converts a Unix selector into a formatted string representation.
impl From<Unix> for String {
    fn from(value: Unix) -> Self {
        match value {
            Unix::Pid(s) => format!("{UNIX_PID_TYPE}:{s}"),
            Unix::Gid(s) => format!("{UNIX_GID_TYPE}:{s}"),
            Unix::Uid(s) => format!("{UNIX_UID_TYPE}:{s}"),
        }
    }
}

/// A Unix user or group identifier.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct UnixId(u32);

impl UnixId {
    /// Creates a UID or GID selector value.
    ///
    /// Accepts any `u32` value without checking for a corresponding user or group.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the numeric identifier.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl From<u32> for UnixId {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl std::fmt::Display for UnixId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A positive Unix process identifier used in a SPIFFE selector.
///
/// Accepts values in `1..=u32::MAX`. Requests for PID-based delegated attestation
/// use the narrower range of
/// [`DelegatePid`](crate::agent::delegated_identity::DelegatePid).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct UnixPid(std::num::NonZeroU32);

impl UnixPid {
    /// Creates a selector process identifier in the `1..=u32::MAX` range.
    ///
    /// Returns `None` if `value` is zero.
    pub const fn new(value: u32) -> Option<Self> {
        match std::num::NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the numeric process ID.
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl TryFrom<u32> for UnixPid {
    type Error = InvalidUnixPid;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(InvalidUnixPid)
    }
}

impl std::fmt::Display for UnixPid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// An error indicating that a process ID is zero.
#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
#[error("Unix PID must be greater than zero")]
pub struct InvalidUnixPid;

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
/// Represents SPIFFE identity selectors based on Unix process-related attributes.
pub enum Unix {
    /// Specifies a selector for a Unix process ID (PID).
    Pid(UnixPid),
    /// Specifies a selector for a Unix group ID (GID).
    Gid(UnixId),
    /// Specifies a selector for a Unix user ID (UID).
    Uid(UnixId),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_k8s_sa_selector() {
        let selector = Selector::K8s(K8s::ServiceAccount("foo".to_string()));
        let spiffe_selector: SpiffeSelector = selector.into();
        assert_eq!(spiffe_selector.r#type, K8S_TYPE);
        assert_eq!(spiffe_selector.value, "sa:foo");
    }

    #[test]
    fn test_k8s_ns_selector() {
        let selector = Selector::K8s(K8s::Namespace("foo".to_string()));
        let spiffe_selector: SpiffeSelector = selector.into();
        assert_eq!(spiffe_selector.r#type, K8S_TYPE);
        assert_eq!(spiffe_selector.value, "ns:foo");
    }

    #[test]
    fn test_unix_pid_selector() {
        let selector = Selector::Unix(Unix::Pid(UnixPid::new(500).unwrap()));
        let spiffe_selector: SpiffeSelector = selector.into();
        assert_eq!(spiffe_selector.r#type, UNIX_TYPE);
        assert_eq!(spiffe_selector.value, "pid:500");
    }

    #[test]
    fn test_unix_gid_selector() {
        let selector = Selector::Unix(Unix::Gid(UnixId::new(500)));
        let spiffe_selector: SpiffeSelector = selector.into();
        assert_eq!(spiffe_selector.r#type, UNIX_TYPE);
        assert_eq!(spiffe_selector.value, "gid:500");
    }

    #[test]
    fn test_unix_uid_selector() {
        let selector = Selector::Unix(Unix::Uid(UnixId::new(500)));
        let spiffe_selector: SpiffeSelector = selector.into();
        assert_eq!(spiffe_selector.r#type, UNIX_TYPE);
        assert_eq!(spiffe_selector.value, "uid:500");
    }

    #[test]
    fn unix_ids_preserve_u32_boundaries() {
        let uid: String = Unix::Uid(UnixId::new(u32::MAX)).into();
        let gid: String = Unix::Gid(UnixId::new(u32::from(u16::MAX) + 1)).into();

        assert_eq!(uid, format!("uid:{}", u32::MAX));
        assert_eq!(gid, "gid:65536");
    }

    #[test]
    fn unix_pid_rejects_zero_and_accepts_u32_max() {
        assert_eq!(UnixPid::try_from(0), Err(InvalidUnixPid));
        assert_eq!(UnixPid::try_from(u32::MAX).unwrap().get(), u32::MAX);
    }
}
