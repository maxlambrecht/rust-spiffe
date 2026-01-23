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

#[derive(Debug, Clone, Copy)]
/// Represents SPIFFE identity selectors based on Unix process-related attributes.
pub enum Unix {
    /// Specifies a selector for a Unix process ID (PID).
    Pid(u16),
    /// Specifies a selector for a Unix group ID (GID).
    Gid(u16),
    /// Specifies a selector for a Unix user ID (UID).
    Uid(u16),
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
        let selector = Selector::Unix(Unix::Pid(500));
        let spiffe_selector: SpiffeSelector = selector.into();
        assert_eq!(spiffe_selector.r#type, UNIX_TYPE);
        assert_eq!(spiffe_selector.value, "pid:500");
    }

    #[test]
    fn test_unix_gid_selector() {
        let selector = Selector::Unix(Unix::Gid(500));
        let spiffe_selector: SpiffeSelector = selector.into();
        assert_eq!(spiffe_selector.r#type, UNIX_TYPE);
        assert_eq!(spiffe_selector.value, "gid:500");
    }

    #[test]
    fn test_unix_uid_selector() {
        let selector = Selector::Unix(Unix::Uid(500));
        let spiffe_selector: SpiffeSelector = selector.into();
        assert_eq!(spiffe_selector.r#type, UNIX_TYPE);
        assert_eq!(spiffe_selector.value, "uid:500");
    }
}
