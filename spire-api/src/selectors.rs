//! Selectors which conform to SPIRE standards.
//! 
use crate::proto::spire::api::types::Selector as SpiffeSelector;

const K8S_TYPE: &str = "k8s";
const UNIX_TYPE: &str = "unix";

/// User-facing version of underlying proto selector type
impl From<Selector> for SpiffeSelector {
  fn from(s: Selector) -> SpiffeSelector {
    match s {
      Selector::K8s(k8s_selector) => SpiffeSelector {
          r#type: K8S_TYPE.to_string(),
          value: k8s_selector.into(),
      },
      Selector::Unix(unix_selector) => SpiffeSelector {
          r#type: UNIX_TYPE.to_string(),
          value: unix_selector.into(),
      },
      Selector::Generic((k, v)) => SpiffeSelector {
          r#type: k,
          value: v,
      },
  }
  }
}

#[derive(Debug, Clone)]
/// Selector represents a SPIFFE ID selector.
pub enum Selector {
    /// K8s represents a SPIFFE ID selector.
    K8s(K8s),
    /// Selector represents a SPIFFE ID selector.
    Unix(Unix),
    /// Selector represents a SPIFFE ID selector.
    Generic((String, String)),
}

const K8S_SA_TYPE: &str = "sa";
const K8S_NS_TYPE: &str = "ns";

impl From<K8s> for String {
    fn from(k: K8s) -> String {
      match k {
        K8s::ServiceAccount(s) => format!("{}:{}", K8S_SA_TYPE, s),
        K8s::Namespace(s) => format!("{}:{}", K8S_NS_TYPE, s),
    }
    }
}

#[derive(Debug, Clone)]
/// K8s is a helper type to create a SPIFFE ID selector for Kubernetes.
pub enum K8s {
    /// ServiceAccount represents the SPIFFE ID selector for a Kubernetes service account.
    ServiceAccount(String),
    /// Namespace represents the SPIFFE ID selector for a Kubernetes namespace.
    Namespace(String),
}

const UNIX_PID_TYPE: &str = "pid";
const UNIX_GID_TYPE: &str = "gid";
const UNIX_UID_TYPE: &str = "uid";

impl From<Unix> for String {
  fn from(value: Unix) -> Self {
    match value {
      Unix::Pid(s) => format!("{}:{}", UNIX_PID_TYPE, s),
      Unix::Gid(s) => format!("{}:{}", UNIX_GID_TYPE, s),
      Unix::Uid(s) => format!("{}:{}", UNIX_UID_TYPE, s),
  }
  }
}

#[derive(Debug, Clone)]
/// K8s is a helper type to create a SPIFFE ID unix process constructs.
pub enum Unix {
    /// PID represents the SPIFFE ID selector for a process ID.
    Pid(u16),
    /// GID represents the SPIFFE ID selector for a group ID.
    Gid(u16),
    /// UID represents the SPIFFE ID selector for a User ID.
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