pub(crate) mod workload;
pub mod agent {
    pub mod delegatedidentity {
        pub mod v1 {
            include!("spire.api.agent.delegatedidentity.v1.rs");
        }
    }
}

pub mod types {
    include!("spire.api.types.rs");
}
