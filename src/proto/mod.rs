#[cfg(feature = "grpcio")]
pub(crate) mod workload;
#[cfg(feature = "grpcio")]
pub(crate) mod workload_grpc;

#[cfg(feature = "tonic")]
pub mod spire {
  pub mod api {

    pub mod workload {
      include!("_.rs");
    }

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
  }

}
