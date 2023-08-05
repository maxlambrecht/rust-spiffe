//! This module provides an API surface to interact with the DelegateIdentity API.
//! The protobuf definition can be found [here](https://github.com/spiffe/spire-api-sdk/blob/main/proto/spire/api/agent/delegatedidentity/v1/delegatedidentity.proto)
//! 
//! More information on it's usage can be found in the [SPIFFE docs](https://spiffe.io/docs/latest/deploying/spire_agent/#delegated-identity-api)


use thiserror::Error;
use futures::{Stream, StreamExt};
use crate::proto::spire::api::agent::delegatedidentity::v1::{
  delegated_identity_client, SubscribeToX509BundlesRequest, SubscribeToX509BundlesResponse, 
  SubscribeToX509sviDsRequest, SubscribeToX509sviDsResponse, X509svidWithKey
};
use crate::proto::spire::api::types::{Selector as SpiffeSelector};
use crate::workload_api::address::{
  get_default_socket_path, validate_socket_path, SocketPathError,
};
use crate::bundle::jwt::{JwtBundle, JwtBundleError, JwtBundleSet};
use crate::bundle::x509::{X509Bundle, X509BundleError, X509BundleSet};
use crate::spiffe_id::{SpiffeId, SpiffeIdError, TrustDomain};
use crate::svid::jwt::{JwtSvid, JwtSvidError};
use crate::svid::x509::{X509Svid, X509SvidError};

use crate::workload_api::client::{ClientError, DEFAULT_SVID};
use tokio::net::UnixStream;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;
use std::convert::{TryFrom, Into};

#[derive(Debug, Clone)]
/// User-facing version of underlying proto selector type
pub struct Selector {
  key: String,
  value: String,
}

impl Into<SpiffeSelector> for Selector {
  fn into(self) -> SpiffeSelector {
    SpiffeSelector{
      r#type: self.key,
      value: self.value,
    }
  }
}


impl Into<Selector> for SpiffeSelector {
  fn into(self) -> Selector {
    Selector{
      key: self.r#type,
      value: self.value,
    }
  }
}



/// Impl for DelegatedIdentity API
#[derive(Debug, Clone)]
pub struct DelegatedIdentityClient {
    client: delegated_identity_client::DelegatedIdentityClient<tonic::transport::Channel>,
}

/// Constructors
impl DelegatedIdentityClient {
      /// new returns a new client
      pub async fn new_from_path(path: String) -> Result<Self, ClientError> {
        validate_socket_path(path.as_str())?;
        // We need to strip the 'unix:' prefix from the path to use it with tonic
        // Because the service_fn doesn't have FnMut we need a new String, I think
        let inner_path = String::from(path.clone()).strip_prefix("unix:").unwrap_or(path.as_str()).to_string();
        let channel = Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(move |_: Uri| {
            // Connect to a Uds socket
            UnixStream::connect(inner_path.clone())
        }))
        .await?;
        
        Ok(DelegatedIdentityClient{client: delegated_identity_client::DelegatedIdentityClient::new(channel)})
    }

    /// Creates a new `DelegatedIdentityClient` using the default socket endpoint address.
    ///
    /// Requires that the environment variable `SPIFFE_ENDPOINT_SOCKET` be set with
    /// the path to the Workload API endpoint socket.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`ClientError`] if environment variable is not set or if
    /// the provided socket path is not valid.
    pub async fn default() -> Result<Self, ClientError> {
        let socket_path = match get_default_socket_path() {
            None => return Err(ClientError::MissingEndpointSocketPath),
            Some(s) => s,
        };
        Self::new_from_path(socket_path).await
    }

    /// new returns a new client
    pub fn new(conn: tonic::transport::Channel) -> Result<Self, ClientError> {
        Ok(DelegatedIdentityClient{client: delegated_identity_client::DelegatedIdentityClient::new(conn)})
    }
}

impl DelegatedIdentityClient {
      /// Fetch a single x509_svid
      pub async fn fetch_x509_svid(mut self, selectors: Vec<Selector>) -> Result<X509Svid, ClientError> {
        
        let request = SubscribeToX509sviDsRequest{
          selectors: selectors.into_iter().map(|s| s.into()).collect(), 
        };

        let response: tonic::Response<tonic::Streaming<SubscribeToX509sviDsResponse>> = self.client.subscribe_to_x509svi_ds(request).await?;
        let initial = response.into_inner().message().await?;
        DelegatedIdentityClient::parse_x509_svid_from_grpc_response(initial.unwrap_or_default())
    }

    /// Stream the primary SVID
    pub async fn stream_x509_svids(mut self, selectors: Vec<Selector>) -> Result<impl Stream<Item = Result<X509Svid, ClientError>>, ClientError> {
        
      let request = SubscribeToX509sviDsRequest{
        selectors: selectors.into_iter().map(|s| s.into()).collect(), 
      };

      let response: tonic::Response<tonic::Streaming<SubscribeToX509sviDsResponse>> = self.client.subscribe_to_x509svi_ds(request).await?;

      let stream = response.into_inner().map(|item| match item {
        Ok(response) => DelegatedIdentityClient::parse_x509_svid_from_grpc_response(response),
        Err(e) => Err(e.into()),
      });

      Ok(stream)
    }

    /// Fetches [`X509BundleSet`], that is a set of [`X509Bundle`] keyed by the trust domain to which they belong.
    ///
    /// # Errors
    ///
    /// The function returns a variant of [`ClientError`] if there is en error connecting to the Workload API or
    /// there is a problem processing the response.
    pub async fn fetch_x509_bundles(mut self) -> Result<X509BundleSet, ClientError> {
        let request = SubscribeToX509BundlesRequest::default();

        let response: tonic::Response<tonic::Streaming<SubscribeToX509BundlesResponse>> = self.client.subscribe_to_x509_bundles(request).await?;
        let initial = response.into_inner().message().await?;
        DelegatedIdentityClient::parse_x509_bundle_set_from_grpc_response(initial.unwrap_or_default())
    }

    /// Stream all trust_bundles
    pub async fn stream_x509_bundles(mut self) -> Result<impl Stream<Item = Result<X509BundleSet, ClientError>>, ClientError> {
      let request = SubscribeToX509BundlesRequest::default();

      let response: tonic::Response<tonic::Streaming<SubscribeToX509BundlesResponse>> = self.client.subscribe_to_x509_bundles(request).await?;

      let stream = response.into_inner().map(|item| match item {
        Ok(response) => DelegatedIdentityClient::parse_x509_bundle_set_from_grpc_response(response),
        Err(e) => Err(e.into()),
      });

      Ok(stream)
    }

}

impl DelegatedIdentityClient {

  fn parse_x509_svid_from_grpc_response(
      response: SubscribeToX509sviDsResponse,
  ) -> Result<X509Svid, ClientError> {
      let svid = match response.x509_svids.get(DEFAULT_SVID) {
          None => return Err(ClientError::EmptyResponse),
          Some(s) => s,
      };
      
      // OPTIMIZE THIS
      let mut total_length = 0;
      svid.x509_svid.as_ref().ok_or(ClientError::EmptyResponse)?.cert_chain.iter().for_each(|c| total_length += c.len());
      let mut cert_chain = bytes::BytesMut::with_capacity(total_length);
      svid.x509_svid.as_ref().ok_or(ClientError::EmptyResponse)?.cert_chain.iter().for_each(|c| cert_chain.extend(c));

      
      let x509_svid =
          match X509Svid::parse_from_der(cert_chain.as_ref(), svid.x509_svid_key.as_ref()) {
              Ok(s) => s,
              Err(e) => return Err(e.into()),
          };
      Ok(x509_svid)
  }

      fn parse_x509_bundle_set_from_grpc_response(
        response: SubscribeToX509BundlesResponse,
    ) -> Result<X509BundleSet, ClientError> {
        let mut bundle_set = X509BundleSet::new();

        for (td, bundle) in response.ca_certificates.into_iter() {
            let trust_domain = TrustDomain::try_from(td)?;
            let bundle = match X509Bundle::parse_from_der(trust_domain, &bundle) {
                Ok(b) => b,
                Err(e) => return Err(e.into()),
            };
            bundle_set.add_bundle(bundle);
        }
        Ok(bundle_set)
    }

}



