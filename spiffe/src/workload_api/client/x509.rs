use crate::constants::DEFAULT_SVID;
use crate::workload_api::pb::workload::{
    X509BundlesRequest, X509BundlesResponse, X509svidRequest, X509svidResponse,
};
use crate::workload_api::x509_context::X509Context;
use crate::{
    TrustDomain, WorkloadApiClient, WorkloadApiError, X509Bundle, X509BundleSet, X509Svid,
};
use futures::{Stream, StreamExt as _};
use std::sync::Arc;

impl WorkloadApiClient {
    /// Fetches the default X.509 SVID for the calling workload from the SPIFFE Workload API.
    ///
    /// # Errors
    ///
    /// Returns a [`WorkloadApiError`] if the gRPC request fails, the response stream
    /// ends unexpectedly, or the received data is invalid.
    pub async fn fetch_x509_svid(&self) -> Result<X509Svid, WorkloadApiError> {
        let request = X509svidRequest::default();

        let mut client = self.client.clone();
        let grpc_stream_response: tonic::Response<tonic::Streaming<X509svidResponse>> =
            client.fetch_x509svid(request).await?;

        let resp = Self::first_message(grpc_stream_response.into_inner()).await?;

        Self::parse_x509_svid_from_grpc_response(&resp)
    }

    /// Fetches all X.509 SVIDs available to the calling workload from the SPIFFE Workload API.
    ///
    /// # Errors
    ///
    /// Returns a [`WorkloadApiError`] if the gRPC request fails, the response stream
    /// ends unexpectedly, or the received data is invalid.
    pub async fn fetch_all_x509_svids(&self) -> Result<Vec<X509Svid>, WorkloadApiError> {
        let request = X509svidRequest::default();

        let mut client = self.client.clone();

        let grpc_stream_response: tonic::Response<tonic::Streaming<X509svidResponse>> =
            client.fetch_x509svid(request).await?;

        let response = Self::first_message(grpc_stream_response.into_inner()).await?;
        Self::parse_x509_svids_from_grpc_response(&response)
    }

    /// Fetches the current X.509 bundle set from the SPIFFE Workload API.
    ///
    /// # Errors
    ///
    /// Returns a [`WorkloadApiError`] if the gRPC request fails, the response stream
    /// ends unexpectedly, or the received data is invalid.
    ///
    /// CRLs included in the Workload API response are currently ignored.
    pub async fn fetch_x509_bundles(&self) -> Result<X509BundleSet, WorkloadApiError> {
        let request = X509BundlesRequest::default();

        let mut client = self.client.clone();

        let grpc_stream_response: tonic::Response<tonic::Streaming<X509BundlesResponse>> =
            client.fetch_x509_bundles(request).await?;

        let response = Self::first_message(grpc_stream_response.into_inner()).await?;

        Self::parse_x509_bundle_set_from_grpc_response(response)
    }

    /// Fetches the current X.509 context (SVIDs and bundles).
    ///
    /// # Errors
    ///
    /// Returns a [`WorkloadApiError`] if the Workload API request fails, the response
    /// stream terminates unexpectedly, or the received data cannot be parsed.
    ///
    /// CRLs included in the Workload API response are currently ignored.
    #[cfg(feature = "x509")]
    pub async fn fetch_x509_context(&self) -> Result<X509Context, WorkloadApiError> {
        let request = X509svidRequest::default();

        let mut client = self.client.clone();

        let grpc_stream_response: tonic::Response<tonic::Streaming<X509svidResponse>> =
            client.fetch_x509svid(request).await?;

        let response = Self::first_message(grpc_stream_response.into_inner()).await?;
        Self::parse_x509_context_from_grpc_response(response)
    }

    /// Streams X.509 context updates from the Workload API.
    ///
    /// The stream ends when the server closes the connection. This stream does not
    /// automatically reconnect; if you need resilience and automatic reconnection,
    /// use [`crate::X509Source`].
    ///
    /// # Errors
    ///
    /// Returns a [`WorkloadApiError`] if the Workload API stream cannot be
    /// established or the initial request fails.
    ///
    pub async fn stream_x509_contexts(
        &self,
    ) -> Result<
        impl Stream<Item = Result<X509Context, WorkloadApiError>> + Send + 'static + use<>,
        WorkloadApiError,
    > {
        let request = X509svidRequest::default();

        let mut client = self.client.clone();

        let response = client.fetch_x509svid(request).await?;
        let stream = response.into_inner().map(|message| {
            message
                .map_err(WorkloadApiError::from)
                .and_then(Self::parse_x509_context_from_grpc_response)
        });
        Ok(Box::pin(stream))
    }

    /// Streams default X.509 SVID updates from the Workload API.
    ///
    /// The stream ends when the server closes the connection. This stream does not
    /// automatically reconnect; if you need resilience and automatic reconnection,
    /// use [`crate::X509Source`].
    ///
    /// # Errors
    ///
    /// Returns a [`WorkloadApiError`] if the stream cannot be established or if a
    /// stream item fails to be received or parsed.
    pub async fn stream_x509_svids(
        &self,
    ) -> Result<
        impl Stream<Item = Result<X509Svid, WorkloadApiError>> + Send + 'static + use<>,
        WorkloadApiError,
    > {
        let request = X509svidRequest::default();

        let mut client = self.client.clone();

        let response = client.fetch_x509svid(request).await?;
        let stream = response.into_inner().map(|message| {
            let resp = message.map_err(WorkloadApiError::from)?;
            Self::parse_x509_svid_from_grpc_response(&resp)
        });
        Ok(Box::pin(stream))
    }

    /// Streams X.509 bundle set updates from the Workload API.
    ///
    /// The stream ends when the server closes the connection. This stream does not
    /// automatically reconnect; if you need resilience and automatic reconnection,
    /// use [`crate::X509Source`].
    ///
    /// # Errors
    ///
    /// Returns a [`WorkloadApiError`] if the Workload API stream cannot be
    /// established or the initial request fails.
    pub async fn stream_x509_bundles(
        &self,
    ) -> Result<
        impl Stream<Item = Result<X509BundleSet, WorkloadApiError>> + Send + 'static + use<>,
        WorkloadApiError,
    > {
        let request = X509BundlesRequest::default();

        let mut client = self.client.clone();

        let response = client.fetch_x509_bundles(request).await?;
        let stream = response.into_inner().map(|message| {
            message
                .map_err(WorkloadApiError::from)
                .and_then(Self::parse_x509_bundle_set_from_grpc_response)
        });
        Ok(Box::pin(stream))
    }
}

impl WorkloadApiClient {
    fn parse_x509_svid_from_grpc_response(
        response: &X509svidResponse,
    ) -> Result<X509Svid, WorkloadApiError> {
        Self::validate_required_x509_svid_fields(response)?;

        let svid = response
            .svids
            .get(DEFAULT_SVID)
            .ok_or(WorkloadApiError::EmptyResponse)?;

        X509Svid::parse_from_der_with_hint(
            svid.x509_svid.as_ref(),
            svid.x509_svid_key.as_ref(),
            (!svid.hint.is_empty()).then(|| Arc::<str>::from(svid.hint.as_str())),
        )
        .map_err(WorkloadApiError::from)
    }

    fn parse_x509_svids_from_grpc_response(
        response: &X509svidResponse,
    ) -> Result<Vec<X509Svid>, WorkloadApiError> {
        Self::validate_required_x509_svid_fields(response)?;

        response
            .svids
            .iter()
            .map(|svid| {
                let hint = (!svid.hint.is_empty()).then(|| Arc::<str>::from(svid.hint.as_str()));

                X509Svid::parse_from_der_with_hint(
                    svid.x509_svid.as_ref(),
                    svid.x509_svid_key.as_ref(),
                    hint,
                )
                .map_err(WorkloadApiError::from)
            })
            .collect()
    }

    fn parse_x509_bundle_set_from_grpc_response(
        response: X509BundlesResponse,
    ) -> Result<X509BundleSet, WorkloadApiError> {
        let bundles: Result<Vec<_>, _> = response
            .bundles
            .into_iter()
            .map(|(td, bundle_data)| {
                let trust_domain = TrustDomain::try_from(td)?;
                X509Bundle::parse_from_der(trust_domain, &bundle_data)
                    .map_err(WorkloadApiError::from)
            })
            .collect();

        let mut bundle_set = X509BundleSet::new();
        for bundle in bundles? {
            bundle_set.add_bundle(bundle);
        }

        Ok(bundle_set)
    }

    fn parse_x509_context_from_grpc_response(
        response: X509svidResponse,
    ) -> Result<X509Context, WorkloadApiError> {
        Self::validate_required_x509_svid_fields(&response)?;

        let mut svids: Vec<Arc<X509Svid>> = Vec::new();
        let mut bundle_set = X509BundleSet::new();

        for svid in response.svids {
            let hint = (!svid.hint.is_empty()).then(|| Arc::<str>::from(svid.hint.as_str()));

            let x509_svid = X509Svid::parse_from_der_with_hint(
                svid.x509_svid.as_ref(),
                svid.x509_svid_key.as_ref(),
                hint,
            )
            .map_err(WorkloadApiError::from)?;

            let trust_domain = x509_svid.spiffe_id().trust_domain().clone();
            svids.push(Arc::new(x509_svid));

            let bundle = X509Bundle::parse_from_der(trust_domain, svid.bundle.as_ref())
                .map_err(WorkloadApiError::from)?;
            bundle_set.add_bundle(bundle);
        }

        for (trust_domain, bundle) in response.federated_bundles {
            let trust_domain = TrustDomain::try_from(trust_domain)?;
            let x509_bundle = X509Bundle::parse_from_der(trust_domain, bundle.as_ref())
                .map_err(WorkloadApiError::from)?;
            // Federated bundles are applied after per-SVID bundles. If a non-conforming
            // server repeats the workload's own trust domain here, this intentionally follows
            // X509BundleSet::add_bundle replacement semantics and the federated entry wins.
            bundle_set.add_bundle(x509_bundle);
        }

        Ok(X509Context::new(svids, Arc::new(bundle_set)))
    }

    fn validate_required_x509_svid_fields(
        response: &X509svidResponse,
    ) -> Result<(), WorkloadApiError> {
        if response.svids.iter().any(|svid| svid.bundle.is_empty()) {
            return Err(WorkloadApiError::MissingRequiredField {
                field: "X509SVID.bundle",
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload_api::pb::workload::X509svid;
    use std::collections::HashMap;

    fn x509_svid(bundle: &[u8]) -> X509svid {
        let cert = include_bytes!("../../../tests/testdata/svid/x509/1-svid-chain.der");
        let key = include_bytes!("../../../tests/testdata/svid/x509/1-key.der");
        X509svid {
            spiffe_id: "spiffe://example.org/workload".into(),
            x509_svid: cert.to_vec().into(),
            x509_svid_key: key.to_vec().into(),
            bundle: bundle.to_vec().into(),
            hint: String::new(),
        }
    }

    fn assert_missing_required_local_bundle<T>(result: &Result<T, WorkloadApiError>) {
        assert!(matches!(
            result,
            Err(WorkloadApiError::MissingRequiredField {
                field: "X509SVID.bundle"
            })
        ));
    }

    #[test]
    fn x509_context_rejects_empty_required_local_bundle() {
        let response = X509svidResponse {
            svids: vec![x509_svid(&[])],
            ..X509svidResponse::default()
        };

        let result = WorkloadApiClient::parse_x509_context_from_grpc_response(response);

        assert_missing_required_local_bundle(&result);
    }

    #[test]
    fn default_x509_svid_parser_rejects_empty_required_bundle_in_complete_response() {
        let bundle = include_bytes!("../../../tests/testdata/bundle/x509/cert1.der");
        let response = X509svidResponse {
            // Even though the selected default entry is valid, a malformed later entry
            // makes the complete Workload API response invalid and must discard it.
            svids: vec![x509_svid(bundle), x509_svid(&[])],
            ..X509svidResponse::default()
        };

        let result = WorkloadApiClient::parse_x509_svid_from_grpc_response(&response);

        assert_missing_required_local_bundle(&result);
    }

    #[test]
    fn all_x509_svids_parser_rejects_empty_required_local_bundle() {
        let response = X509svidResponse {
            svids: vec![x509_svid(&[])],
            ..X509svidResponse::default()
        };

        let result = WorkloadApiClient::parse_x509_svids_from_grpc_response(&response);

        assert_missing_required_local_bundle(&result);
    }

    #[test]
    fn x509_context_accepts_empty_optional_federated_bundle() {
        let local_bundle = include_bytes!("../../../tests/testdata/bundle/x509/cert1.der");
        let federated_trust_domain = TrustDomain::new("federated.example.org").unwrap();
        let response = X509svidResponse {
            svids: vec![x509_svid(local_bundle)],
            federated_bundles: HashMap::from([(
                federated_trust_domain.to_string(),
                Vec::new().into(),
            )]),
            ..X509svidResponse::default()
        };

        let context = WorkloadApiClient::parse_x509_context_from_grpc_response(response).unwrap();
        let bundle = context
            .bundle_set()
            .get(&federated_trust_domain)
            .expect("empty federated bundle should remain present in the complete update");

        assert!(bundle.authorities().is_empty());
    }
}
