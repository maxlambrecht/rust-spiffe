#![expect(missing_docs, reason = "example")]

use spiffe::X509Source;
use spiffe_rustls::{authorizer, mtls_client, AllowList};
use std::collections::BTreeSet;
use tonic::transport::Uri;
use tonic::Request;
use tonic_rustls::channel::Channel;
use tonic_rustls::Endpoint;

#[expect(
    clippy::allow_attributes,
    clippy::allow_attributes_without_reason,
    clippy::clone_on_ref_ptr,
    clippy::default_trait_access,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc,
    missing_docs,
    unused_qualifications
)]
pub mod helloworld {
    tonic::include_proto!("helloworld");
}

use helloworld::greeter_client::GreeterClient;
use helloworld::HelloRequest;

#[expect(clippy::print_stdout, reason = "example")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Env-driven, zero-config Workload API connection (SPIFFE_ENDPOINT_SOCKET).
    let source = X509Source::new().await?;

    // Example 1: Authorization by exact SPIFFE IDs
    // Only accept connections to servers with these specific SPIFFE IDs.
    // Pass string literals directly - exact() will convert them.
    let allowed_server_ids = [
        "spiffe://example.org/myservice",
        "spiffe://example.org/myservice2",
    ];

    // Example 2: Trust Domain Policy (defense-in-depth)
    // Restrict which trust domains are accepted, even if the Workload API
    // provides bundles for multiple trust domains (federation scenario).
    // This is a defense-in-depth mechanism - the primary trust comes from
    // the bundle set, but this policy adds an additional restriction.
    let mut allowed_trust_domains = BTreeSet::new();
    allowed_trust_domains.insert("example.org".try_into()?);
    // In a federation scenario, you might also allow:
    // allowed_trust_domains.insert("broker.example".try_into()?);
    // allowed_trust_domains.insert("stockmarket.example".try_into()?);

    // Build rustls client config with:
    // - Authorization: only accept servers with the specified SPIFFE IDs
    // - Trust Domain Policy: only trust certificates from the allowed trust domains
    // - ALPN: HTTP/2 (required for gRPC)
    let client_cfg = mtls_client(source.clone())
        .authorize(authorizer::exact(allowed_server_ids)?)
        .trust_domain_policy(AllowList(allowed_trust_domains))
        .with_alpn_protocols([b"h2"])
        .build()?;

    let uri: Uri = "https://example.org:50051".parse()?;

    let channel: Channel = Endpoint::from(uri)
        .tls_config(client_cfg)?
        .connect()
        .await?;

    let mut client = GreeterClient::new(channel);

    let req = Request::new(HelloRequest {
        name: "spiffe".to_string(),
    });

    let resp = client.say_hello(req).await?;
    println!("{}", resp.into_inner().message);

    let () = source.shutdown().await;
    Ok(())
}
