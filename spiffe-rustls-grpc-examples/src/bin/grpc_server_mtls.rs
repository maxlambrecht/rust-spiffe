use spiffe::{TrustDomain, X509Source};
use spiffe_rustls::{authorizer, mtls_server, LocalOnly};
use tonic::{Request, Response, Status};
use tonic_rustls::Server;

pub mod helloworld {
    tonic::include_proto!("helloworld");
}

use helloworld::greeter_server::{Greeter, GreeterServer};
use helloworld::{HelloReply, HelloRequest};

#[derive(Default)]
struct MyGreeter;

#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(&self, req: Request<HelloRequest>) -> Result<Response<HelloReply>, Status> {
        let name = req.into_inner().name;
        Ok(Response::new(HelloReply {
            message: format!("hello, {name}"),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Env-driven, zero-config Workload API connection (SPIFFE_ENDPOINT_SOCKET).
    let source = X509Source::new().await?;

    // Example 1: Authorization by trust domain
    // Accept clients from any SPIFFE ID in the specified trust domains.
    // This is more flexible than exact SPIFFE ID matching and works well
    // when you trust an entire trust domain.
    // Pass string literals directly - trust_domains() will convert them.
    let allowed_trust_domains = [
        "example.org",
        // In a federation scenario, you might also allow:
        // "broker.example",
    ];

    // Example 2: Trust Domain Policy - LocalOnly
    // Only trust certificates from a single trust domain, even if the Workload API
    // provides bundles for multiple trust domains (federation scenario).
    // This is the most restrictive policy and ensures we only accept connections
    // from our own trust domain.
    let local_trust_domain: TrustDomain = "example.org".try_into()?;

    // Build rustls server config with:
    // - Authorization: accept clients from the specified trust domains
    // - Trust Domain Policy: only trust certificates from our local trust domain
    //   (defense-in-depth: even if federation provides other bundles, we ignore them)
    // - ALPN: HTTP/2 (required for gRPC)
    let server_cfg = mtls_server(source.clone())
        .authorize(authorizer::trust_domains(allowed_trust_domains)?)
        .trust_domain_policy(LocalOnly(local_trust_domain))
        .with_alpn_protocols([b"h2"])
        .build()?;

    let addr = "127.0.0.1:50051".parse()?;
    eprintln!("gRPC server listening on https://{addr}");
    eprintln!("Server configured to:");
    eprintln!("  - Accept clients from trust domains: example.org");
    eprintln!("  - Trust domain policy: LocalOnly (example.org)");

    let mut server = Server::builder().tls_config(server_cfg)?;

    server
        .add_service(GreeterServer::new(MyGreeter))
        .serve_with_shutdown(addr, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;

    let _ = source.shutdown().await;
    Ok(())
}
