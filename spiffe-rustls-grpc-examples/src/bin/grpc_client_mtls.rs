use spiffe::X509Source;
use spiffe_rustls::{ClientConfigBuilder, ClientConfigOptions};
use std::sync::Arc;
use tonic::Request;
use tonic::transport::Uri;
use tonic_rustls::Endpoint;
use tonic_rustls::channel::Channel;

pub mod helloworld {
    tonic::include_proto!("helloworld");
}

use helloworld::HelloRequest;
use helloworld::greeter_client::GreeterClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let socket = std::env::var("SPIFFE_ENDPOINT_SOCKET")
        .unwrap_or_else(|_| "unix:///tmp/spire-agent/public/api.sock".to_string());
    unsafe { std::env::set_var("SPIFFE_ENDPOINT_SOCKET", socket) };

    let source = X509Source::new().await?;

    // Client only accepts specific server SPIFFE IDs.
    let opts = ClientConfigOptions {
        trust_domain: "example.org".try_into()?,
        authorize_server: Arc::new(|id: &str| {
            id == "spiffe://example.org/myservice" || id == "spiffe://example.org/myservice2"
        }),
    };

    // Build rustls client config backed by SPIFFE X509Source.
    let mut client_cfg = ClientConfigBuilder::new(source.clone(), opts)
        .build()
        .await?;

    // gRPC requires HTTP/2 via ALPN.
    client_cfg.alpn_protocols = vec![b"h2".to_vec()];

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

    let _ = source.shutdown().await;
    Ok(())
}
